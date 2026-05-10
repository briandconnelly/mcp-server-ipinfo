import ipaddress
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any, Literal, NoReturn

import httpx
import ipinfo
from fastmcp import Context, FastMCP
from fastmcp.dependencies import CurrentContext
from fastmcp.exceptions import ToolError
from ipinfo.error import APIError
from ipinfo.exceptions import RequestQuotaExceededError, TimeoutExceededError
from pydantic import Field

from .cache import IPInfoCache
from .ipinfo import (
    create_async_handler,
    ipinfo_batch_lookup,
    ipinfo_get_map_url,
    ipinfo_lookup,
    ipinfo_resproxy_lookup,
)
from .models import (
    IPDetails,
    MapResult,
    ResidentialProxyDetails,
    SkippedIP,
    ToolErrorCode,
    ToolErrorEnvelope,
)


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[dict]:
    """Initialize the async IPInfo handler and cache at startup."""
    handler = await create_async_handler()
    cache = IPInfoCache()

    try:
        yield {"ipinfo_handler": handler, "cache": cache}
    finally:
        await handler.deinit()


# Create an MCP server
mcp = FastMCP(
    name="IP Address Geolocation and Internet Service Provider Lookup",
    instructions="""
    Geolocate IPv4/IPv6 addresses via ipinfo.io: location, ISP, ASN, and
    (on paid plans) privacy/VPN/Tor/proxy flags, carrier, company, abuse
    contacts, hosted domains.

    Tools:
    - ipinfo_lookup_my_ip(): the calling client's own IP (no args).
    - ipinfo_lookup_ips(ips, detail="full"): batch lookup; detail="summary"
      nulls heavy nested blocks (continent, country_flag*, country_currency,
      abuse, domains) for token savings while preserving shape.
    - ipinfo_check_residential_proxy(ip): Enterprise residential-proxy add-on
      required (tagged "enterprise").
    - ipinfo_generate_map_url(ips): returns a MapResult
      {url, mapped_ip_count, skipped_ips (capped at 100), skipped_count, truncated}.

    Deprecated forwarding aliases, removed in 0.6.0: get_ip_details,
    get_residential_proxy_info, get_map_url.

    NOT in scope: DNS/hostname resolution; CIDR or BGP lookups; historical or
    time-series data; private/loopback/multicast/link-local/reserved IPs
    (filtered at boundary as `special_ip_unsupported`); deanonymizing users
    behind VPNs/proxies/Tor (results reflect the exit point); malice scoring.

    Plan tiers (set IPINFO_API_TOKEN):
    - no token: country, country_code, continent, ASN basics
    - Core: + full geolocation, ASN details, privacy/VPN/proxy/Tor/hosting flags
    - Plus: + carrier, company
    - Enterprise: + domains, abuse, residential-proxy add-on

    Cache (lookup tools only — not residential-proxy or map): in-memory,
    IPINFO_CACHE_TTL seconds (default 3600), max IPINFO_CACHE_SIZE entries
    (default 4096), oldest evicted first. `ts_retrieved` on a cached record
    is the original lookup time — compare against now for freshness.

    Transport: on stdio, ipinfo_lookup_my_ip resolves to this server's
    outbound IP, not the end user's. Use ipinfo_lookup_ips with an explicit
    IP when the caller already has one.

    Errors: every ToolError message is JSON-encoded with a stable `code`
    (auth_invalid, auth_insufficient_scope, quota_exceeded, timeout,
    api_error, invalid_ip_address, special_ip_unsupported, no_valid_ips,
    too_many_ips, unknown_error), a `temporary` flag, an optional
    `retry_after_ms`, and a `repair` hint. Parse the message as JSON and
    branch on `code`.
    """,
    lifespan=app_lifespan,
)


def _get_handler_and_cache(
    ctx: Context,
) -> tuple[ipinfo.AsyncHandler, IPInfoCache]:
    """Get the handler and cache from lifespan context."""
    lifespan_context = ctx.lifespan_context
    return lifespan_context["ipinfo_handler"], lifespan_context["cache"]


_IP_CHECKS = [
    ("is_loopback", "loopback"),
    ("is_multicast", "multicast"),
    ("is_link_local", "link-local"),
    ("is_reserved", "reserved"),
    ("is_private", "private"),
]

_NORMALIZE_SENTINELS = frozenset({"null", "", "undefined", "0.0.0.0", "::"})

# Heavy nested blocks dropped from IPDetails when an agent requests detail="summary".
# These fields contribute the most tokens per record without being load-bearing for
# typical batch tasks (geolocation, ASN). Core fields (ip, city, country, org, loc,
# timezone, asn, privacy) survive summarization.
_HEAVY_NESTED_FIELDS: tuple[str, ...] = (
    "continent",
    "country_flag",
    "country_flag_url",
    "country_currency",
    "abuse",
    "domains",
)

DetailLevel = Literal["summary", "full"]

MAX_LOOKUP_IPS = 500_000

# Cap on the size of MapResult.skipped_ips so a 500K-IP submission with all
# entries filtered cannot inflate the response. truncated=True signals overflow.
MAX_SKIPPED_IPS_REPORTED = 100

# Cap on per-IP ``ctx.warning`` emissions during input filtering so a 500K
# batch with many filtered entries cannot drown the log stream (and trip the
# tool-level timeout). After the cap, a single aggregated summary is logged.
MAX_SKIP_WARNINGS = 100

# Framework-level guard on the map tool. Bounds end-to-end execution time
# even if the underlying httpx client misbehaves; httpx itself enforces a
# tighter per-request timeout (DEFAULT_MAP_TIMEOUT_SECONDS).
MAP_TOOL_TIMEOUT_SECONDS = 60.0


def _raise_envelope(
    code: ToolErrorCode,
    message: str,
    *,
    temporary: bool,
    field: str | None = None,
    value: Any = None,
    retry_after_ms: int | None = None,
    repair: dict[str, Any] | None = None,
) -> NoReturn:
    """Build a ToolErrorEnvelope and raise it as a JSON-encoded ToolError.

    Encoding the envelope into the ToolError message preserves the wire-level
    `isError: true` while giving agents a parseable structured payload.
    """
    envelope = ToolErrorEnvelope(
        code=code,
        message=message,
        temporary=temporary,
        field=field,
        value=value,
        retry_after_ms=retry_after_ms,
        repair=repair,
    )
    raise ToolError(envelope.model_dump_json())


def _envelope_from_upstream(
    exc: Exception,
) -> tuple[ToolErrorCode, str, bool, int | None, dict[str, Any] | None]:
    """Classify an upstream exception into the structured-error fields.

    Returns ``(code, message, temporary, retry_after_ms, repair)``. The mapping
    covers both the ``ipinfo`` SDK exceptions (used by the lookup tools) and
    raw ``httpx`` exceptions (used by the map tool which calls the IPInfo map
    endpoint directly).
    """
    if isinstance(exc, APIError):
        if exc.error_code == 401:
            return (
                "auth_invalid",
                "IPInfo rejected the provided API token.",
                False,
                None,
                {
                    "hint": (
                        "Set IPINFO_API_TOKEN to a valid IPInfo API token. "
                        "Sign up at https://ipinfo.io/signup."
                    ),
                },
            )
        if exc.error_code == 403:
            return (
                "auth_insufficient_scope",
                "IPInfo plan does not grant access to this capability.",
                False,
                None,
                {
                    "hint": (
                        "Upgrade your IPInfo plan or enable the required add-on "
                        "(e.g., residential proxy data)."
                    ),
                },
            )
        if 500 <= exc.error_code < 600:
            return (
                "api_error",
                f"IPInfo returned HTTP {exc.error_code}.",
                True,
                None,
                {
                    "hint": "Retry after a short delay; the upstream service is degraded."
                },
            )
        return (
            "api_error",
            f"IPInfo returned HTTP {exc.error_code}.",
            False,
            None,
            None,
        )
    if isinstance(exc, RequestQuotaExceededError):
        return (
            "quota_exceeded",
            "IPInfo request quota exceeded for this token.",
            True,
            None,
            {"hint": "Wait for daily quota reset or upgrade your IPInfo plan."},
        )
    if isinstance(exc, TimeoutExceededError):
        return (
            "timeout",
            "IPInfo request timed out.",
            True,
            None,
            {"hint": "Retry; transient network or upstream slowness."},
        )
    # The map tool talks to ipinfo.io via httpx directly, so its failures
    # surface as httpx exceptions rather than ipinfo SDK exceptions.
    if isinstance(exc, httpx.TimeoutException):
        return (
            "timeout",
            "Map request timed out before the upstream responded.",
            True,
            None,
            {"hint": "Retry; transient network or upstream slowness."},
        )
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status == 401:
            return (
                "auth_invalid",
                "IPInfo rejected the provided API token.",
                False,
                None,
                {"hint": "Set IPINFO_API_TOKEN to a valid IPInfo API token."},
            )
        if status == 403:
            return (
                "auth_insufficient_scope",
                "IPInfo plan does not grant access to the map endpoint.",
                False,
                None,
                {"hint": "Upgrade your IPInfo plan."},
            )
        if status == 429:
            return (
                "quota_exceeded",
                "IPInfo rate limit exceeded.",
                True,
                None,
                {"hint": "Wait for the rate-limit window to reset."},
            )
        if 500 <= status < 600:
            return (
                "api_error",
                f"IPInfo returned HTTP {status}.",
                True,
                None,
                {
                    "hint": "Retry after a short delay; the upstream service is degraded."
                },
            )
        return (
            "api_error",
            f"IPInfo returned HTTP {status}.",
            False,
            None,
            None,
        )
    # Catch-all: surface the exception class name as a structured field so
    # agents can branch on type without parsing the message. The raw
    # `str(exc)` is included to preserve diagnostic context (we run with
    # mask_error_details=False); upstream library messages should not embed
    # secrets, but callers wanting redaction can flip mask_error_details.
    return (
        "unknown_error",
        f"Unexpected {type(exc).__name__}: {exc}",
        True,
        None,
        {"exception_type": type(exc).__name__},
    )


def _raise_from_upstream(exc: Exception) -> NoReturn:
    """Translate an upstream exception into a structured ToolError envelope."""
    code, message, temporary, retry_after_ms, repair = _envelope_from_upstream(exc)
    _raise_envelope(
        code,
        message,
        temporary=temporary,
        retry_after_ms=retry_after_ms,
        repair=repair,
    )


def _validate_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Validate an IP address and reject special-use addresses.

    Raises a structured ToolError envelope (``invalid_ip_address`` or
    ``special_ip_unsupported``) so callers receive an agent-actionable error
    instead of opaque prose.
    """
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        _raise_envelope(
            "invalid_ip_address",
            f"{ip} is not a valid IP address.",
            temporary=False,
            field="ip",
            value=ip,
            repair={"hint": "Provide a valid IPv4 (e.g., 8.8.8.8) or IPv6 address."},
        )

    # Check in order of specificity - loopback and reserved are subsets of private
    for attr, label in _IP_CHECKS:
        if getattr(parsed_ip, attr):
            _raise_envelope(
                "special_ip_unsupported",
                f"{ip} is a {label} IP address. Geolocation is not available.",
                temporary=False,
                field="ip",
                value=ip,
                repair={
                    "hint": f"{label.capitalize()} addresses are not publicly geolocatable.",
                    "class": label,
                },
            )

    return parsed_ip


def _normalize_ip(ip: str) -> str | None:
    """Normalize empty/placeholder IP values to None, stripping whitespace."""
    ip = ip.strip()
    if ip in _NORMALIZE_SENTINELS:
        return None
    return ip


def _envelope_message(err: ToolError) -> str:
    """Extract the readable message from a structured ToolError, or fall back to str(err)."""
    try:
        return json.loads(str(err))["message"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return str(err)


async def _filter_valid_ips(
    ips: list[str], ctx: Context
) -> tuple[list[str], list[tuple[str, str]]]:
    """Normalize, deduplicate, validate IPs and log warnings for skipped ones.

    Returns:
        A tuple of (valid_ips, skipped) where skipped contains (ip, reason)
        pairs. Empty/placeholder values and duplicates are recorded in
        ``skipped`` with explicit reasons so ``mapped + skipped`` accounts for
        every input. Per-IP ``ctx.warning`` emissions are capped at
        ``MAX_SKIP_WARNINGS`` (with an aggregated summary after the cap) so a
        500K batch cannot flood the log stream.
    """
    seen: set[str] = set()
    valid: list[str] = []
    skipped: list[tuple[str, str]] = []

    for ip in ips:
        norm = _normalize_ip(ip)
        if norm is None:
            skipped.append((ip, "empty or placeholder value (treated as not an IP)"))
            continue
        if norm in seen:
            skipped.append((ip, "duplicate of a previously submitted IP"))
            continue
        seen.add(norm)

        try:
            _validate_ip(norm)
            valid.append(norm)
        except ToolError as e:
            skipped.append((ip, _envelope_message(e)))

    for ip, reason in skipped[:MAX_SKIP_WARNINGS]:
        await ctx.warning(f"Skipping {ip}: {reason}")
    if len(skipped) > MAX_SKIP_WARNINGS:
        await ctx.warning(
            f"Skipped {len(skipped)} IPs total; per-IP details logged for the first "
            f"{MAX_SKIP_WARNINGS}. The structured response carries up to "
            f"{MAX_SKIPPED_IPS_REPORTED} skipped entries with reasons."
        )

    return valid, skipped


def _summarize_for_batch(details: IPDetails) -> IPDetails:
    """Drop heavy nested blocks from an IPDetails for batch token efficiency.

    Returns a copy with the deeply-nested decorative fields nulled out
    (continent, country_flag, country_flag_url, country_currency, abuse,
    domains). Shape parity with full detail is preserved so existing
    parsers continue to work.
    """
    return details.model_copy(update={field: None for field in _HEAVY_NESTED_FIELDS})


async def _do_my_ip_lookup(
    handler: ipinfo.AsyncHandler, cache: IPInfoCache, ctx: Context
) -> IPDetails:
    """Look up details for the client's own IP. Shared by ipinfo_lookup_my_ip and the deprecated alias."""
    await ctx.info("Looking up client IP details")
    try:
        result = await ipinfo_lookup(handler, None)
        await cache.set(str(result.ip), result)
        return result
    except Exception as e:
        await ctx.error(f"Failed to look up client IP: {e}")
        _raise_from_upstream(e)


async def _do_batch_lookup(
    handler: ipinfo.AsyncHandler,
    cache: IPInfoCache,
    ips: list[str],
    ctx: Context,
) -> list[IPDetails]:
    """Validate, dedupe, cache-check, and look up a batch of IPs.

    Shared between ipinfo_lookup_ips and the deprecated get_ip_details alias.
    """
    # Defense-in-depth: schema enforces the cap, but direct Python invocation
    # (or any caller bypassing FastMCP validation) can still pass an arbitrary
    # list. Reject early before any per-IP work.
    if len(ips) > MAX_LOOKUP_IPS:
        _raise_envelope(
            "too_many_ips",
            f"Too many IPs ({len(ips)}). Maximum is {MAX_LOOKUP_IPS:,} per lookup.",
            temporary=False,
            field="ips",
            value=len(ips),
            repair={
                "limit": MAX_LOOKUP_IPS,
                "received": len(ips),
                "hint": f"Reduce ips to <= {MAX_LOOKUP_IPS} entries.",
            },
        )

    valid_ips, skipped = await _filter_valid_ips(ips, ctx)

    if not valid_ips:
        _raise_envelope(
            "no_valid_ips",
            "No valid IP addresses provided; all inputs were filtered as invalid or special-use.",
            temporary=False,
            field="ips",
            repair={
                "hint": "Provide at least one public IPv4 or IPv6 address.",
                "skipped_count": len(skipped),
            },
        )

    cached_results = await cache.get_batch(valid_ips)
    ips_to_lookup = [ip for ip in valid_ips if ip not in cached_results]

    if cached_results:
        await ctx.info(f"Found {len(cached_results)} IPs in cache")

    new_results: dict[str, IPDetails] = {}
    if ips_to_lookup:
        await ctx.info(f"Looking up {len(ips_to_lookup)} IP address(es)")
        try:
            if len(ips_to_lookup) == 1:
                result = await ipinfo_lookup(handler, ips_to_lookup[0])
                new_results[ips_to_lookup[0]] = result
            else:
                new_results = await ipinfo_batch_lookup(
                    handler, ips_to_lookup, raise_on_fail=False
                )
            await cache.set_batch(new_results)
        except Exception as e:
            await ctx.error(f"IP lookup failed: {e}")
            _raise_from_upstream(e)

    all_results = {**cached_results, **new_results}
    ordered_results = [all_results[ip] for ip in valid_ips if ip in all_results]

    await ctx.info(
        f"Returning {len(ordered_results)} result(s) "
        f"({len(skipped)} skipped, {len(cached_results)} cached)"
    )

    return ordered_results


def _build_skipped_list(
    skipped: list[tuple[str, str]],
) -> tuple[list[SkippedIP], bool]:
    """Convert filter results into a capped SkippedIP list plus a truncation flag."""
    truncated = len(skipped) > MAX_SKIPPED_IPS_REPORTED
    capped = skipped[:MAX_SKIPPED_IPS_REPORTED]
    return [SkippedIP(ip=ip, reason=reason) for ip, reason in capped], truncated


@mcp.tool(
    annotations={"readOnlyHint": True, "openWorldHint": True},
    meta={"introduced_in": "0.5.0"},
)
async def ipinfo_lookup_my_ip(
    ctx: Context = CurrentContext(),
) -> IPDetails:
    """Geolocate the calling client's own IP. No arguments.

    On stdio transports the result is this server's outbound IP, not the
    end user's. Use `ipinfo_lookup_ips` when the caller already has a
    specific IP. Errors raise ToolError with a JSON-encoded envelope.
    """
    handler, cache = _get_handler_and_cache(ctx)
    return await _do_my_ip_lookup(handler, cache, ctx)


@mcp.tool(
    annotations={"readOnlyHint": True, "openWorldHint": True},
    meta={"introduced_in": "0.5.0"},
)
async def ipinfo_lookup_ips(
    ips: Annotated[
        list[str],
        Field(
            description="IPv4/IPv6 addresses to look up. Invalid or special-use IPs are filtered.",
            min_length=1,
            max_length=MAX_LOOKUP_IPS,
            examples=[["8.8.8.8"], ["8.8.8.8", "1.1.1.1", "208.67.222.222"]],
        ),
    ],
    detail: Annotated[
        DetailLevel,
        Field(
            description=(
                "'full' returns every IPDetails field; 'summary' nulls heavy "
                "nested blocks (continent, country_flag*, country_currency, "
                "abuse, domains) for batch token savings while preserving shape."
            ),
        ),
    ] = "full",
    ctx: Context = CurrentContext(),
) -> list[IPDetails]:
    """Geolocate one or more IPs and return ISP/ASN details.

    Returns a list of IPDetails in input order (after dedup and invalid-IP
    filtering). Match results back to your input via the `ip` field. Capped
    at 500,000 IPs per call (`too_many_ips` if exceeded). Higher plan tiers
    populate more fields; see the server instructions for the
    Lite/Core/Plus/Enterprise tier mapping. Errors raise ToolError with a
    JSON-encoded envelope.
    """
    handler, cache = _get_handler_and_cache(ctx)
    results = await _do_batch_lookup(handler, cache, ips, ctx)
    if detail == "summary":
        return [_summarize_for_batch(r) for r in results]
    return results


@mcp.tool(
    annotations={"readOnlyHint": True, "openWorldHint": True},
    meta={"introduced_in": "0.5.0", "plan_required": "residential_proxy_addon"},
    tags={"enterprise"},
)
async def ipinfo_check_residential_proxy(
    ip: Annotated[
        str,
        Field(
            description="IPv4/IPv6 address to classify.",
            examples=["142.250.80.46"],
        ),
    ],
    ctx: Context = CurrentContext(),
) -> ResidentialProxyDetails:
    """Classify whether an IP is a known residential-proxy exit node.

    Returns ResidentialProxyDetails with `is_residential_proxy` (the canonical
    yes/no), and — when true — `service`, `last_seen` (YYYY-MM-DD), and
    `percent_days_seen` over a 7-day window. Useful for fraud, bot, and
    ad-fraud detection. Requires IPINFO_API_TOKEN with the Enterprise
    residential-proxy add-on; absence surfaces as `auth_insufficient_scope`
    (distinct from `auth_invalid` for a missing/wrong token).
    """
    handler, _ = _get_handler_and_cache(ctx)

    ip = ip.strip()
    _validate_ip(ip)

    await ctx.info(f"Checking residential proxy status for {ip}")

    try:
        result = await ipinfo_resproxy_lookup(handler, ip)
        return result
    except Exception as e:
        await ctx.error(f"Residential proxy lookup failed: {e}")
        _raise_from_upstream(e)


@mcp.tool(
    annotations={"readOnlyHint": True, "openWorldHint": True},
    meta={"introduced_in": "0.5.0"},
    timeout=MAP_TOOL_TIMEOUT_SECONDS,
)
async def ipinfo_generate_map_url(
    ips: Annotated[
        list[str],
        Field(
            description="IPv4/IPv6 addresses to plot. Invalid or special-use IPs are filtered.",
            min_length=1,
            max_length=MAX_LOOKUP_IPS,
            examples=[["8.8.8.8", "1.1.1.1", "208.67.222.222"]],
        ),
    ],
    ctx: Context = CurrentContext(),
) -> MapResult:
    """Build an interactive ipinfo.io map for a set of IPs.

    Returns MapResult{url, mapped_ip_count, skipped_ips, skipped_count,
    truncated}. `skipped_ips` is a list of {ip, reason} entries for filtered
    inputs, capped at 100; `truncated` flags overflow. `skipped_count` is the
    true total even when the list is capped, so `mapped_ip_count +
    skipped_count` equals the input length. Errors raise ToolError with a
    JSON-encoded envelope.
    """
    if len(ips) > MAX_LOOKUP_IPS:
        # Schema enforces the cap, but defense-in-depth covers callers that
        # bypass schema validation (e.g., direct Python invocation).
        _raise_envelope(
            "too_many_ips",
            f"Too many IPs ({len(ips)}). Maximum is {MAX_LOOKUP_IPS:,} for map generation.",
            temporary=False,
            field="ips",
            value=len(ips),
            repair={
                "limit": MAX_LOOKUP_IPS,
                "received": len(ips),
                "hint": f"Reduce ips to <= {MAX_LOOKUP_IPS} entries.",
            },
        )

    valid_ips, skipped = await _filter_valid_ips(ips, ctx)

    if not valid_ips:
        _raise_envelope(
            "no_valid_ips",
            "No valid IP addresses to map; all inputs were filtered as invalid or special-use.",
            temporary=False,
            field="ips",
            repair={
                "hint": "Provide at least one public IPv4 or IPv6 address.",
                "skipped_count": len(skipped),
            },
        )

    await ctx.info(f"Generating map for {len(valid_ips)} IP address(es)")

    # Pull the token from the handler (captured at startup) instead of
    # re-reading the environment, so a runtime IPINFO_API_TOKEN mutation
    # cannot produce divergent behavior between the lookup and map paths.
    handler, _ = _get_handler_and_cache(ctx)
    try:
        url = await ipinfo_get_map_url(valid_ips, token=handler.access_token)
        await ctx.info("Map URL generated successfully")
    except Exception as e:
        await ctx.error(f"Map generation failed: {e}")
        _raise_from_upstream(e)

    skipped_entries, truncated = _build_skipped_list(skipped)
    return MapResult.model_validate(
        {
            "url": url,
            "mapped_ip_count": len(valid_ips),
            "skipped_ips": skipped_entries,
            "skipped_count": len(skipped),
            "truncated": truncated,
        }
    )


# --- Deprecated aliases ------------------------------------------------------
#
# Old tool names from <= 0.4.x. They forward to the new tools so cached MCP
# clients still work for one minor version. Removed in 0.6.0.


@mcp.tool(
    annotations={"readOnlyHint": True, "openWorldHint": True},
    tags={"deprecated"},
    meta={"deprecated_since": "0.5.0", "replaced_by": "ipinfo_lookup_ips"},
)
async def get_ip_details(
    ips: Annotated[
        list[str] | None,
        Field(
            description=(
                "[DEPRECATED in 0.5.0; use ipinfo_lookup_my_ip when ips is None, "
                "or ipinfo_lookup_ips otherwise. Removed in 0.6.0.] "
                "IP address(es) to analyze (IPv4 or IPv6). Pass a list of one or "
                "more IPs. If not provided, analyzes the requesting client's IP "
                "address."
            ),
            examples=[["8.8.8.8"], ["8.8.8.8", "1.1.1.1", "208.67.222.222"]],
        ),
    ] = None,
    ctx: Context = CurrentContext(),
) -> list[IPDetails]:
    """[DEPRECATED in 0.5.0 — use ipinfo_lookup_my_ip / ipinfo_lookup_ips. Removed in 0.6.0.]

    Forwards to ipinfo_lookup_my_ip when called with no `ips` (or `ips=None`),
    and to ipinfo_lookup_ips otherwise. Behavior is otherwise unchanged.
    """
    handler, cache = _get_handler_and_cache(ctx)
    if ips is None:
        return [await _do_my_ip_lookup(handler, cache, ctx)]
    return await _do_batch_lookup(handler, cache, ips, ctx)


@mcp.tool(
    annotations={"readOnlyHint": True, "openWorldHint": True},
    tags={"deprecated"},
    meta={
        "deprecated_since": "0.5.0",
        "replaced_by": "ipinfo_check_residential_proxy",
    },
)
async def get_residential_proxy_info(
    ip: Annotated[
        str,
        Field(
            description=(
                "[DEPRECATED in 0.5.0; use ipinfo_check_residential_proxy. Removed "
                "in 0.6.0.] The IP address to check for residential proxy usage "
                "(IPv4 or IPv6)."
            ),
            examples=["142.250.80.46"],
        ),
    ],
    ctx: Context = CurrentContext(),
) -> ResidentialProxyDetails:
    """[DEPRECATED in 0.5.0 — use ipinfo_check_residential_proxy. Removed in 0.6.0.]"""
    return await ipinfo_check_residential_proxy(ip=ip, ctx=ctx)


@mcp.tool(
    annotations={"readOnlyHint": True, "openWorldHint": True},
    tags={"deprecated"},
    meta={
        "deprecated_since": "0.5.0",
        "replaced_by": "ipinfo_generate_map_url",
    },
)
async def get_map_url(
    ips: Annotated[
        list[str],
        Field(
            description=(
                "[DEPRECATED in 0.5.0; use ipinfo_generate_map_url. Removed in "
                "0.6.0.] List of IP addresses to visualize on a map (IPv4 or "
                "IPv6). Maximum 500,000 IPs."
            ),
            min_length=1,
            max_length=MAX_LOOKUP_IPS,
            examples=[["8.8.8.8", "1.1.1.1", "208.67.222.222"]],
        ),
    ],
    ctx: Context = CurrentContext(),
) -> str:
    """[DEPRECATED in 0.5.0 — use ipinfo_generate_map_url. Removed in 0.6.0.]

    Returns just the bare map URL string for 0.4.x cached-client parity.
    Callers wanting structured skip/truncation metadata should call
    ipinfo_generate_map_url directly.
    """
    result = await ipinfo_generate_map_url(ips=ips, ctx=ctx)
    return str(result.url)
