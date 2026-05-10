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
    This MCP server looks up information about IPv4 and IPv6 addresses via the
    IPInfo API: geographic location (country, region, city, coordinates), the
    owning organization / ISP, and (on paid plans) ASN, privacy/VPN/Tor/proxy
    detection, mobile carrier, company, abuse contacts, and hosted domains.

    Tools (current, ipinfo_-prefixed):
    - ipinfo_lookup_my_ip: Geolocate the calling client's own IP (no arguments).
    - ipinfo_lookup_ips: Geolocate one or more specific IPs. Supports
      detail="summary" to null heavy nested blocks for batch token savings.
    - ipinfo_check_residential_proxy: Check whether an IP is a known residential
      proxy exit (Enterprise add-on; tagged "enterprise").
    - ipinfo_generate_map_url: Build an interactive ipinfo.io map URL for a set
      of IPs. Returns a structured MapResult.

    Deprecated aliases (forwarding wrappers, removed in 0.6.0): get_ip_details,
    get_residential_proxy_info, get_map_url.

    What this server does NOT do:
    - Resolve hostnames or domains to IPs (use DNS tooling).
    - Look up IP ranges, CIDR blocks, or BGP routes.
    - Provide historical or time-series IP data — every result is the current
      snapshot from IPInfo.
    - Geolocate private, loopback, link-local, multicast, or other reserved
      addresses; these are filtered at the boundary with `special_ip_unsupported`.
    - Geolocate the actual user behind a VPN, proxy, Tor relay, or cloud host;
      results reflect the exit point's location, not the originating user's.
    - Score, classify, or otherwise attribute IPs as "malicious"; only the raw
      privacy/proxy signals are returned.

    Plan tiers (set IPINFO_API_TOKEN to enable):
    - No token (free Lite): country, country_code, continent, ASN basics.
    - Core: full geolocation, ASN details, privacy/VPN/proxy/Tor/hosting flags.
    - Plus: adds carrier and company data.
    - Enterprise: adds domains and abuse contacts; the residential-proxy add-on
      is what powers ipinfo_check_residential_proxy.

    Caching:
    - IP lookup results are cached in-memory for IPINFO_CACHE_TTL seconds
      (default 3600, i.e. one hour). Up to IPINFO_CACHE_SIZE entries (default
      4096) are retained; the oldest are evicted.
    - Cached records keep their original `ts_retrieved` timestamp; that field
      reflects when the lookup was first performed, not when the cached value
      was returned. Compare against the current time to gauge freshness.

    Transport notes:
    - Stdio is the default transport; ipinfo_lookup_my_ip resolves to the IP
      that ipinfo.io sees from this MCP server's outbound connection (typically
      the host's egress IP), not the end user's IP. Use ipinfo_lookup_ips when
      the caller already has the target IP.

    Errors:
    All tool errors carry a JSON-encoded ToolErrorEnvelope in the error message
    with a stable `code` (one of: auth_invalid, auth_insufficient_scope,
    quota_exceeded, timeout, api_error, invalid_ip_address, special_ip_unsupported,
    no_valid_ips, too_many_ips, unknown_error), a `temporary` flag, an optional
    `retry_after_ms`, and a `repair` hint. Parse the error string as JSON to branch.

    Address formats:
    IPv4 = four decimal octets separated by dots (e.g., 8.8.8.8).
    IPv6 = eight groups of four hexadecimal digits separated by colons
    (e.g., 2001:4860:4860::8888).
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
    """Return geolocation and ISP details for the calling client's own IP address.

    Useful when an agent wants to ground "where am I" without taking the IP as
    an argument. The result depends on the transport: on HTTP transports the
    IPInfo API observes the requesting party's IP; on stdio the result reflects
    the IP that the IPInfo API sees from this MCP server's outbound connection.
    For looking up specific IPs, use `ipinfo_lookup_ips` instead.

    Errors are JSON-encoded ToolErrorEnvelopes.
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
            description=(
                "List of IPv4 or IPv6 addresses to look up. Must contain at least 1 entry; "
                "max 500,000. Invalid or special-use IPs (private, loopback, etc.) are filtered "
                "with warnings."
            ),
            min_length=1,
            max_length=MAX_LOOKUP_IPS,
            examples=[["8.8.8.8"], ["8.8.8.8", "1.1.1.1", "208.67.222.222"]],
        ),
    ],
    detail: Annotated[
        DetailLevel,
        Field(
            description=(
                "Response density. 'full' (default) returns every IPDetails field. "
                "'summary' nulls heavy nested blocks (continent, country_flag*, "
                "country_currency, abuse, domains) for batch token savings while "
                "preserving shape parity."
            ),
        ),
    ] = "full",
    ctx: Context = CurrentContext(),
) -> list[IPDetails]:
    """Look up geolocation, ISP, and network details for one or more IP addresses.

    Returns a list of IPDetails preserving input order (after dedup and
    invalid-IP filtering). Use the `ip` field on each result to match back to
    your input.

    Common use cases:
    - Investigate one or more IP addresses for security analysis
    - Look up ISP and hosting provider information for a known address
    - Analyze server logs to identify visitor locations
    - Geographic distribution analysis across many IPs

    Detail toggle:
    - `detail="full"` (default): every available field, including decorative
      blocks like continent metadata and country flags.
    - `detail="summary"`: same shape, but heavy nested blocks are nulled out.
      Cuts response size for large batches without changing the parser contract.

    Errors are JSON-encoded ToolErrorEnvelopes with stable `code` values
    (invalid_ip_address, no_valid_ips, too_many_ips, auth_invalid,
    auth_insufficient_scope, quota_exceeded, timeout, api_error, unknown_error).

    Note: Some fields (asn, privacy, carrier, company, abuse, domains) require
    IPINFO_API_TOKEN with the appropriate plan tier.
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
            description="The IP address to check for residential proxy usage (IPv4 or IPv6).",
            examples=["142.250.80.46"],
        ),
    ],
    ctx: Context = CurrentContext(),
) -> ResidentialProxyDetails:
    """Check whether an IP address belongs to a residential proxy network.

    Residential proxies route traffic through real residential IP addresses,
    making them harder to detect than datacenter proxies. This tool identifies
    such IPs and returns details about the proxy service.

    Returns:
    - ip: The checked IP address
    - last_seen: Last date the proxy was active (YYYY-MM-DD)
    - percent_days_seen: Activity percentage over the last 7-day window
    - service: Name of the residential proxy service (None if not a known proxy)

    Common use cases:
    - Fraud detection and prevention
    - Bot detection
    - Ad fraud analysis
    - Security investigations

    Errors are JSON-encoded ToolErrorEnvelopes. A 403 from IPInfo surfaces as
    `auth_insufficient_scope` so agents can distinguish "needs a token" from
    "token lacks the residential-proxy add-on".

    Note: Requires IPINFO_API_TOKEN with the residential-proxy add-on enabled.
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
            description="List of IP addresses to visualize on a map (IPv4 or IPv6). Maximum 500,000 IPs.",
            min_length=1,
            max_length=MAX_LOOKUP_IPS,
            examples=[["8.8.8.8", "1.1.1.1", "208.67.222.222"]],
        ),
    ],
    ctx: Context = CurrentContext(),
) -> MapResult:
    """Generate an interactive map visualization for a set of IP addresses.

    Submits the IPs to ipinfo.io's map endpoint and returns a structured
    MapResult containing the URL, the count that made the map, the IPs that
    were filtered out (with reasons), and a truncation flag.

    Common use cases:
    - Visualize geographic distribution of server logs
    - Create shareable maps of user locations
    - Display IP address clusters for security analysis
    - Geographic visualization of network traffic

    Response shape (MapResult):
    - url: HttpUrl to the interactive map
    - mapped_ip_count: Number of IPs that made it onto the map
    - skipped_ips: List of (ip, reason) entries for inputs that were filtered;
      capped at 100 entries
    - skipped_count: Total filtered count, even when the list is truncated
    - truncated: True when skipped_ips was capped

    Errors are JSON-encoded ToolErrorEnvelopes (`too_many_ips`, `no_valid_ips`,
    upstream `api_error` / `timeout` / `auth_invalid` / `auth_insufficient_scope`
    / `quota_exceeded` / `unknown_error`).
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
