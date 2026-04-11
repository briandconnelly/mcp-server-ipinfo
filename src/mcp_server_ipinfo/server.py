import ipaddress
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

import ipinfo
from fastmcp import Context, FastMCP
from fastmcp.dependencies import CurrentContext
from fastmcp.exceptions import ToolError
from pydantic import Field

from .cache import IPInfoCache
from .ipinfo import (
    create_async_handler,
    ipinfo_batch_lookup,
    ipinfo_get_map_url,
    ipinfo_lookup,
    ipinfo_resproxy_lookup,
)
from .models import IPDetails, ResidentialProxyDetails


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
    This MCP server provides tools to look up IP address information using the IPInfo API.
    For a given IPv4 or IPv6 address, it provides information about the geographic location
    of that device, the internet service provider, and additional information about the connection.

    Available tools:
    - get_ip_details: Look up details for one or more IP addresses
    - get_residential_proxy_info: Check if an IP is a residential proxy
    - get_map_url: Generate an interactive map URL showing IP locations

    The IPInfo API is free to use with rate limits. Paid plans provide more information.
    Set the IPINFO_API_TOKEN environment variable with a valid API key for premium features.

    The accuracy of IP geolocation can vary. Generally, the country is accurate, but the
    city and region may not be. If a user is using a VPN, Proxy, Tor, or hosting provider,
    the location returned will be the location of that service's exit point.

    An IPv4 address consists of four decimal numbers separated by dots (.).
    An IPv6 address consists of eight groups of four hexadecimal numbers separated by colons (:).
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


def _validate_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """
    Validate an IP address and check for special addresses.

    Args:
        ip: The IP address string to validate.

    Returns:
        The parsed IP address object.

    Raises:
        ToolError: If the IP is invalid or is a special address type.
    """
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        raise ToolError(f"{ip} is not a valid IP address")

    # Check in order of specificity - loopback and reserved are subsets of private
    for attr, label in _IP_CHECKS:
        if getattr(parsed_ip, attr):
            raise ToolError(
                f"{ip} is a {label} IP address. Geolocation is not available."
            )

    return parsed_ip


def _normalize_ip(ip: str) -> str | None:
    """Normalize empty/placeholder IP values to None, stripping whitespace."""
    ip = ip.strip()
    if ip in _NORMALIZE_SENTINELS:
        return None
    return ip


async def _filter_valid_ips(
    ips: list[str], ctx: Context
) -> tuple[list[str], list[tuple[str, str]]]:
    """Normalize, deduplicate, validate IPs and log warnings for skipped ones.

    Returns:
        A tuple of (valid_ips, skipped) where skipped contains (ip, reason) pairs.
    """
    seen: set[str] = set()
    valid: list[str] = []
    skipped: list[tuple[str, str]] = []

    for ip in ips:
        norm = _normalize_ip(ip)
        if norm is None or norm in seen:
            continue
        seen.add(norm)

        try:
            _validate_ip(norm)
            valid.append(norm)
        except ToolError as e:
            skipped.append((ip, str(e)))

    for ip, reason in skipped:
        await ctx.warning(f"Skipping {ip}: {reason}")

    return valid, skipped


@mcp.tool(
    annotations={
        "readOnlyHint": True,
        "openWorldHint": True,
    }
)
async def get_ip_details(
    ips: Annotated[
        list[str] | None,
        Field(
            description="IP address(es) to analyze (IPv4 or IPv6). Pass a list of one or more IPs. If not provided, analyzes the requesting client's IP address.",
            examples=[["8.8.8.8"], ["8.8.8.8", "1.1.1.1", "208.67.222.222"]],
        ),
    ] = None,
    ctx: Context = CurrentContext(),
) -> list[IPDetails]:
    """Get detailed information about IP addresses including location, ISP, and network details.

    This tool provides comprehensive IP address analysis including geographic location,
    internet service provider information, and network details.

    Common use cases:
    - Analyze user's current location and connection details (omit ips parameter)
    - Investigate one or more IP addresses for security analysis
    - Look up ISP and hosting provider information
    - Analyze server logs to identify visitor locations
    - Geographic distribution analysis

    Returns a list of IPDetails, each with: ip, hostname, city, region, country, postal,
    timezone, org, loc (coordinates), and premium fields like asn, privacy, carrier if available.

    Invalid or special IPs (private, loopback, etc.) are skipped with warnings.
    Use the 'ip' field in results to match back to your input.

    Note: Some features require IPINFO_API_TOKEN environment variable.
    """
    handler, cache = _get_handler_and_cache(ctx)

    # Handle client IP lookup (no IPs provided)
    if ips is None:
        await ctx.info("Looking up client IP details")
        try:
            result = await ipinfo_lookup(handler, None)
            await cache.set(str(result.ip), result)
            return [result]
        except Exception as e:
            await ctx.error(f"Failed to look up client IP: {e}")
            raise ToolError(f"Lookup failed: {e}")

    valid_ips, skipped = await _filter_valid_ips(ips, ctx)

    if not valid_ips:
        raise ToolError("No valid IP addresses provided")

    # Check cache
    cached_results = await cache.get_batch(valid_ips)
    ips_to_lookup = [ip for ip in valid_ips if ip not in cached_results]

    if cached_results:
        await ctx.info(f"Found {len(cached_results)} IPs in cache")

    if not ips_to_lookup and not cached_results:
        raise ToolError("No valid IP addresses to look up")

    # Perform lookup for non-cached IPs
    new_results = {}
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
            raise ToolError(f"Lookup failed: {e}")

    # Combine and return in original order
    all_results = {**cached_results, **new_results}
    ordered_results = [all_results[ip] for ip in valid_ips if ip in all_results]

    await ctx.info(
        f"Returning {len(ordered_results)} result(s) "
        f"({len(skipped)} skipped, {len(cached_results)} cached)"
    )

    return ordered_results


@mcp.tool(
    annotations={
        "readOnlyHint": True,
        "openWorldHint": True,
    }
)
async def get_residential_proxy_info(
    ip: Annotated[
        str,
        Field(
            description="The IP address to check for residential proxy usage (IPv4 or IPv6).",
            examples=["142.250.80.46"],
        ),
    ],
    ctx: Context = CurrentContext(),
) -> ResidentialProxyDetails:
    """Check if an IP address is associated with a residential proxy service.

    Residential proxies route traffic through real residential IP addresses,
    making them harder to detect than datacenter proxies. This tool identifies
    such IPs and provides details about the proxy service.

    Returns:
    - ip: The checked IP address
    - last_seen: Last date the proxy was active (YYYY-MM-DD)
    - percent_days_seen: Activity percentage over the last 7 days
    - service: Name of the residential proxy service

    Common use cases:
    - Fraud detection and prevention
    - Bot detection
    - Ad fraud analysis
    - Security investigations

    Note: Requires IPINFO_API_TOKEN with residential proxy data access.
    """
    handler, _ = _get_handler_and_cache(ctx)

    # Validate IP
    ip = ip.strip()
    _validate_ip(ip)

    await ctx.info(f"Checking residential proxy status for {ip}")

    try:
        result = await ipinfo_resproxy_lookup(handler, ip)
        return result
    except Exception as e:
        await ctx.error(f"Residential proxy lookup failed: {e}")
        raise ToolError(f"Residential proxy lookup failed: {e}")


@mcp.tool(
    annotations={
        "readOnlyHint": True,
        "openWorldHint": True,
    }
)
async def get_map_url(
    ips: Annotated[
        list[str],
        Field(
            description="List of IP addresses to visualize on a map (IPv4 or IPv6). Maximum 500,000 IPs.",
            min_length=1,
            examples=[["8.8.8.8", "1.1.1.1", "208.67.222.222"]],
        ),
    ],
    ctx: Context = CurrentContext(),
) -> str:
    """Generate a URL to an interactive map visualization of IP addresses.

    Creates a map on ipinfo.io showing the geographic locations of the provided
    IP addresses. The map is interactive and can be shared.

    Common use cases:
    - Visualize geographic distribution of server logs
    - Create shareable maps of user locations
    - Display IP address clusters for security analysis
    - Geographic visualization of network traffic

    Returns a URL to the interactive map that can be opened in a browser.

    Note: Invalid or special IPs (private, loopback, etc.) are filtered out.
    """
    MAX_MAP_IPS = 500_000
    if len(ips) > MAX_MAP_IPS:
        raise ToolError(
            f"Too many IPs ({len(ips)}). Maximum is {MAX_MAP_IPS:,} for map generation."
        )

    valid_ips, _ = await _filter_valid_ips(ips, ctx)

    if not valid_ips:
        raise ToolError("No valid IP addresses to map")

    await ctx.info(f"Generating map for {len(valid_ips)} IP address(es)")

    try:
        url = await ipinfo_get_map_url(valid_ips)
        await ctx.info("Map URL generated successfully")
        return url
    except Exception as e:
        await ctx.error(f"Map generation failed: {e}")
        raise ToolError(f"Map generation failed: {e}")
