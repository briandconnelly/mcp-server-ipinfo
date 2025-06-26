import ipaddress
import os
from typing import Annotated

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from .cache import IPInfoCache
from .ipinfo import ipinfo_lookup
from .models import IPDetails

cache = IPInfoCache()


# Create an MCP server
mcp = FastMCP(
    name="IP Address Geolocation and Internet Service Provider Lookup",
    instructions="""
    This MCP server provides tools to look up IP address information using the IPInfo API.
    For a given IPv4 or IPv6 address, it provides information about the geographic location of that device, the internet service provider, and additional information about the connection.
    If we assume that the user is physically using that device, the location of that user is the location of the device.

    The IPInfo API is free to use, but it has a rate limit.
    Paid plans provide more information, but are not required for basic use.
    The IPINFO_API_TOKEN environment variable with a valid API key can be set to enable paid features.

    The accuracy of the location determined by IP geolocation can vary.
    Generally, the country is accurate, but the city and region may not be.
    If a user is using a VPN, Proxy, Tor, or hosting provider, the location returned will be the location of that service's exit point, not the user's actual location.
    If the user is using a mobile/cellular connection, the location returned may differ from the user's actual location.
    If anycast is true, the location returned may differ from the user's actual location.
    In any of these cases, if the user's location is important, you should ask the user for their location.

    An IPv4 address consists of four decimal numbers separated by dots (.), known as octets.
    An IPv6 address consists of eight groups of four hexadecimal numbers separated by colons (:).

    Recommended companion servers:
    - unifi-network-mcp: Provides information about the devices, configuration, and performance of the user's local area network (LAN), their Wi-Fi network, and their connection to the internet.
    - cloudflare: Provides information about historical internet speed/quality summaries for a given internet service provider or location. For example, we can provide Cloudflare with the internet service provider or location determined using get_ip_details to obtain information about the historical and competitiveperformance of the user's internet service provider.
    """,
)


@mcp.tool()
async def get_ip_details(
    ip: Annotated[
        str | None,
        Field(
            description="The IP address to analyze (IPv4 or IPv6). If None or not provided, analyzes the requesting client's IP address.",
            examples=["8.8.8.8", "2001:4860:4860::8888", None],
        ),
    ] = None,
    ctx: Context = None,
) -> IPDetails:
    """Get detailed information about an IP address including location, ISP, and network details.

    This tool provides comprehensive IP address analysis including geographic location,
    internet service provider information, network details, and security context.
    Use when you need to understand the user's location, ISP, and network details or those of
    a given IP address.

    Common use cases:
    - Analyze user's current location and connection details (leave ip parameter blank)
    - Investigate suspicious IP addresses for security analysis
    - Determine geographic distribution of website visitors or API users
    - Look up ISP and hosting provider information for network troubleshooting
    - Get timezone information for scheduling or time-sensitive operations
    - Verify if an IP belongs to a VPN, proxy, or hosting provider
    - Check country-specific compliance requirements (EU, etc.)

    Args:
        ip: The IP address to analyze (IPv4 or IPv6). If None or not provided,
            analyzes the requesting client's IP address.
        ctx: The MCP request context.

    Returns:
        IPDetails: Comprehensive IP information including:

        Basic Info:
        - ip: The IP address that was analyzed
        - hostname: Associated hostname/domain name
        - org: Organization/ISP name (e.g., "Google LLC", "Comcast Cable")
        - ts_retrieved: The timestamp when the IP address was looked up (UTC)

        Geographic Location:
        - city: City name
        - region: State/province/region name
        - country: Two-letter ISO country code (e.g., "US", "GB")
        - country_name: Full country name
        - postal: ZIP/postal code
        - loc: Coordinates as "latitude,longitude" string
        - latitude/longitude: Separate coordinate values
        - timezone: IANA timezone identifier (e.g., "America/New_York")

        Regional Info:
        - continent: Continent information dictionary
        - country_flag: Country flag image data
        - country_flag_url: URL to country flag image
        - country_currency: Currency information for the country
        - isEU: True if country is in European Union

        Network/Security Info (some features require paid API plan):
        - asn: Autonomous System Number details
        - privacy: VPN/proxy/hosting detection data
        - carrier: Mobile network operator info (for cellular IPs)
        - company: Company/organization details
        - domains: Associated domain names
        - abuse: Abuse contact information
        - bogon: True if IP is in bogon/reserved range
        - anycast: True if IP uses anycast routing

    Examples:
        # Get your own IP details
        my_info = get_ip_details()

        # Analyze a specific IP
        server_info = get_ip_details("8.8.8.8")

        # Check if IP is from EU for GDPR compliance
        details = get_ip_details("192.168.1.1")
        is_eu_user = details.isEU

    Note:
        Some advanced features (ASN, privacy detection, carrier info) require
        an IPINFO_API_TOKEN environment variable with a paid API plan.
        Basic location and ISP info works without authentication.
    """

    ctx.info(f"Getting details for IP address {ip}")

    if "IPINFO_API_TOKEN" not in os.environ:
        ctx.warning("IPINFO_API_TOKEN is not set")

    if ip in ("null", "", "undefined", "0.0.0.0", "::"):
        ip = None

    # If IP address given, check cache first
    if ip and (cached := cache.get(ip)):
        ctx.debug(f"Returning cached result for {ip}")
        return cached

    if ip:
        try:
            parsed_ip = ipaddress.ip_address(ip)

            if parsed_ip.is_private:
                raise ToolError(
                    f"{ip} is a private IP address. Geolocation may not be meaningful."
                )
            elif parsed_ip.is_loopback:
                raise ToolError(
                    f"{ip} is a loopback IP address. Geolocation may not be meaningful."
                )
            elif parsed_ip.is_multicast:
                raise ToolError(
                    f"{ip} is a multicast IP address. Geolocation may not be meaningful."
                )
            elif parsed_ip.is_reserved:
                raise ToolError(
                    f"{ip} is a reserved IP address. Geolocation may not be meaningful."
                )
        except ValueError:
            ctx.error(f"Got an invalid IP address: {ip}")
            raise ToolError(f"{ip} is not a valid IP address")

    try:
        result = ipinfo_lookup(ip)
        cache.set(result.ip, result)
        return result
    except Exception as e:
        ctx.error(f"Failed to look up IP details: {str(e)}")
        raise ToolError(f"Lookup failed for IP address {str(e)}")


@mcp.tool()
def get_ipinfo_api_token(ctx: Context) -> str | None:
    """Check if the IPINFO_API_TOKEN environment variable is configured for enhanced IP lookups.

    This tool verifies whether the IPInfo API token is properly configured in the environment.
    The token enables access to premium features like ASN information, privacy detection,
    carrier details, and enhanced accuracy for IP geolocation analysis.

    Common use cases:
    - Verify API token configuration before performing advanced IP analysis
    - Troubleshoot why certain IP lookup features are unavailable
    - Check system configuration for applications requiring premium IP data
    - Validate environment setup during deployment or testing
    - Determine available feature set for IP analysis workflows

    Args:
        ctx: The MCP request context.

    Returns:
        bool: True if IPINFO_API_TOKEN environment variable is set and configured,
              False if the token is missing or not configured.

    Examples:
        # Check if premium features are available
        has_token = get_ipinfo_api_token()
        if has_token:
            # Safe to use advanced IP analysis features
            details = get_ip_details("8.8.8.8")  # Will include ASN, privacy data
        else:
            # Limited to basic IP information only
            details = get_ip_details("8.8.8.8")  # Basic location/ISP only

        # Use in conditional workflows
        if get_ipinfo_api_token():
            # Perform advanced IP geolocation analysis
            pass
        else:
            # Fall back to basic analysis or prompt for token configuration
            pass

    Note:
        The IPInfo API provides basic location and ISP information without authentication,
        but premium features (ASN details, VPN/proxy detection, carrier information,
        enhanced accuracy) require a valid API token from https://ipinfo.io/.
    """
    return os.environ.get("IPINFO_API_TOKEN")
