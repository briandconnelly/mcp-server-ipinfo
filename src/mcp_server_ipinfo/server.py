import os

from mcp.server.fastmcp import Context, FastMCP

from .ipinfo import ipinfo_lookup
from .models import IPDetails

# Create an MCP server
mcp = FastMCP("IPInfo")


@mcp.tool()
def get_ip_details(ip: str | None, ctx: Context) -> IPDetails:
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

    if "IPINFO_API_TOKEN" not in os.environ:
        ctx.warning("IPINFO_API_TOKEN is not set")

    return ipinfo_lookup(ip)


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
