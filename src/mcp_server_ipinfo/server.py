import os

from mcp.server.fastmcp import Context, FastMCP

from .ipinfo import ipinfo_lookup
from .models import IPDetails

# Create an MCP server
mcp = FastMCP("IPInfo")


@mcp.tool()
def get_ip_details(ip: str | None, ctx: Context) -> IPDetails:
    """Get information about an IP address.

    Use this tool to:
    - Determine the user's geographic location to coarse granularity
    - Get information about the user's internet service provider
    - Get information about a specific IP address

    Args:
        ip (str | None): The IP address to look up. If None, returns information
            about the requesting client's IP address.
        ctx (Context): The MCP request context.

    Returns:
        IPDetails: Object containing the following information about the IP address:
        - ip: The IP address.
        - hostname: The hostname associated with the IP address.
        - city: The city where the IP address is located.
        - region: The region/state where the IP address is located.
        - country: The two-letter ISO country code.
        - loc: The geographical coordinates in 'latitude,longitude' format.
        - org: The organization/ISP associated with the IP address.
        - postal: The postal/ZIP code.
        - timezone: The timezone of the IP address location.
        - country_name: The full name of the country.
        - isEU: Boolean indicating if the country is in the European Union.
        - country_flag_url: URL to the country's flag image.
        - country_flag: Dictionary containing country flag information.
        - country_currency: Dictionary containing country currency information.
        - continent: Dictionary containing continent information.
        - latitude: The latitude coordinate.
        - longitude: The longitude coordinate.
        - asn: Dictionary containing ASN information (paid plans only).
        - privacy: Dictionary containing privacy information (paid plans only).
        - carrier: Dictionary containing mobile operator information (paid plans only).
        - company: Dictionary containing company information (paid plans only).
        - domains: Dictionary containing domains information (paid plans only).
        - abuse: Dictionary containing abuse contact information (paid plans only).
        - bogon: Boolean indicating if the IP address is a bogon IP.
        - anycast: Boolean indicating if the IP address is an anycast IP.

    Note:
        This tool requires an IPINFO_API_TOKEN environment variable to be set for full functionality.
    """

    if "IPINFO_API_TOKEN" not in os.environ:
        ctx.warning("IPINFO_API_TOKEN is not set")

    return ipinfo_lookup(ip)
