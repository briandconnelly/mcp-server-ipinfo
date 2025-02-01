import os

from mcp.server.fastmcp import FastMCP, Context

from .ipinfo import ipinfo_lookup
from .models import IPDetails

# Create an MCP server
mcp = FastMCP("IPInfo")


@mcp.tool()
def get_ip_details(ip: str | None, ctx: Context) -> IPDetails:
    """Get information about an IP address.

    Args:
        ip (str | None): The IP address to look up. If None, returns information
            about the requesting client's IP address.
        ctx (Context): The MCP request context.

    Returns:
        IPDetails: Object containing information about the IP address,
            including geographic location, network operator, and more.

    Note:
        This tool requires an IPInfo API Token specified via the IPINFO_API_TOKEN
        environment variable for full functionality.
    """

    if "IPINFO_API_TOKEN" not in os.environ:
        ctx.warning("IPINFO_API_TOKEN is not set")

    return ipinfo_lookup(ip)
