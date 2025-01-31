import os

from mcp.server.fastmcp import FastMCP, Context

from .ipinfo import ipinfo_lookup
from .models import IPDetails

# Create an MCP server
mcp = FastMCP("IPInfo")


@mcp.tool()
def get_ip_details(ip: str | None, ctx: Context) -> IPDetails:
    """Get information about a given IP address"""

    if "IPINFO_API_TOKEN" not in os.environ:
        ctx.warning("IPINFO_API_TOKEN is not set")

    return ipinfo_lookup(ip)
