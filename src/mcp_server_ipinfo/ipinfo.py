import os
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv6Address

import httpx
import ipinfo

from .models import IPDetails, ResidentialProxyDetails

IPINFO_API_URL = "https://ipinfo.io"


async def create_async_handler(**kwargs) -> ipinfo.AsyncHandler:
    """
    Create an async IPInfo handler.

    Args:
        **kwargs: Additional arguments to pass to the handler.

    Returns:
        An initialized AsyncHandler instance.
    """
    return ipinfo.getHandlerAsync(
        access_token=os.environ.get("IPINFO_API_TOKEN"),
        headers={"user-agent": "mcp-server-ipinfo"},
        **kwargs,
    )


async def ipinfo_lookup(handler: ipinfo.AsyncHandler, ip: str | None) -> IPDetails:
    """
    Retrieve detailed information about an IP address using the ipinfo.io service.

    Args:
        handler: The async IPInfo handler to use.
        ip: The IP address to look up. If None, returns information about
            the client's current IP address.

    Returns:
        IPDetails: A Pydantic model containing detailed information about the IP.

    Raises:
        ipinfo.exceptions.RequestQuotaExceededError: If the API request quota is exceeded
        ipinfo.exceptions.RequestFailedError: If the API request fails
        ValueError: If the provided IP address is invalid
    """
    details = await handler.getDetails(ip_address=ip)
    return IPDetails(**details.all, ts_retrieved=str(datetime.now(timezone.utc)))


async def ipinfo_batch_lookup(
    handler: ipinfo.AsyncHandler,
    ips: list[str],
    raise_on_fail: bool = False,
) -> dict[str, IPDetails]:
    """
    Retrieve detailed information about multiple IP addresses.

    Args:
        handler: The async IPInfo handler to use.
        ips: List of IP addresses to look up.
        raise_on_fail: If False, return partial results on errors.

    Returns:
        Dictionary mapping IP addresses to their IPDetails.

    Raises:
        ipinfo.exceptions.RequestQuotaExceededError: If raise_on_fail and quota exceeded
        ipinfo.exceptions.RequestFailedError: If raise_on_fail and request fails
    """
    results = await handler.getBatchDetails(
        ip_addresses=ips,
        raise_on_fail=raise_on_fail,
    )

    ts = str(datetime.now(timezone.utc))
    return {
        ip: IPDetails(**details.all, ts_retrieved=ts)
        for ip, details in results.items()
        if hasattr(details, "all")  # Skip failed lookups
    }


async def ipinfo_resproxy_lookup(
    handler: ipinfo.AsyncHandler, ip: str
) -> ResidentialProxyDetails:
    """
    Retrieve residential proxy information for an IP address.

    Args:
        handler: The async IPInfo handler to use.
        ip: The IP address to check.

    Returns:
        ResidentialProxyDetails with proxy information.

    Raises:
        ipinfo.exceptions.RequestQuotaExceededError: If the API request quota is exceeded
        ipinfo.exceptions.RequestFailedError: If the API request fails
    """
    details = await handler.getResproxy(ip_address=ip)
    return ResidentialProxyDetails(
        **details.all,
        ts_retrieved=str(datetime.now(timezone.utc)),
    )


async def ipinfo_get_map_url(ips: list[str | IPv4Address | IPv6Address]) -> str:
    """
    Get a URL to an interactive map visualization of IP addresses.

    The map is hosted on ipinfo.io and supports up to 500,000 IPs.

    Args:
        ips: List of IP addresses to visualize on the map.

    Returns:
        URL to the interactive map.

    Raises:
        httpx.HTTPStatusError: If the API request fails.
    """
    # Convert IP address objects to strings
    ip_strs = []
    for ip in ips:
        if isinstance(ip, (IPv4Address, IPv6Address)):
            ip_strs.append(ip.exploded)
        else:
            ip_strs.append(str(ip))

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{IPINFO_API_URL}/map?cli=1",
            json=ip_strs,
            headers={
                "content-type": "application/json",
                "user-agent": "mcp-server-ipinfo",
            },
        )
        response.raise_for_status()
        return response.json()["reportUrl"]
