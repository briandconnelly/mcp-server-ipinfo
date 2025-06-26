import os
from datetime import datetime, timezone

import ipinfo

from .models import IPDetails


def ipinfo_lookup(ip: str | None, **kwargs) -> IPDetails:
    """
    Retrieve detailed information about an IP address using the ipinfo.io service.

    This function fetches comprehensive information about the specified IP address,
    including geolocation data, ISP details, and country information. If no IP is
    provided, it returns information about the client's current IP address.

    Args:
        ip: The IP address to look up. If None, returns information about the
            client's current IP address.
        **kwargs: Additional arguments to pass to the ipinfo handler. These can
            include timeout settings, cache settings, or other ipinfo.io options.

    Returns:
        IPDetails: A Pydantic model containing detailed information about the IP,
                  including location, organization, and country details.

    Raises:
        ipinfo.exceptions.RequestQuotaExceededError: If the API request quota is exceeded
        ipinfo.exceptions.RequestFailedError: If the API request fails
        ValueError: If the provided IP address is invalid

    Example:
        >>> details = ipinfo_lookup("8.8.8.8")
        >>> print(details.country)
        'US'
        >>> print(details.org)
        'Google LLC'
    """

    handler = ipinfo.getHandler(
        access_token=os.environ.get("IPINFO_API_TOKEN", None),
        headers={"user-agent": "mcp-server-ipinfo", "custom_header": "yes"},
        **kwargs,
    )

    details = handler.getDetails(ip_address=ip)

    return IPDetails(**details.all, ts_retrieved=str(datetime.now(timezone.utc)))
