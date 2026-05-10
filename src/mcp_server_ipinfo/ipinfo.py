import os
from datetime import datetime, timezone

import httpx
import ipinfo

from .models import IPDetails, ResidentialProxyDetails

IPINFO_API_URL = "https://ipinfo.io"


def _utc_timestamp() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _flatten_nested_response(details: dict) -> dict:
    """Flatten Core/Plus API nested response shape onto the flat IPDetails schema.

    Core and Plus responses nest geolocation under ``geo`` and AS info under ``as``;
    the standard endpoint puts these at the top level. This promotes nested keys to
    the top level so a single Pydantic schema works for both, and renames the ``as``
    key (a Python keyword) to ``asn``.

    The ``geo`` block uses ``country`` for the full country name and
    ``country_code`` for the ISO alpha-2; the flat schema uses ``country`` for the
    alpha-2 and ``country_name`` for the full name, so those are remapped.
    Top-level keys win over nested keys on conflict.

    ``mobile`` and ``anonymous`` blocks (Plus only) are intentionally left untouched
    until their field shapes can be verified against a real Plus response.
    """
    out = dict(details)

    geo = out.pop("geo", None)
    if isinstance(geo, dict):
        geo = dict(geo)
        if "country" in geo:
            geo["country_name"] = geo.pop("country")
        if "country_code" in geo:
            geo["country"] = geo.pop("country_code")
        for key, value in geo.items():
            out.setdefault(key, value)

    as_block = out.pop("as", None)
    if as_block is not None and "asn" not in out:
        out["asn"] = as_block

    return out


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
    return IPDetails(
        **_flatten_nested_response(details.all), ts_retrieved=_utc_timestamp()
    )


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

    ts = _utc_timestamp()
    return {
        ip: IPDetails(**_flatten_nested_response(details.all), ts_retrieved=ts)
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
        ts_retrieved=_utc_timestamp(),
    )


DEFAULT_MAP_TIMEOUT_SECONDS = 30.0


async def ipinfo_get_map_url(
    ips: list[str],
    *,
    token: str | None = None,
    timeout: float = DEFAULT_MAP_TIMEOUT_SECONDS,
) -> str:
    """
    Get a URL to an interactive map visualization of IP addresses.

    The map is hosted on ipinfo.io and supports up to 500,000 IPs.

    Args:
        ips: List of IP address strings to visualize on the map.
        token: IPInfo API token to authorize the request. Pass the value once
            from the calling layer (typically ``handler.access_token`` set at
            startup) so the environment is not re-read on every call.
            ``None`` sends no Authorization header (free-tier behavior).
            Keyword-only.
        timeout: Request timeout in seconds. Bounds the HTTP call so a hung
            upstream cannot block the tool indefinitely. Keyword-only.

    Returns:
        URL to the interactive map.

    Raises:
        httpx.HTTPStatusError: If the API request fails.
        httpx.TimeoutException: If the request exceeds ``timeout``.
    """
    headers = {
        "content-type": "application/json",
        "user-agent": "mcp-server-ipinfo",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(
            f"{IPINFO_API_URL}/map?cli=1",
            json=ips,
            headers=headers,
        )
        response.raise_for_status()
        return response.json()["reportUrl"]
