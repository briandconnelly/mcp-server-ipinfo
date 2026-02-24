"""Pytest configuration and fixtures for mcp-server-ipinfo tests."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_server_ipinfo.cache import IPInfoCache
from mcp_server_ipinfo.models import (
    ASNInfo,
    ASNPrefix,
    IPDetails,
    IPRangesInfo,
    ResidentialProxyDetails,
)


def create_mock_details(ip: str, **kwargs) -> MagicMock:
    """Create a mock ipinfo Details object."""
    mock = MagicMock()
    mock.all = {
        "ip": ip,
        "hostname": f"host-{ip.replace('.', '-')}.example.com",
        "city": "Mountain View",
        "region": "California",
        "country": "US",
        "loc": "37.3860,-122.0838",
        "org": "AS15169 Google LLC",
        "postal": "94035",
        "timezone": "America/Los_Angeles",
        "country_name": "United States",
        "isEU": False,
        "latitude": 37.3860,
        "longitude": -122.0838,
        **kwargs,
    }
    return mock


def create_mock_resproxy_details(ip: str, **kwargs) -> MagicMock:
    """Create a mock ipinfo residential proxy Details object."""
    mock = MagicMock()
    mock.all = {
        "ip": ip,
        "last_seen": "2024-01-15",
        "percent_days_seen": 85.7,
        "service": "Luminati",
        **kwargs,
    }
    return mock


@pytest.fixture
def mock_handler() -> AsyncMock:
    """Create a mock async ipinfo handler."""
    handler = AsyncMock()

    async def mock_get_details(ip_address=None):
        if ip_address is None:
            return create_mock_details("203.0.113.1")
        return create_mock_details(ip_address)

    async def mock_get_batch_details(ip_addresses, raise_on_fail=True):
        return {ip: create_mock_details(ip) for ip in ip_addresses}

    async def mock_get_resproxy(ip_address):
        return create_mock_resproxy_details(ip_address)

    handler.getDetails = mock_get_details
    handler.getBatchDetails = mock_get_batch_details
    handler.getResproxy = mock_get_resproxy
    handler.deinit = AsyncMock()

    return handler


@pytest.fixture
def cache() -> IPInfoCache:
    """Create a fresh cache instance."""
    return IPInfoCache(ttl_seconds=3600)


@pytest.fixture
def sample_ip_details() -> IPDetails:
    """Create a sample IPDetails object."""
    return IPDetails(
        ip="8.8.8.8",
        hostname="dns.google",
        city="Mountain View",
        region="California",
        country="US",
        loc="37.3860,-122.0838",
        org="AS15169 Google LLC",
        postal="94035",
        timezone="America/Los_Angeles",
        country_name="United States",
        isEU=False,
        latitude=37.3860,
        longitude=-122.0838,
        ts_retrieved=str(datetime.now(timezone.utc)),
    )


@pytest.fixture
def sample_residential_proxy_details() -> ResidentialProxyDetails:
    """Create a sample ResidentialProxyDetails object."""
    return ResidentialProxyDetails(
        ip="142.250.80.46",
        last_seen="2024-01-15",
        percent_days_seen=85.7,
        service="Luminati",
        ts_retrieved=str(datetime.now(timezone.utc)),
    )


@pytest.fixture
def sample_asn_info() -> ASNInfo:
    """Create a sample ASNInfo object."""
    return ASNInfo(
        asn="AS15169",
        name="Google LLC",
        country="US",
        allocated="2000-03-30",
        registry="arin",
        domain="google.com",
        num_ips=17574144,
        type="hosting",
        prefixes=[
            ASNPrefix(
                netblock="8.8.4.0/24",
                id="AS15169",
                name="Google LLC",
                country="US",
            ),
            ASNPrefix(
                netblock="8.8.8.0/24",
                id="AS15169",
                name="Google LLC",
                country="US",
            ),
        ],
        prefixes6=[
            ASNPrefix(
                netblock="2001:4860::/32",
                id="AS15169",
                name="Google LLC",
                country="US",
            ),
        ],
        ts_retrieved=str(datetime.now(timezone.utc)),
    )


@pytest.fixture
def sample_ip_ranges_info() -> IPRangesInfo:
    """Create a sample IPRangesInfo object."""
    return IPRangesInfo(
        domain="google.com",
        num_ranges=3,
        ranges=[
            "8.8.4.0/24",
            "8.8.8.0/24",
            "8.34.208.0/20",
        ],
        ts_retrieved=str(datetime.now(timezone.utc)),
    )


@pytest.fixture
def mock_context() -> MagicMock:
    """Create a mock FastMCP Context."""
    ctx = MagicMock()
    ctx.info = AsyncMock()
    ctx.debug = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.error = AsyncMock()
    return ctx


@pytest.fixture
def mock_lifespan_state(mock_handler, cache) -> dict:
    """Create mock lifespan state with handler and cache."""
    return {
        "ipinfo_handler": mock_handler,
        "cache": cache,
    }


@pytest.fixture
def mock_context_with_state(mock_context, mock_lifespan_state) -> MagicMock:
    """Create a mock context with lifespan context."""
    # Mock the FastMCP server with _lifespan_result (FastMCP 2.x pattern)
    mock_fastmcp = MagicMock()
    mock_fastmcp._lifespan_result = mock_lifespan_state
    mock_context.fastmcp = mock_fastmcp
    # Also provide lifespan_context for forward compatibility with FastMCP 3.x
    mock_context.lifespan_context = mock_lifespan_state
    return mock_context
