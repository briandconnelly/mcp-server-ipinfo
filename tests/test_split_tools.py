"""Tests for the split tools introduced in 0.5.0.

`get_ip_details` is split into:
- `ipinfo_lookup_my_ip()` — no args; the calling client's IP.
- `ipinfo_lookup_ips(ips, detail="full")` — list lookup with optional null-stripping.

The original `get_ip_details` is retained as a deprecated alias.
"""

import pytest
from fastmcp.exceptions import ToolError

from mcp_server_ipinfo.models import IPDetails


class TestIpinfoLookupMyIp:
    """ipinfo_lookup_my_ip() takes no arguments and returns a single IPDetails."""

    async def test_returns_single_details(self, mock_context_with_state):
        from mcp_server_ipinfo.server import ipinfo_lookup_my_ip

        result = await ipinfo_lookup_my_ip(ctx=mock_context_with_state)
        assert isinstance(result, IPDetails)
        # The conftest mock returns 203.0.113.1 for None ip_address.
        assert str(result.ip) == "203.0.113.1"

    async def test_caches_result(self, mock_context_with_state):
        from mcp_server_ipinfo.server import ipinfo_lookup_my_ip

        cache = mock_context_with_state.lifespan_context["cache"]
        await ipinfo_lookup_my_ip(ctx=mock_context_with_state)
        # The IP returned by the mock should now sit in the cache.
        cached = await cache.get("203.0.113.1")
        assert cached is not None


class TestIpinfoLookupIps:
    """ipinfo_lookup_ips returns a list and supports a `detail` toggle."""

    async def test_full_detail_default(self, mock_context_with_state):
        from mcp_server_ipinfo.server import ipinfo_lookup_ips

        results = await ipinfo_lookup_ips(ips=["8.8.8.8"], ctx=mock_context_with_state)
        assert len(results) == 1
        assert isinstance(results[0], IPDetails)
        assert results[0].city == "Mountain View"

    async def test_summary_detail_drops_heavy_blocks(
        self, mock_context_with_state, sample_ip_details
    ):
        """Summary mode nulls out the heavy nested blocks for token savings.

        The agent opts in by passing detail="summary"; shape parity is
        preserved (still IPDetails) so existing parsers don't break.
        """
        from mcp_server_ipinfo.server import ipinfo_lookup_ips

        cache = mock_context_with_state.lifespan_context["cache"]
        # Pre-seed cache with rich IPDetails containing the heavy fields.
        rich = sample_ip_details.model_copy(
            update={
                "continent": {"code": "NA", "name": "North America"},
                "country_flag": {"emoji": "🇺🇸", "unicode": "U+1F1FA U+1F1F8"},
                "country_currency": {"code": "USD", "symbol": "$"},
                "isEU": False,
            }
        )
        await cache.set("8.8.8.8", rich)

        full = await ipinfo_lookup_ips(
            ips=["8.8.8.8"], detail="full", ctx=mock_context_with_state
        )
        summary = await ipinfo_lookup_ips(
            ips=["8.8.8.8"], detail="summary", ctx=mock_context_with_state
        )

        # Full mode preserves the heavy blocks.
        assert full[0].continent is not None
        assert full[0].country_flag is not None
        # Summary mode nulls them out.
        assert summary[0].continent is None
        assert summary[0].country_flag is None
        assert summary[0].country_flag_url is None
        assert summary[0].country_currency is None
        # Core geolocation fields survive.
        assert summary[0].city == "Mountain View"
        assert summary[0].country == "US"


class TestRenamedTools:
    """The remaining two tools are renamed with the ipinfo_ prefix."""

    async def test_ipinfo_check_residential_proxy(self, mock_context_with_state):
        from mcp_server_ipinfo.server import ipinfo_check_residential_proxy

        result = await ipinfo_check_residential_proxy(
            ip="142.250.80.46", ctx=mock_context_with_state
        )
        assert str(result.ip) == "142.250.80.46"
        assert result.service == "Luminati"

    async def test_ipinfo_generate_map_url(self, mock_context_with_state):
        from unittest.mock import AsyncMock, MagicMock, patch

        from mcp_server_ipinfo.server import ipinfo_generate_map_url

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "reportUrl": "https://ipinfo.io/map/demo/xyz"
        }
        mock_response.raise_for_status = MagicMock()

        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            url = await ipinfo_generate_map_url(
                ips=["8.8.8.8", "1.1.1.1"], ctx=mock_context_with_state
            )
        assert url == "https://ipinfo.io/map/demo/xyz"


class TestDeprecatedGetIpDetails:
    """The original get_ip_details remains as a deprecated alias."""

    async def test_alias_still_callable(self, mock_context_with_state):
        from mcp_server_ipinfo.server import get_ip_details

        results = await get_ip_details(ips=["8.8.8.8"], ctx=mock_context_with_state)
        assert len(results) == 1
        assert str(results[0].ip) == "8.8.8.8"

    async def test_alias_my_ip_mode(self, mock_context_with_state):
        """get_ip_details(ips=None) preserves the legacy self-IP shortcut."""
        from mcp_server_ipinfo.server import get_ip_details

        results = await get_ip_details(ips=None, ctx=mock_context_with_state)
        assert len(results) == 1
        assert str(results[0].ip) == "203.0.113.1"

    async def test_no_valid_ips_envelope(self, mock_context_with_state):
        """The deprecated alias still emits structured envelopes on validation failures."""
        import json

        from mcp_server_ipinfo.server import get_ip_details

        with pytest.raises(ToolError) as excinfo:
            await get_ip_details(ips=["192.168.1.1"], ctx=mock_context_with_state)
        env = json.loads(str(excinfo.value))
        assert env["code"] == "no_valid_ips"
