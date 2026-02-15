"""Tests for MCP tools."""

from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.exceptions import ToolError

from mcp_server_ipinfo.server import (
    _normalize_ip,
    _validate_ip,
    get_ip_details as get_ip_details_tool,
    get_map_url as get_map_url_tool,
    get_residential_proxy_info as get_residential_proxy_info_tool,
)

# Access underlying functions from FunctionTool wrappers
get_ip_details = get_ip_details_tool.fn
get_map_url = get_map_url_tool.fn
get_residential_proxy_info = get_residential_proxy_info_tool.fn


class TestValidateIP:
    """Tests for _validate_ip helper function."""

    def test_valid_public_ipv4(self):
        """Test valid public IPv4 addresses."""
        result = _validate_ip("8.8.8.8")
        assert str(result) == "8.8.8.8"

    def test_valid_public_ipv6(self):
        """Test valid public IPv6 addresses."""
        result = _validate_ip("2001:4860:4860::8888")
        assert str(result) == "2001:4860:4860::8888"

    def test_invalid_ip(self):
        """Test invalid IP address format."""
        with pytest.raises(ToolError, match="not a valid IP address"):
            _validate_ip("not-an-ip")

    def test_private_ipv4(self):
        """Test private IPv4 addresses are rejected."""
        with pytest.raises(ToolError, match="private IP address"):
            _validate_ip("192.168.1.1")

        with pytest.raises(ToolError, match="private IP address"):
            _validate_ip("10.0.0.1")

        with pytest.raises(ToolError, match="private IP address"):
            _validate_ip("172.16.0.1")

    def test_loopback_ipv4(self):
        """Test loopback addresses are rejected."""
        with pytest.raises(ToolError, match="loopback IP address"):
            _validate_ip("127.0.0.1")

    def test_loopback_ipv6(self):
        """Test IPv6 loopback is rejected."""
        with pytest.raises(ToolError, match="loopback IP address"):
            _validate_ip("::1")

    def test_multicast(self):
        """Test multicast addresses are rejected."""
        with pytest.raises(ToolError, match="multicast IP address"):
            _validate_ip("224.0.0.1")

    def test_reserved(self):
        """Test reserved addresses are rejected."""
        with pytest.raises(ToolError, match="reserved IP address"):
            _validate_ip("240.0.0.1")


class TestNormalizeIP:
    """Tests for _normalize_ip helper function."""

    def test_normal_ip(self):
        """Test normal IP passes through."""
        assert _normalize_ip("8.8.8.8") == "8.8.8.8"

    def test_null_string(self):
        """Test 'null' is normalized to None."""
        assert _normalize_ip("null") is None

    def test_empty_string(self):
        """Test empty string is normalized to None."""
        assert _normalize_ip("") is None

    def test_undefined(self):
        """Test 'undefined' is normalized to None."""
        assert _normalize_ip("undefined") is None

    def test_zero_ipv4(self):
        """Test 0.0.0.0 is normalized to None."""
        assert _normalize_ip("0.0.0.0") is None

    def test_zero_ipv6(self):
        """Test :: is normalized to None."""
        assert _normalize_ip("::") is None


class TestGetIPDetails:
    """Tests for get_ip_details tool."""

    async def test_lookup_single_ip(self, mock_context_with_state):
        """Test looking up a single IP."""
        results = await get_ip_details(ips=["8.8.8.8"], ctx=mock_context_with_state)

        assert len(results) == 1
        assert str(results[0].ip) == "8.8.8.8"
        assert results[0].city == "Mountain View"

    async def test_lookup_multiple_ips(self, mock_context_with_state):
        """Test looking up multiple IPs."""
        ips = ["8.8.8.8", "1.1.1.1"]
        results = await get_ip_details(ips=ips, ctx=mock_context_with_state)

        assert len(results) == 2
        result_ips = {str(r.ip) for r in results}
        assert result_ips == {"8.8.8.8", "1.1.1.1"}

    async def test_lookup_client_ip(self, mock_context_with_state):
        """Test looking up client's own IP (None)."""
        results = await get_ip_details(ips=None, ctx=mock_context_with_state)

        assert len(results) == 1
        # Mock returns 203.0.113.1 for None
        assert str(results[0].ip) == "203.0.113.1"

    async def test_cache_hit(self, mock_context_with_state, sample_ip_details):
        """Test that cached results are returned."""
        cache = mock_context_with_state.lifespan_context["cache"]
        await cache.set("8.8.8.8", sample_ip_details)

        results = await get_ip_details(ips=["8.8.8.8"], ctx=mock_context_with_state)

        assert len(results) == 1
        assert results[0] is sample_ip_details

    async def test_invalid_ip(self, mock_context_with_state):
        """Test that all invalid IPs raise ToolError."""
        with pytest.raises(ToolError, match="No valid IP addresses"):
            await get_ip_details(ips=["not-an-ip"], ctx=mock_context_with_state)

    async def test_private_ip(self, mock_context_with_state):
        """Test that all private IPs raise ToolError."""
        with pytest.raises(ToolError, match="No valid IP addresses"):
            await get_ip_details(ips=["192.168.1.1"], ctx=mock_context_with_state)

    async def test_mixed_valid_invalid_ips(self, mock_context_with_state):
        """Test batch skips invalid IPs with warnings."""
        ips = ["8.8.8.8", "192.168.1.1", "1.1.1.1"]
        results = await get_ip_details(ips=ips, ctx=mock_context_with_state)

        # Only public IPs should be returned
        assert len(results) == 2
        result_ips = {str(r.ip) for r in results}
        assert "192.168.1.1" not in result_ips

        # Warning should be logged
        mock_context_with_state.warning.assert_called()

    async def test_all_invalid_ips(self, mock_context_with_state):
        """Test batch with all invalid IPs raises error."""
        ips = ["192.168.1.1", "10.0.0.1", "127.0.0.1"]

        with pytest.raises(ToolError, match="No valid IP addresses"):
            await get_ip_details(ips=ips, ctx=mock_context_with_state)

    async def test_with_cache(self, mock_context_with_state, sample_ip_details):
        """Test uses cache for known IPs."""
        cache = mock_context_with_state.lifespan_context["cache"]
        await cache.set("8.8.8.8", sample_ip_details)

        ips = ["8.8.8.8", "1.1.1.1"]
        results = await get_ip_details(ips=ips, ctx=mock_context_with_state)

        assert len(results) == 2
        # 8.8.8.8 should be the cached version
        cached_result = next(r for r in results if str(r.ip) == "8.8.8.8")
        assert cached_result is sample_ip_details

    async def test_preserves_order(self, mock_context_with_state):
        """Test that results preserve input order where possible."""
        ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        results = await get_ip_details(ips=ips, ctx=mock_context_with_state)

        result_ips = [str(r.ip) for r in results]
        assert result_ips == ips

    async def test_normalized_inputs(self, mock_context_with_state):
        """Test that placeholder values are filtered out."""
        # Only the valid IP should be looked up
        results = await get_ip_details(
            ips=["8.8.8.8", "", "null"], ctx=mock_context_with_state
        )
        assert len(results) == 1
        assert str(results[0].ip) == "8.8.8.8"

    async def test_empty_list_after_normalization(self, mock_context_with_state):
        """Test error when all IPs normalize to None."""
        with pytest.raises(ToolError, match="No valid IP addresses"):
            await get_ip_details(
                ips=["", "null", "undefined"], ctx=mock_context_with_state
            )


class TestGetResidentialProxyInfo:
    """Tests for get_residential_proxy_info tool."""

    async def test_lookup(self, mock_context_with_state):
        """Test residential proxy lookup."""
        result = await get_residential_proxy_info(
            ip="142.250.80.46", ctx=mock_context_with_state
        )

        assert result is not None
        assert str(result.ip) == "142.250.80.46"
        assert result.service == "Luminati"
        assert result.percent_days_seen == 85.7

    async def test_invalid_ip(self, mock_context_with_state):
        """Test that invalid IPs raise ToolError."""
        with pytest.raises(ToolError, match="not a valid IP address"):
            await get_residential_proxy_info(
                ip="not-an-ip", ctx=mock_context_with_state
            )

    async def test_private_ip(self, mock_context_with_state):
        """Test that private IPs raise ToolError."""
        with pytest.raises(ToolError, match="private IP address"):
            await get_residential_proxy_info(
                ip="192.168.1.1", ctx=mock_context_with_state
            )


class TestGetMapUrl:
    """Tests for get_map_url tool."""

    @pytest.fixture
    def mock_httpx_response(self):
        """Create a mock httpx response."""
        from unittest.mock import MagicMock

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "reportUrl": "https://ipinfo.io/map/demo/abc123"
        }
        mock_response.raise_for_status = MagicMock()
        return mock_response

    async def test_generate_map_url(self, mock_context, mock_httpx_response):
        """Test generating a map URL for valid IPs."""
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_httpx_response
            )

            url = await get_map_url(ips=["8.8.8.8", "1.1.1.1"], ctx=mock_context)

            assert url == "https://ipinfo.io/map/demo/abc123"
            mock_context.info.assert_called()

    async def test_filters_invalid_ips(self, mock_context, mock_httpx_response):
        """Test that invalid IPs are filtered with warnings."""
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_post = AsyncMock(return_value=mock_httpx_response)
            mock_client.return_value.__aenter__.return_value.post = mock_post

            url = await get_map_url(
                ips=["8.8.8.8", "192.168.1.1", "1.1.1.1"], ctx=mock_context
            )

            assert url == "https://ipinfo.io/map/demo/abc123"
            # Check that only valid IPs were sent
            call_args = mock_post.call_args
            sent_ips = call_args.kwargs.get("json") or call_args[1].get("json")
            assert "192.168.1.1" not in sent_ips
            assert len(sent_ips) == 2

            # Warning should be logged for skipped IP
            mock_context.warning.assert_called()

    async def test_all_invalid_ips_error(self, mock_context):
        """Test error when all IPs are invalid."""
        with pytest.raises(ToolError, match="No valid IP addresses"):
            await get_map_url(ips=["192.168.1.1", "10.0.0.1"], ctx=mock_context)

    async def test_filters_placeholder_values(self, mock_context, mock_httpx_response):
        """Test that placeholder values are filtered out."""
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_post = AsyncMock(return_value=mock_httpx_response)
            mock_client.return_value.__aenter__.return_value.post = mock_post

            url = await get_map_url(
                ips=["8.8.8.8", "", "null", "undefined"], ctx=mock_context
            )

            assert url == "https://ipinfo.io/map/demo/abc123"
            call_args = mock_post.call_args
            sent_ips = call_args.kwargs.get("json") or call_args[1].get("json")
            assert sent_ips == ["8.8.8.8"]

    async def test_api_error_handling(self, mock_context):
        """Test handling of API errors."""
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_post = AsyncMock(side_effect=Exception("API error"))
            mock_client.return_value.__aenter__.return_value.post = mock_post

            with pytest.raises(ToolError, match="Map generation failed"):
                await get_map_url(ips=["8.8.8.8"], ctx=mock_context)
