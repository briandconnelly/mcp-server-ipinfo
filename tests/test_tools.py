"""Tests for MCP tools."""

from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.exceptions import ToolError

from mcp_server_ipinfo.server import (
    _normalize_ip,
    _validate_ip,
    ipinfo_check_residential_proxy,
    ipinfo_generate_map_url,
    ipinfo_lookup_ips,
)


class TestValidateIP:
    """Tests for _validate_ip helper function."""

    @pytest.mark.parametrize(
        "ip",
        ["8.8.8.8", "1.1.1.1", "208.67.222.222"],
        ids=["google-dns", "cloudflare", "opendns"],
    )
    def test_valid_public_ipv4(self, ip):
        """Test valid public IPv4 addresses."""
        result = _validate_ip(ip)
        assert str(result) == ip

    @pytest.mark.parametrize(
        "ip",
        ["2001:4860:4860::8888", "2606:4700:4700::1111"],
        ids=["google-dns-v6", "cloudflare-v6"],
    )
    def test_valid_public_ipv6(self, ip):
        """Test valid public IPv6 addresses."""
        result = _validate_ip(ip)
        assert str(result) == ip

    @pytest.mark.parametrize("ip", ["not-an-ip", "999.999.999.999", "abc"])
    def test_invalid_ip(self, ip):
        """Test invalid IP address formats."""
        with pytest.raises(ToolError, match="not a valid IP address"):
            _validate_ip(ip)

    @pytest.mark.parametrize("ip", ["192.168.1.1", "10.0.0.1", "172.16.0.1"])
    def test_private_ipv4(self, ip):
        """Test private IPv4 addresses are rejected."""
        with pytest.raises(ToolError, match="private IP address"):
            _validate_ip(ip)

    @pytest.mark.parametrize("ip", ["127.0.0.1", "::1"])
    def test_loopback(self, ip):
        """Test loopback addresses are rejected."""
        with pytest.raises(ToolError, match="loopback IP address"):
            _validate_ip(ip)

    @pytest.mark.parametrize("ip", ["224.0.0.1", "ff02::1"])
    def test_multicast(self, ip):
        """Test multicast addresses are rejected."""
        with pytest.raises(ToolError, match="multicast IP address"):
            _validate_ip(ip)

    @pytest.mark.parametrize("ip", ["169.254.1.1", "fe80::1"])
    def test_link_local(self, ip):
        """Test link-local addresses are rejected."""
        with pytest.raises(ToolError, match="link-local IP address"):
            _validate_ip(ip)

    def test_reserved(self):
        """Test reserved addresses are rejected."""
        with pytest.raises(ToolError, match="reserved IP address"):
            _validate_ip("240.0.0.1")


class TestNormalizeIP:
    """Tests for _normalize_ip helper function."""

    @pytest.mark.parametrize(
        ("input_ip", "expected"),
        [
            ("8.8.8.8", "8.8.8.8"),
            ("  8.8.8.8  ", "8.8.8.8"),
            ("null", None),
            ("", None),
            ("undefined", None),
            ("0.0.0.0", None),
            ("::", None),
            ("  ", None),
            (" null ", None),
        ],
        ids=[
            "normal",
            "whitespace",
            "null",
            "empty",
            "undefined",
            "zero-v4",
            "zero-v6",
            "spaces-only",
            "padded-null",
        ],
    )
    def test_normalize(self, input_ip, expected):
        assert _normalize_ip(input_ip) == expected


class TestLookupIps:
    """Tests for ipinfo_lookup_ips tool (detail="full" to assert on model fields)."""

    async def test_lookup_single_ip(self, mock_context_with_state):
        """Test looking up a single IP."""
        results = await ipinfo_lookup_ips(
            ips=["8.8.8.8"], detail="full", ctx=mock_context_with_state
        )

        assert len(results) == 1
        assert str(results[0].ip) == "8.8.8.8"
        assert results[0].city == "Mountain View"

    async def test_lookup_multiple_ips(self, mock_context_with_state):
        """Test looking up multiple IPs."""
        ips = ["8.8.8.8", "1.1.1.1"]
        results = await ipinfo_lookup_ips(
            ips=ips, detail="full", ctx=mock_context_with_state
        )

        assert len(results) == 2
        result_ips = {str(r.ip) for r in results}
        assert result_ips == {"8.8.8.8", "1.1.1.1"}

    async def test_cache_hit(self, mock_context_with_state, sample_ip_details):
        """Test that cached results are returned."""
        cache = mock_context_with_state.lifespan_context["cache"]
        await cache.set("8.8.8.8", sample_ip_details)

        results = await ipinfo_lookup_ips(
            ips=["8.8.8.8"], detail="full", ctx=mock_context_with_state
        )

        assert len(results) == 1
        assert results[0] is sample_ip_details

    async def test_invalid_ip(self, mock_context_with_state):
        """Test that all invalid IPs raise ToolError."""
        with pytest.raises(ToolError, match="No valid IP addresses"):
            await ipinfo_lookup_ips(
                ips=["not-an-ip"], detail="full", ctx=mock_context_with_state
            )

    async def test_private_ip(self, mock_context_with_state):
        """Test that all private IPs raise ToolError."""
        with pytest.raises(ToolError, match="No valid IP addresses"):
            await ipinfo_lookup_ips(
                ips=["192.168.1.1"], detail="full", ctx=mock_context_with_state
            )

    async def test_mixed_valid_invalid_ips(self, mock_context_with_state):
        """Test batch skips invalid IPs with warnings."""
        ips = ["8.8.8.8", "192.168.1.1", "1.1.1.1"]
        results = await ipinfo_lookup_ips(
            ips=ips, detail="full", ctx=mock_context_with_state
        )

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
            await ipinfo_lookup_ips(ips=ips, detail="full", ctx=mock_context_with_state)

    async def test_with_cache(self, mock_context_with_state, sample_ip_details):
        """Test uses cache for known IPs."""
        cache = mock_context_with_state.lifespan_context["cache"]
        await cache.set("8.8.8.8", sample_ip_details)

        ips = ["8.8.8.8", "1.1.1.1"]
        results = await ipinfo_lookup_ips(
            ips=ips, detail="full", ctx=mock_context_with_state
        )

        assert len(results) == 2
        # 8.8.8.8 should be the cached version
        cached_result = next(r for r in results if str(r.ip) == "8.8.8.8")
        assert cached_result is sample_ip_details

    async def test_preserves_order(self, mock_context_with_state):
        """Test that results preserve input order where possible."""
        ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        results = await ipinfo_lookup_ips(
            ips=ips, detail="full", ctx=mock_context_with_state
        )

        result_ips = [str(r.ip) for r in results]
        assert result_ips == ips

    async def test_normalized_inputs(self, mock_context_with_state):
        """Test that placeholder values are filtered out."""
        # Only the valid IP should be looked up
        results = await ipinfo_lookup_ips(
            ips=["8.8.8.8", "", "null"], detail="full", ctx=mock_context_with_state
        )
        assert len(results) == 1
        assert str(results[0].ip) == "8.8.8.8"

    async def test_empty_list_after_normalization(self, mock_context_with_state):
        """Test error when all IPs normalize to None."""
        with pytest.raises(ToolError, match="No valid IP addresses"):
            await ipinfo_lookup_ips(
                ips=["", "null", "undefined"],
                detail="full",
                ctx=mock_context_with_state,
            )

    async def test_duplicate_ips_deduplicated(self, mock_context_with_state):
        """Test that duplicate IPs are deduplicated."""
        results = await ipinfo_lookup_ips(
            ips=["8.8.8.8", "8.8.8.8", "8.8.8.8"],
            detail="full",
            ctx=mock_context_with_state,
        )
        assert len(results) == 1
        assert str(results[0].ip) == "8.8.8.8"

    async def test_whitespace_stripped(self, mock_context_with_state):
        """Test that whitespace around IPs is stripped."""
        results = await ipinfo_lookup_ips(
            ips=[" 8.8.8.8 "], detail="full", ctx=mock_context_with_state
        )
        assert len(results) == 1
        assert str(results[0].ip) == "8.8.8.8"

    # Upstream-error → structured envelope coverage lives in test_error_dispatch.py.


class TestCheckResidentialProxy:
    """Tests for ipinfo_check_residential_proxy tool."""

    async def test_lookup(self, mock_context_with_state):
        """Test residential proxy lookup."""
        result = await ipinfo_check_residential_proxy(
            ip="142.250.80.46", ctx=mock_context_with_state
        )

        assert result is not None
        assert str(result.ip) == "142.250.80.46"
        assert result.service == "Luminati"
        assert result.percent_days_seen == 85.7

    async def test_invalid_ip(self, mock_context_with_state):
        """Test that invalid IPs raise ToolError."""
        with pytest.raises(ToolError, match="not a valid IP address"):
            await ipinfo_check_residential_proxy(
                ip="not-an-ip", ctx=mock_context_with_state
            )

    async def test_private_ip(self, mock_context_with_state):
        """Test that private IPs raise ToolError."""
        with pytest.raises(ToolError, match="private IP address"):
            await ipinfo_check_residential_proxy(
                ip="192.168.1.1", ctx=mock_context_with_state
            )


class TestGenerateMapUrl:
    """Tests for ipinfo_generate_map_url tool."""

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

    async def test_generate_map_url(self, mock_context_with_state, mock_httpx_response):
        """Test generating a map URL for valid IPs."""
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_httpx_response
            )

            result = await ipinfo_generate_map_url(
                ips=["8.8.8.8", "1.1.1.1"], ctx=mock_context_with_state
            )

            assert str(result.url) == "https://ipinfo.io/map/demo/abc123"
            mock_context_with_state.info.assert_called()

    async def test_filters_invalid_ips(
        self, mock_context_with_state, mock_httpx_response
    ):
        """Test that invalid IPs are filtered with warnings."""
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_post = AsyncMock(return_value=mock_httpx_response)
            mock_client.return_value.__aenter__.return_value.post = mock_post

            result = await ipinfo_generate_map_url(
                ips=["8.8.8.8", "192.168.1.1", "1.1.1.1"],
                ctx=mock_context_with_state,
            )

            assert str(result.url) == "https://ipinfo.io/map/demo/abc123"
            # Check that only valid IPs were sent
            call_args = mock_post.call_args
            sent_ips = call_args.kwargs.get("json") or call_args[1].get("json")
            assert "192.168.1.1" not in sent_ips
            assert len(sent_ips) == 2

            # Warning should be logged for skipped IP
            mock_context_with_state.warning.assert_called()

    async def test_all_invalid_ips_error(self, mock_context_with_state):
        """Test error when all IPs are invalid."""
        with pytest.raises(ToolError, match="No valid IP addresses"):
            await ipinfo_generate_map_url(
                ips=["192.168.1.1", "10.0.0.1"], ctx=mock_context_with_state
            )

    async def test_filters_placeholder_values(
        self, mock_context_with_state, mock_httpx_response
    ):
        """Test that placeholder values are filtered out."""
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_post = AsyncMock(return_value=mock_httpx_response)
            mock_client.return_value.__aenter__.return_value.post = mock_post

            result = await ipinfo_generate_map_url(
                ips=["8.8.8.8", "", "null", "undefined"],
                ctx=mock_context_with_state,
            )

            assert str(result.url) == "https://ipinfo.io/map/demo/abc123"
            call_args = mock_post.call_args
            sent_ips = call_args.kwargs.get("json") or call_args[1].get("json")
            assert sent_ips == ["8.8.8.8"]

    # API-error → structured envelope coverage lives in test_error_dispatch.py.

    async def test_too_many_ips_error(self, mock_context_with_state):
        """Test error when too many IPs are provided.

        The cap check fires before any per-IP work, so a repeated single-value
        list keeps the test cheap.
        """
        ips = ["1.1.1.1"] * 500_001
        with pytest.raises(ToolError, match="Too many IPs"):
            await ipinfo_generate_map_url(ips=ips, ctx=mock_context_with_state)
