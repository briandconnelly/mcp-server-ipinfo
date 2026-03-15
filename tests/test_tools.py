"""Tests for MCP tools."""

from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.exceptions import ToolError

from mcp_server_ipinfo.server import (
    _normalize_asn,
    _normalize_ip,
    _validate_domain,
    _validate_ip,
    get_asn_details as get_asn_details_tool,
    get_ip_details as get_ip_details_tool,
    get_ip_ranges as get_ip_ranges_tool,
    get_map_url as get_map_url_tool,
    get_residential_proxy_info as get_residential_proxy_info_tool,
)

# Access underlying functions from FunctionTool wrappers
get_asn_details = get_asn_details_tool.fn
get_ip_details = get_ip_details_tool.fn
get_ip_ranges = get_ip_ranges_tool.fn
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


class TestNormalizeASN:
    """Tests for _normalize_asn helper function."""

    def test_uppercase_prefix(self):
        """Test 'AS7922' format."""
        assert _normalize_asn("AS7922") == "AS7922"

    def test_lowercase_prefix(self):
        """Test 'as7922' format."""
        assert _normalize_asn("as7922") == "AS7922"

    def test_number_only(self):
        """Test '7922' format (no prefix)."""
        assert _normalize_asn("7922") == "AS7922"

    def test_with_whitespace(self):
        """Test input with surrounding whitespace."""
        assert _normalize_asn("  AS15169  ") == "AS15169"

    def test_invalid_non_numeric(self):
        """Test invalid ASN with non-numeric characters."""
        with pytest.raises(ToolError, match="not a valid ASN"):
            _normalize_asn("ASabc")

    def test_invalid_empty(self):
        """Test invalid empty ASN."""
        with pytest.raises(ToolError, match="not a valid ASN"):
            _normalize_asn("AS")

    def test_invalid_garbage(self):
        """Test completely invalid input."""
        with pytest.raises(ToolError, match="not a valid ASN"):
            _normalize_asn("not-an-asn")


class TestValidateDomain:
    """Tests for _validate_domain helper function."""

    def test_valid_domain(self):
        """Test a valid domain."""
        assert _validate_domain("google.com") == "google.com"

    def test_valid_subdomain(self):
        """Test a valid subdomain."""
        assert _validate_domain("www.google.com") == "www.google.com"

    def test_uppercase_normalized(self):
        """Test that domains are lowercased."""
        assert _validate_domain("Google.COM") == "google.com"

    def test_with_whitespace(self):
        """Test that whitespace is stripped."""
        assert _validate_domain("  google.com  ") == "google.com"

    def test_no_dot(self):
        """Test domain without a dot."""
        with pytest.raises(ToolError, match="not appear to be a valid domain"):
            _validate_domain("localhost")

    def test_empty(self):
        """Test empty domain."""
        with pytest.raises(ToolError, match="must not be empty"):
            _validate_domain("")

    def test_invalid_characters(self):
        """Test domain with invalid characters."""
        with pytest.raises(ToolError, match="not appear to be a valid domain"):
            _validate_domain("goo gle.com")


class TestGetASNDetails:
    """Tests for get_asn_details tool."""

    @pytest.fixture
    def mock_asn_response(self):
        """Create a mock httpx response for ASN lookup."""
        from unittest.mock import MagicMock

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "asn": "AS15169",
            "name": "Google LLC",
            "country": "US",
            "allocated": "2000-03-30",
            "registry": "arin",
            "domain": "google.com",
            "num_ips": 17574144,
            "type": "hosting",
            "prefixes": [
                {
                    "netblock": "8.8.8.0/24",
                    "id": "AS15169",
                    "name": "Google LLC",
                    "country": "US",
                }
            ],
            "prefixes6": [
                {
                    "netblock": "2001:4860::/32",
                    "id": "AS15169",
                    "name": "Google LLC",
                    "country": "US",
                }
            ],
        }
        mock_response.raise_for_status = MagicMock()
        return mock_response

    async def test_valid_asn_lookup(self, mock_context, mock_asn_response):
        """Test looking up a valid ASN."""
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_asn_response
            )

            result = await get_asn_details(asn="AS15169", ctx=mock_context)

            assert result.asn == "AS15169"
            assert result.name == "Google LLC"
            assert result.country == "US"
            assert len(result.prefixes) == 1
            assert result.prefixes[0].netblock == "8.8.8.0/24"
            assert len(result.prefixes6) == 1

    async def test_lowercase_asn_input(self, mock_context, mock_asn_response):
        """Test that lowercase ASN input is normalized."""
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_get = AsyncMock(return_value=mock_asn_response)
            mock_client.return_value.__aenter__.return_value.get = mock_get

            await get_asn_details(asn="as15169", ctx=mock_context)

            # Verify the URL used the normalized ASN
            call_args = mock_get.call_args
            assert "AS15169" in call_args[0][0]

    async def test_number_only_input(self, mock_context, mock_asn_response):
        """Test that number-only ASN input is normalized."""
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_get = AsyncMock(return_value=mock_asn_response)
            mock_client.return_value.__aenter__.return_value.get = mock_get

            await get_asn_details(asn="15169", ctx=mock_context)

            call_args = mock_get.call_args
            assert "AS15169" in call_args[0][0]

    async def test_invalid_asn(self, mock_context):
        """Test that invalid ASN raises ToolError."""
        with pytest.raises(ToolError, match="not a valid ASN"):
            await get_asn_details(asn="not-an-asn", ctx=mock_context)

    async def test_api_error_handling(self, mock_context):
        """Test handling of API errors."""
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_get = AsyncMock(side_effect=Exception("API error"))
            mock_client.return_value.__aenter__.return_value.get = mock_get

            with pytest.raises(ToolError, match="ASN lookup failed"):
                await get_asn_details(asn="AS15169", ctx=mock_context)


class TestGetIPRanges:
    """Tests for get_ip_ranges tool."""

    @pytest.fixture
    def mock_ranges_response(self):
        """Create a mock httpx response for IP ranges lookup."""
        from unittest.mock import MagicMock

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "domain": "google.com",
            "num_ranges": 3,
            "ranges": [
                "8.8.4.0/24",
                "8.8.8.0/24",
                "8.34.208.0/20",
            ],
        }
        mock_response.raise_for_status = MagicMock()
        return mock_response

    async def test_valid_domain_lookup(self, mock_context, mock_ranges_response):
        """Test looking up IP ranges for a valid domain."""
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_ranges_response
            )

            result = await get_ip_ranges(domain="google.com", ctx=mock_context)

            assert result.domain == "google.com"
            assert result.num_ranges == 3
            assert len(result.ranges) == 3
            assert "8.8.8.0/24" in result.ranges

    async def test_invalid_domain(self, mock_context):
        """Test that invalid domain raises ToolError."""
        with pytest.raises(ToolError, match="not appear to be a valid domain"):
            await get_ip_ranges(domain="not-a-domain", ctx=mock_context)

    async def test_empty_domain(self, mock_context):
        """Test that empty domain raises ToolError."""
        with pytest.raises(ToolError, match="must not be empty"):
            await get_ip_ranges(domain="", ctx=mock_context)

    async def test_api_error_handling(self, mock_context):
        """Test handling of API errors."""
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_get = AsyncMock(side_effect=Exception("API error"))
            mock_client.return_value.__aenter__.return_value.get = mock_get

            with pytest.raises(ToolError, match="IP ranges lookup failed"):
                await get_ip_ranges(domain="google.com", ctx=mock_context)
