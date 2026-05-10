"""Tests for the structured MapResult response shape (introduced in 0.5.x).

`ipinfo_generate_map_url` now returns a typed MapResult with the URL, the
count that made the map, the list of IPs filtered out, and a truncated flag.
The deprecated `get_map_url` alias keeps the bare `str` return shape for
0.4.x cached-client parity.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastmcp.exceptions import ToolError

from mcp_server_ipinfo.models import MapResult, SkippedIP


def parse_envelope(excinfo) -> dict:
    import json

    return json.loads(str(excinfo.value))


@pytest.fixture
def mock_httpx_response():
    """A successful map-API response."""
    mock_response = MagicMock()
    mock_response.json.return_value = {"reportUrl": "https://ipinfo.io/map/demo/abc123"}
    mock_response.raise_for_status = MagicMock()
    return mock_response


class TestMapResultModel:
    """The MapResult model carries everything an agent needs to act on."""

    def test_required_fields(self):
        result = MapResult(
            url="https://ipinfo.io/map/demo/x",
            mapped_ip_count=2,
            skipped_ips=[],
            skipped_count=0,
            truncated=False,
        )
        assert result.mapped_ip_count == 2
        assert result.truncated is False
        assert str(result.url) == "https://ipinfo.io/map/demo/x"

    def test_skipped_entry_shape(self):
        entry = SkippedIP(ip="192.168.1.1", reason="private IP address")
        assert entry.ip == "192.168.1.1"
        assert "private" in entry.reason

    def test_truncation_flag(self):
        many = [SkippedIP(ip=f"10.0.0.{i}", reason="private") for i in range(100)]
        result = MapResult(
            url="https://ipinfo.io/map/demo/x",
            mapped_ip_count=5,
            skipped_ips=many,
            skipped_count=250,  # actual total exceeded the 100 cap
            truncated=True,
        )
        assert result.truncated is True
        assert len(result.skipped_ips) == 100
        assert result.skipped_count == 250


class TestIpinfoGenerateMapUrlReturnsStructured:
    """ipinfo_generate_map_url returns a MapResult, not a bare URL string."""

    async def test_returns_map_result(
        self, mock_context_with_state, mock_httpx_response
    ):
        from mcp_server_ipinfo.server import ipinfo_generate_map_url

        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_httpx_response
            )
            result = await ipinfo_generate_map_url(
                ips=["8.8.8.8", "1.1.1.1"], ctx=mock_context_with_state
            )

        assert isinstance(result, MapResult)
        assert str(result.url) == "https://ipinfo.io/map/demo/abc123"
        assert result.mapped_ip_count == 2
        assert result.skipped_ips == []
        assert result.skipped_count == 0
        assert result.truncated is False

    async def test_skipped_ips_recorded(
        self, mock_context_with_state, mock_httpx_response
    ):
        """Invalid IPs surface as structured SkippedIP entries with readable reasons."""
        from mcp_server_ipinfo.server import ipinfo_generate_map_url

        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_httpx_response
            )
            result = await ipinfo_generate_map_url(
                ips=["8.8.8.8", "192.168.1.1", "10.0.0.1", "1.1.1.1"],
                ctx=mock_context_with_state,
            )

        assert result.mapped_ip_count == 2
        assert result.skipped_count == 2
        assert {entry.ip for entry in result.skipped_ips} == {"192.168.1.1", "10.0.0.1"}
        for entry in result.skipped_ips:
            assert "private" in entry.reason.lower()
        assert result.truncated is False

    async def test_skipped_list_caps_at_100(
        self, mock_context_with_state, mock_httpx_response
    ):
        """When more than 100 IPs are skipped, the list truncates and the flag fires.

        skipped_count must reflect the *actual* total even when the list is capped.
        """
        from mcp_server_ipinfo.server import ipinfo_generate_map_url

        # 150 private + 1 public IP. All 150 should be filtered, but only 100
        # should appear in the SkippedIP list.
        ips = [f"10.0.{i // 256}.{i % 256}" for i in range(150)] + ["8.8.8.8"]
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_httpx_response
            )
            result = await ipinfo_generate_map_url(ips=ips, ctx=mock_context_with_state)

        assert result.mapped_ip_count == 1
        assert result.skipped_count == 150
        assert len(result.skipped_ips) == 100
        assert result.truncated is True


class TestDeprecatedGetMapUrlPreservesStringReturn:
    """The deprecated get_map_url alias keeps the 0.4.x bare-URL return shape."""

    async def test_alias_returns_string(
        self, mock_context_with_state, mock_httpx_response
    ):
        from mcp_server_ipinfo.server import get_map_url

        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_httpx_response
            )
            url = await get_map_url(ips=["8.8.8.8"], ctx=mock_context_with_state)

        assert isinstance(url, str)
        assert url == "https://ipinfo.io/map/demo/abc123"


class TestHttpxErrorClassification:
    """httpx exceptions from the map call route through the structured envelope."""

    async def test_timeout_to_timeout_code(self, mock_context_with_state):
        from mcp_server_ipinfo.server import ipinfo_generate_map_url

        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=httpx.TimeoutException("upstream slow")
            )
            with pytest.raises(ToolError) as excinfo:
                await ipinfo_generate_map_url(
                    ips=["8.8.8.8"], ctx=mock_context_with_state
                )

        env = parse_envelope(excinfo)
        assert env["code"] == "timeout"
        assert env["temporary"] is True

    async def test_http_500_to_temporary_api_error(self, mock_context_with_state):
        from mcp_server_ipinfo.server import ipinfo_generate_map_url

        # raise_for_status raises HTTPStatusError on 500.
        bad_response = MagicMock()
        bad_response.status_code = 500
        bad_response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "Server error",
                request=MagicMock(),
                response=MagicMock(status_code=500),
            )
        )
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=bad_response
            )
            with pytest.raises(ToolError) as excinfo:
                await ipinfo_generate_map_url(
                    ips=["8.8.8.8"], ctx=mock_context_with_state
                )

        env = parse_envelope(excinfo)
        assert env["code"] == "api_error"
        assert env["temporary"] is True

    @pytest.mark.parametrize(
        ("status_code", "expected_code", "expected_temporary"),
        [
            (401, "auth_invalid", False),
            (403, "auth_insufficient_scope", False),
            (429, "quota_exceeded", True),
        ],
        ids=["401", "403", "429"],
    )
    async def test_http_status_dispatch(
        self,
        mock_context_with_state,
        status_code,
        expected_code,
        expected_temporary,
    ):
        """Map-endpoint status codes route to the same envelope codes as the SDK exceptions."""
        from mcp_server_ipinfo.server import ipinfo_generate_map_url

        bad_response = MagicMock()
        bad_response.status_code = status_code
        bad_response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                f"HTTP {status_code}",
                request=MagicMock(),
                response=MagicMock(status_code=status_code),
            )
        )
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=bad_response
            )
            with pytest.raises(ToolError) as excinfo:
                await ipinfo_generate_map_url(
                    ips=["8.8.8.8"], ctx=mock_context_with_state
                )

        env = parse_envelope(excinfo)
        assert env["code"] == expected_code
        assert env["temporary"] is expected_temporary

    async def test_http_404_to_non_temporary_api_error(self, mock_context_with_state):
        from mcp_server_ipinfo.server import ipinfo_generate_map_url

        bad_response = MagicMock()
        bad_response.status_code = 404
        bad_response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "Not found",
                request=MagicMock(),
                response=MagicMock(status_code=404),
            )
        )
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=bad_response
            )
            with pytest.raises(ToolError) as excinfo:
                await ipinfo_generate_map_url(
                    ips=["8.8.8.8"], ctx=mock_context_with_state
                )

        env = parse_envelope(excinfo)
        assert env["code"] == "api_error"
        assert env["temporary"] is False


class TestHttpxClientTimeout:
    """The httpx.AsyncClient is constructed with an explicit timeout."""

    async def test_async_client_passes_timeout(
        self, mock_context_with_state, mock_httpx_response
    ):
        from mcp_server_ipinfo.server import ipinfo_generate_map_url

        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_httpx_response
            )
            await ipinfo_generate_map_url(ips=["8.8.8.8"], ctx=mock_context_with_state)

        # AsyncClient must be called with a non-None timeout argument.
        kwargs = mock_client.call_args.kwargs
        assert "timeout" in kwargs
        assert kwargs["timeout"] is not None
