"""Tests that tool errors carry a structured ToolErrorEnvelope payload.

Each tool maps known upstream exception types onto stable error codes that
agents can branch on without parsing prose.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.exceptions import ToolError
from ipinfo.error import APIError
from ipinfo.exceptions import RequestQuotaExceededError, TimeoutExceededError

from mcp_server_ipinfo.server import (
    get_ip_details,
    get_map_url,
    get_residential_proxy_info,
)


def parse_envelope(excinfo) -> dict:
    """Parse a ToolError message back into the structured envelope dict."""
    return json.loads(str(excinfo.value))


class TestValidationErrorCodes:
    """Validation failures raise ToolError with structured envelope codes."""

    async def test_invalid_ip_format(self, mock_context_with_state):
        with pytest.raises(ToolError) as excinfo:
            await get_residential_proxy_info(
                ip="not-an-ip", ctx=mock_context_with_state
            )
        env = parse_envelope(excinfo)
        assert env["code"] == "invalid_ip_address"
        assert env["temporary"] is False
        assert env["field"] == "ip"
        assert env["value"] == "not-an-ip"

    async def test_private_ip_code(self, mock_context_with_state):
        with pytest.raises(ToolError) as excinfo:
            await get_residential_proxy_info(
                ip="192.168.1.1", ctx=mock_context_with_state
            )
        env = parse_envelope(excinfo)
        assert env["code"] == "special_ip_unsupported"
        assert env["temporary"] is False
        assert env["field"] == "ip"
        # repair hint names the class of unsupported address
        assert "private" in env["message"].lower()

    async def test_no_valid_ips_code(self, mock_context_with_state):
        with pytest.raises(ToolError) as excinfo:
            await get_ip_details(
                ips=["192.168.1.1", "10.0.0.1"], ctx=mock_context_with_state
            )
        env = parse_envelope(excinfo)
        assert env["code"] == "no_valid_ips"
        assert env["temporary"] is False
        assert env["field"] == "ips"

    async def test_too_many_ips_code(self, mock_context_with_state):
        # Exceed the 500K cap to trigger the size guard.
        ips = [f"1.1.1.{i % 256}" for i in range(500_001)]
        with pytest.raises(ToolError) as excinfo:
            await get_map_url(ips=ips, ctx=mock_context_with_state)
        env = parse_envelope(excinfo)
        assert env["code"] == "too_many_ips"
        assert env["temporary"] is False
        assert env["field"] == "ips"


class TestUpstreamErrorCodes:
    """Upstream IPInfo exceptions map onto stable, agent-actionable codes."""

    async def test_api_401_to_auth_invalid(self, mock_context_with_state):
        # APIError with HTTP 401 means the supplied token is bad.
        with patch(
            "mcp_server_ipinfo.server.ipinfo_lookup",
            side_effect=APIError(401, {"error": {"message": "Wrong token"}}),
        ):
            with pytest.raises(ToolError) as excinfo:
                await get_ip_details(ips=["8.8.8.8"], ctx=mock_context_with_state)
        env = parse_envelope(excinfo)
        assert env["code"] == "auth_invalid"
        assert env["temporary"] is False
        # Repair should point the agent at IPINFO_API_TOKEN.
        assert "IPINFO_API_TOKEN" in (env["repair"] or {}).get("hint", "")

    async def test_api_403_to_insufficient_scope(self, mock_context_with_state):
        # 403 means the plan tier doesn't include the requested capability.
        with patch(
            "mcp_server_ipinfo.server.ipinfo_resproxy_lookup",
            side_effect=APIError(403, {"error": {"message": "Plan required"}}),
        ):
            with pytest.raises(ToolError) as excinfo:
                await get_residential_proxy_info(
                    ip="142.250.80.46", ctx=mock_context_with_state
                )
        env = parse_envelope(excinfo)
        assert env["code"] == "auth_insufficient_scope"
        assert env["temporary"] is False

    async def test_api_500_to_api_error(self, mock_context_with_state):
        with patch(
            "mcp_server_ipinfo.server.ipinfo_lookup",
            side_effect=APIError(500, {"error": {"message": "boom"}}),
        ):
            with pytest.raises(ToolError) as excinfo:
                await get_ip_details(ips=["8.8.8.8"], ctx=mock_context_with_state)
        env = parse_envelope(excinfo)
        assert env["code"] == "api_error"
        assert env["temporary"] is True

    async def test_quota_to_quota_exceeded(self, mock_context_with_state):
        with patch(
            "mcp_server_ipinfo.server.ipinfo_lookup",
            side_effect=RequestQuotaExceededError(),
        ):
            with pytest.raises(ToolError) as excinfo:
                await get_ip_details(ips=["8.8.8.8"], ctx=mock_context_with_state)
        env = parse_envelope(excinfo)
        assert env["code"] == "quota_exceeded"
        assert env["temporary"] is True

    async def test_timeout_to_timeout_code(self, mock_context_with_state):
        with patch(
            "mcp_server_ipinfo.server.ipinfo_lookup",
            side_effect=TimeoutExceededError(),
        ):
            with pytest.raises(ToolError) as excinfo:
                await get_ip_details(ips=["8.8.8.8"], ctx=mock_context_with_state)
        env = parse_envelope(excinfo)
        assert env["code"] == "timeout"
        assert env["temporary"] is True

    async def test_unknown_to_unknown_error(self, mock_context_with_state):
        # An unexpected exception type still produces a valid envelope.
        with patch(
            "mcp_server_ipinfo.server.ipinfo_lookup",
            side_effect=RuntimeError("???"),
        ):
            with pytest.raises(ToolError) as excinfo:
                await get_ip_details(ips=["8.8.8.8"], ctx=mock_context_with_state)
        env = parse_envelope(excinfo)
        assert env["code"] == "unknown_error"
        assert env["temporary"] is True

    async def test_batch_quota_to_quota_exceeded(self, mock_context_with_state):
        """Batch path also dispatches typed upstream errors."""
        with patch(
            "mcp_server_ipinfo.server.ipinfo_batch_lookup",
            side_effect=RequestQuotaExceededError(),
        ):
            with pytest.raises(ToolError) as excinfo:
                await get_ip_details(
                    ips=["8.8.8.8", "1.1.1.1"], ctx=mock_context_with_state
                )
        env = parse_envelope(excinfo)
        assert env["code"] == "quota_exceeded"
        assert env["temporary"] is True

    async def test_api_404_to_api_error_not_temporary(self, mock_context_with_state):
        """A 4xx that isn't 401/403 lands in api_error, marked non-temporary."""
        with patch(
            "mcp_server_ipinfo.server.ipinfo_lookup",
            side_effect=APIError(404, {"error": {"message": "missing"}}),
        ):
            with pytest.raises(ToolError) as excinfo:
                await get_ip_details(ips=["8.8.8.8"], ctx=mock_context_with_state)
        env = parse_envelope(excinfo)
        assert env["code"] == "api_error"
        assert env["temporary"] is False

    async def test_my_ip_path_dispatches_upstream(self, mock_context_with_state):
        """ipinfo_lookup_my_ip routes through the same upstream classifier."""
        from mcp_server_ipinfo.server import ipinfo_lookup_my_ip

        with patch(
            "mcp_server_ipinfo.server.ipinfo_lookup",
            side_effect=RequestQuotaExceededError(),
        ):
            with pytest.raises(ToolError) as excinfo:
                await ipinfo_lookup_my_ip(ctx=mock_context_with_state)
        env = parse_envelope(excinfo)
        assert env["code"] == "quota_exceeded"
        assert env["temporary"] is True

    async def test_map_api_failure_envelope(self, mock_context_with_state):
        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=RuntimeError("network down")
            )
            with pytest.raises(ToolError) as excinfo:
                await get_map_url(ips=["8.8.8.8"], ctx=mock_context_with_state)
        env = parse_envelope(excinfo)
        # Map errors come from httpx, not the ipinfo library — they land in
        # the generic api_error/unknown bucket but must still be structured.
        assert env["code"] in {"api_error", "unknown_error"}
        assert "message" in env
