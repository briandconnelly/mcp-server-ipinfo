"""The IPINFO_API_TOKEN should be read once at handler creation, not re-read on every call.

Reading the env var twice (once at handler init, once per map call) lets a
runtime env-mutation produce divergent behavior. Threading the token through
the handler resolves that.
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestTokenSourcedFromHandler:
    """``ipinfo_generate_map_url`` uses the handler's stored token, not os.environ."""

    @pytest.fixture
    def mock_httpx_response(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"reportUrl": "https://ipinfo.io/map/demo/x"}
        mock_response.raise_for_status = MagicMock()
        return mock_response

    async def test_handler_token_used_when_env_changes(
        self, mock_context_with_state, mock_httpx_response, monkeypatch
    ):
        """If the env mutates after handler init, the map call uses the handler's token.

        The mock_handler fixture has no real access_token; we assert the call
        flows through without re-reading os.environ for the token.
        """
        from mcp_server_ipinfo.server import ipinfo_generate_map_url

        # Set the handler's token via the fixture-provided mock.
        handler = mock_context_with_state.lifespan_context["ipinfo_handler"]
        handler.access_token = "handler-time-token"

        # Mutate the env after handler init. The map call must NOT pick this up.
        monkeypatch.setenv("IPINFO_API_TOKEN", "post-init-token-DO-NOT-USE")

        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_post = AsyncMock(return_value=mock_httpx_response)
            mock_client.return_value.__aenter__.return_value.post = mock_post
            await ipinfo_generate_map_url(ips=["8.8.8.8"], ctx=mock_context_with_state)

        # Inspect the Authorization header sent by httpx.
        sent_headers = mock_post.call_args.kwargs["headers"]
        assert sent_headers.get("Authorization") == "Bearer handler-time-token"

    async def test_no_authorization_header_when_handler_has_no_token(
        self, mock_context_with_state, mock_httpx_response, monkeypatch
    ):
        """Free-tier (no token at handler init) sends no Authorization, even if env now has one."""
        from mcp_server_ipinfo.server import ipinfo_generate_map_url

        handler = mock_context_with_state.lifespan_context["ipinfo_handler"]
        handler.access_token = None

        # An env mutation should not magically add a token.
        monkeypatch.setenv("IPINFO_API_TOKEN", "post-init-token-DO-NOT-USE")

        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_post = AsyncMock(return_value=mock_httpx_response)
            mock_client.return_value.__aenter__.return_value.post = mock_post
            await ipinfo_generate_map_url(ips=["8.8.8.8"], ctx=mock_context_with_state)

        sent_headers = mock_post.call_args.kwargs["headers"]
        assert "Authorization" not in sent_headers


class TestIpinfoGetMapUrlAcceptsToken:
    """ipinfo_get_map_url accepts a token argument so the env is read at most once."""

    async def test_passes_explicit_token_to_authorization(self, monkeypatch):
        from mcp_server_ipinfo.ipinfo import ipinfo_get_map_url

        # Wipe the env to prove the function uses the explicit argument.
        monkeypatch.delenv("IPINFO_API_TOKEN", raising=False)

        mock_response = MagicMock()
        mock_response.json.return_value = {"reportUrl": "https://ipinfo.io/map/demo/x"}
        mock_response.raise_for_status = MagicMock()

        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_post = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value.post = mock_post
            await ipinfo_get_map_url(["8.8.8.8"], token="explicit-arg-token")

        sent_headers = mock_post.call_args.kwargs["headers"]
        assert sent_headers["Authorization"] == "Bearer explicit-arg-token"

    async def test_no_token_means_no_authorization_header(self, monkeypatch):
        from mcp_server_ipinfo.ipinfo import ipinfo_get_map_url

        monkeypatch.setenv("IPINFO_API_TOKEN", "stale-env-value")

        mock_response = MagicMock()
        mock_response.json.return_value = {"reportUrl": "https://ipinfo.io/map/demo/x"}
        mock_response.raise_for_status = MagicMock()

        with patch("mcp_server_ipinfo.ipinfo.httpx.AsyncClient") as mock_client:
            mock_post = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value.post = mock_post
            await ipinfo_get_map_url(["8.8.8.8"], token=None)

        sent_headers = mock_post.call_args.kwargs["headers"]
        # Explicit token=None means no Authorization header — env is irrelevant.
        assert "Authorization" not in sent_headers
        # And we did NOT read os.environ for IPINFO_API_TOKEN at call time
        # (that's the M4 fix). Test passes by virtue of the env having a value
        # but no Authorization header being sent.
        assert os.environ.get("IPINFO_API_TOKEN") == "stale-env-value"
