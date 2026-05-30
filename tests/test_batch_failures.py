"""Tests for batch-lookup failure surfacing and the structured error contract.

The real ipinfo SDK returns freshly fetched batch entries as raw ``dict``s (it
does ``result.update(json_resp)``), not ``Details`` objects. A ``Details``-only
filter silently dropped every fresh result (bug B0); on top of that, IPs the
upstream dropped were invisible to the caller (A11). These tests pin the
raw-dict parsing, the partial-failure accounting, progress reporting, and the
populated ``request_id`` on error envelopes.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp.exceptions import ToolError

from mcp_server_ipinfo.ipinfo import ipinfo_batch_lookup
from mcp_server_ipinfo.models import IPDetails


class TestBatchLookupParsing:
    """ipinfo_batch_lookup accepts both SDK shapes and reports failures."""

    async def test_parses_raw_dict_entries(self):
        """Fresh batch entries arrive as raw dicts and must still parse (B0)."""
        handler = MagicMock()
        handler.getBatchDetails = AsyncMock(
            return_value={
                "8.8.8.8": {"ip": "8.8.8.8", "country": "US", "city": "Mountain View"},
                "1.1.1.1": {"ip": "1.1.1.1", "country": "AU", "city": "Sydney"},
            }
        )
        results, failed = await ipinfo_batch_lookup(handler, ["8.8.8.8", "1.1.1.1"])
        assert set(results) == {"8.8.8.8", "1.1.1.1"}
        assert all(isinstance(v, IPDetails) for v in results.values())
        assert failed == {}

    async def test_parses_details_objects_too(self):
        """Cache/bogon entries arrive as Details objects (have .all)."""
        handler = MagicMock()
        det = MagicMock()
        det.all = {"ip": "8.8.8.8", "country": "US"}
        handler.getBatchDetails = AsyncMock(return_value={"8.8.8.8": det})
        results, failed = await ipinfo_batch_lookup(handler, ["8.8.8.8"])
        assert "8.8.8.8" in results
        assert failed == {}

    async def test_missing_ip_recorded_as_failed(self):
        """An IP the upstream drops entirely lands in `failed`, not silently gone."""
        handler = MagicMock()
        handler.getBatchDetails = AsyncMock(
            return_value={"8.8.8.8": {"ip": "8.8.8.8", "country": "US"}}
        )
        results, failed = await ipinfo_batch_lookup(handler, ["8.8.8.8", "9.9.9.9"])
        assert "8.8.8.8" in results
        assert "9.9.9.9" in failed
        assert "no result" in failed["9.9.9.9"]

    async def test_unparseable_entry_recorded_as_failed(self):
        """A payload missing required fields is a per-IP failure, not a crash."""
        handler = MagicMock()
        handler.getBatchDetails = AsyncMock(
            return_value={"8.8.8.8": {"error": "nope"}}  # no ip -> validation fails
        )
        results, failed = await ipinfo_batch_lookup(handler, ["8.8.8.8"])
        assert results == {}
        assert "8.8.8.8" in failed

    async def test_every_input_is_accounted_for(self):
        """results + failed together cover the whole input (no silent shrinkage)."""
        handler = MagicMock()
        handler.getBatchDetails = AsyncMock(
            return_value={"1.2.3.4": {"ip": "1.2.3.4", "country": "US"}}
        )
        ips = ["1.2.3.4", "5.6.7.8", "9.10.11.12"]
        results, failed = await ipinfo_batch_lookup(handler, ips)
        assert set(results) | set(failed) == set(ips)


class TestLookupIpsFailureSurfacing:
    """ipinfo_lookup_ips logs dropped IPs and refuses to mask a total failure."""

    async def test_partial_failure_warns_and_drops(self, mock_context_with_state):
        from mcp_server_ipinfo.server import ipinfo_lookup_ips

        handler = mock_context_with_state.lifespan_context["ipinfo_handler"]

        async def partial(ip_addresses, raise_on_fail=True):
            ip = ip_addresses[0]
            return {ip: {"ip": ip, "country": "US", "city": "MV"}}

        handler.getBatchDetails = partial

        results = await ipinfo_lookup_ips(
            ips=["8.8.8.8", "9.9.9.9"], detail="full", ctx=mock_context_with_state
        )
        assert {str(r.ip) for r in results} == {"8.8.8.8"}
        warnings = " ".join(
            c.args[0] for c in mock_context_with_state.warning.call_args_list
        )
        assert "9.9.9.9" in warnings

    async def test_total_failure_raises_temporary(self, mock_context_with_state):
        from mcp_server_ipinfo.server import ipinfo_lookup_ips

        handler = mock_context_with_state.lifespan_context["ipinfo_handler"]

        async def empty(ip_addresses, raise_on_fail=True):
            return {}

        handler.getBatchDetails = empty

        with pytest.raises(ToolError) as exc:
            await ipinfo_lookup_ips(
                ips=["8.8.8.8", "9.9.9.9"], ctx=mock_context_with_state
            )
        env = json.loads(str(exc.value))
        assert env["code"] == "api_error"
        assert env["temporary"] is True
        assert env["repair"]["failed_count"] == 2

    async def test_progress_is_reported(self, mock_context_with_state):
        """Long batches emit progress (no-op without a client progress token)."""
        from mcp_server_ipinfo.server import ipinfo_lookup_ips

        await ipinfo_lookup_ips(
            ips=["8.8.8.8", "1.1.1.1"], detail="full", ctx=mock_context_with_state
        )
        assert mock_context_with_state.report_progress.await_count >= 1


class TestErrorEnvelopeRequestId:
    """Every raised envelope carries a populated correlation id (A5)."""

    async def test_request_id_populated(self, mock_context_with_state):
        from mcp_server_ipinfo.server import ipinfo_lookup_ips

        with pytest.raises(ToolError) as exc:
            await ipinfo_lookup_ips(ips=["192.168.1.1"], ctx=mock_context_with_state)
        env = json.loads(str(exc.value))
        assert env["code"] == "no_valid_ips"
        assert env["request_id"]  # non-null, non-empty
        assert len(env["request_id"]) == 32  # uuid4().hex

    async def test_request_ids_are_unique(self, mock_context_with_state):
        from mcp_server_ipinfo.server import ipinfo_lookup_ips

        ids = set()
        for _ in range(3):
            with pytest.raises(ToolError) as exc:
                await ipinfo_lookup_ips(ips=["not-an-ip"], ctx=mock_context_with_state)
            ids.add(json.loads(str(exc.value))["request_id"])
        assert len(ids) == 3
