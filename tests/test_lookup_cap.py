"""ipinfo_lookup_ips caps per-record output and routes overflow to aggregates.

The per-record tool returns one IPDetails per IP, so a huge batch would blow the
context window. It is capped tighter than the aggregate/map tools and raises a
structured too_many_ips that points the agent at the right alternative.
"""

import json

import pytest
from fastmcp.exceptions import ToolError

from mcp_server_ipinfo.server import MAX_DETAILED_LOOKUP_IPS, ipinfo_lookup_ips


async def test_over_cap_raises_too_many_ips(mock_context_with_state):
    # The cap check runs on len(ips) before validation, so placeholder strings
    # are fine here — we are exercising the boundary, not the lookup.
    oversized = ["8.8.8.8"] * (MAX_DETAILED_LOOKUP_IPS + 1)

    with pytest.raises(ToolError) as excinfo:
        await ipinfo_lookup_ips(ips=oversized, ctx=mock_context_with_state)

    envelope = json.loads(str(excinfo.value))
    assert envelope["code"] == "too_many_ips"
    assert envelope["temporary"] is False
    assert envelope["repair"]["limit"] == MAX_DETAILED_LOOKUP_IPS
    # The repair hint must name real callable alternatives.
    assert envelope["repair"]["alternatives"] == [
        "ipinfo_summarize_ips",
        "ipinfo_generate_map_url",
    ]


async def test_at_cap_is_allowed(mock_context_with_state):
    """Exactly at the cap is fine (boundary is strictly greater-than)."""
    at_cap = ["8.8.8.8"] * MAX_DETAILED_LOOKUP_IPS
    # All duplicates collapse to one resolved record; the point is no raise.
    results = await ipinfo_lookup_ips(ips=at_cap, ctx=mock_context_with_state)
    assert len(results) == 1
