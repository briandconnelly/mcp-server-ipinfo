"""Tests for the ipinfo://capabilities discovery resource and its fingerprint.

The resource gives clients that ignore the advisory `instructions` field a
structured capability summary, and the fingerprint lets a cached client detect
surface changes without re-walking every tool definition.
"""

import json
from typing import get_args

import fastmcp

from mcp_server_ipinfo.models import ToolErrorCode
from mcp_server_ipinfo.server import (
    ERROR_CODE_CATALOG,
    _compute_fingerprint,
    _surface_records,
    mcp,
)


async def _read_capabilities() -> dict:
    """Read and parse the capabilities resource through a real FastMCP client."""
    async with fastmcp.Client(mcp) as client:
        contents = await client.read_resource("ipinfo://capabilities")
    return json.loads(contents[0].text)


class TestCapabilitiesResource:
    async def test_resource_is_registered(self):
        async with fastmcp.Client(mcp) as client:
            uris = {str(r.uri) for r in await client.list_resources()}
        assert "ipinfo://capabilities" in uris

    async def test_reports_server_identity(self):
        payload = await _read_capabilities()
        assert payload["server"]["name"] == "IPInfo Geolocation"
        # Version tracks the installed package, not a hardcoded string.
        from importlib.metadata import version

        assert payload["server"]["version"] == version("mcp-server-ipinfo")

    async def test_carries_fingerprint(self):
        payload = await _read_capabilities()
        fingerprint = payload["fingerprint"]
        assert fingerprint.startswith("sha256:")
        # The label must match the value: a full 64-char SHA-256 hex digest,
        # not a truncated one (PR #73 review).
        digest = fingerprint.removeprefix("sha256:")
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    async def test_negative_scope_present(self):
        payload = await _read_capabilities()
        joined = " ".join(payload["negative_scope"]).lower()
        # The headline out-of-scope items must be visible as data, not prose.
        assert "dns" in joined
        assert "bgp" in joined or "cidr" in joined

    async def test_error_catalog_matches_literal(self):
        """Every ToolErrorCode is documented in the catalog and vice versa."""
        payload = await _read_capabilities()
        catalog_codes = set(payload["error_code_catalog"])
        literal_codes = set(get_args(ToolErrorCode))
        assert catalog_codes == literal_codes

    async def test_lists_every_tool_with_contract(self):
        payload = await _read_capabilities()
        names = {t["name"] for t in payload["tools"]}
        assert names == {
            "ipinfo_lookup_my_ip",
            "ipinfo_lookup_ips",
            "ipinfo_summarize_ips",
            "ipinfo_check_residential_proxy",
            "ipinfo_generate_map_url",
        }
        for tool in payload["tools"]:
            assert tool["title"]
            assert tool["introduced_in"]
            assert "invalid_ip_behavior" in tool

    async def test_limits_reflect_split_caps(self):
        payload = await _read_capabilities()
        assert payload["limits"]["max_detailed_lookup_ips"] == 1_000
        assert payload["limits"]["max_lookup_ips"] == 500_000


class TestFingerprint:
    async def test_deterministic(self):
        """Same surface -> identical fingerprint across calls."""
        records = await _surface_records()
        assert _compute_fingerprint(records) == _compute_fingerprint(records)

    async def test_changes_when_surface_changes(self):
        records = await _surface_records()
        baseline = _compute_fingerprint(records)
        mutated = [dict(records[0], error_codes=[*records[0]["error_codes"], "zzz"])]
        mutated += records[1:]
        assert _compute_fingerprint(mutated) != baseline

    async def test_independent_of_package_version(self):
        """The fingerprint covers the surface, not the version string.

        Two records sets that differ only in nothing version-related hash the
        same; the version lives in a separate payload field so a client can see
        'version moved but fingerprint identical'.
        """
        records = await _surface_records()
        payload = await _read_capabilities()
        # The fingerprint input does not include payload["server"]["version"].
        assert _compute_fingerprint(records) == payload["fingerprint"]


def test_error_catalog_keys_are_valid_codes():
    """Guard: catalog keys cannot drift from the ToolErrorCode literal."""
    assert set(ERROR_CODE_CATALOG) == set(get_args(ToolErrorCode))
