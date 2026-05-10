"""Tests that the FastMCP-generated tool schemas carry our constraints.

We rely on FastMCP to translate Pydantic Field(min_length=..., max_length=...)
into JSON Schema minItems/maxItems on tool input schemas. These tests guard
against regressions in that translation and confirm our metadata survives.
"""

import pytest


@pytest.fixture
async def registered_tools():
    """Resolve the live tool registry from the FastMCP server, keyed by name."""
    from mcp_server_ipinfo.server import mcp

    tools = await mcp.list_tools()
    return {tool.name: tool for tool in tools}


class TestNewToolSchemas:
    """Constraints that agents need to see in the schema."""

    async def test_lookup_ips_caps_array_length(self, registered_tools):
        tool = registered_tools["ipinfo_lookup_ips"]
        ips_schema = tool.parameters["properties"]["ips"]
        assert ips_schema["minItems"] == 1
        assert ips_schema["maxItems"] == 500_000

    async def test_lookup_ips_detail_is_enum(self, registered_tools):
        tool = registered_tools["ipinfo_lookup_ips"]
        detail_schema = tool.parameters["properties"]["detail"]
        # Literal["summary","full"] should expose an enum constraint.
        assert set(detail_schema.get("enum", [])) == {"summary", "full"}
        assert detail_schema.get("default") == "full"

    async def test_generate_map_url_caps_array_length(self, registered_tools):
        tool = registered_tools["ipinfo_generate_map_url"]
        ips_schema = tool.parameters["properties"]["ips"]
        assert ips_schema["minItems"] == 1
        assert ips_schema["maxItems"] == 500_000

    async def test_my_ip_takes_no_args(self, registered_tools):
        tool = registered_tools["ipinfo_lookup_my_ip"]
        # Only the implicit Context parameter remains; no required args.
        assert tool.parameters.get("required", []) == []


class TestDeprecationMetadata:
    """Deprecated aliases carry tags + meta so cached clients can detect them."""

    @pytest.mark.parametrize(
        ("name", "replacement"),
        [
            ("get_ip_details", "ipinfo_lookup_ips"),
            ("get_residential_proxy_info", "ipinfo_check_residential_proxy"),
            ("get_map_url", "ipinfo_generate_map_url"),
        ],
    )
    async def test_alias_marked_deprecated(self, registered_tools, name, replacement):
        tool = registered_tools[name]
        assert "deprecated" in (tool.tags or set())
        assert tool.meta is not None
        assert tool.meta.get("deprecated_since") == "0.5.0"
        assert tool.meta.get("replaced_by") == replacement


class TestNewToolMetadata:
    """New tools carry an introduced_in marker so version diffs are visible."""

    @pytest.mark.parametrize(
        "name",
        [
            "ipinfo_lookup_my_ip",
            "ipinfo_lookup_ips",
            "ipinfo_check_residential_proxy",
            "ipinfo_generate_map_url",
        ],
    )
    async def test_introduced_in_meta(self, registered_tools, name):
        tool = registered_tools[name]
        assert tool.meta is not None
        assert tool.meta.get("introduced_in") == "0.5.0"

    async def test_residential_proxy_marked_enterprise(self, registered_tools):
        tool = registered_tools["ipinfo_check_residential_proxy"]
        assert "enterprise" in (tool.tags or set())
        assert tool.meta.get("plan_required") == "residential_proxy_addon"
