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


def _contract(tool) -> dict:
    """Extract a tool's namespaced convention contract block from its meta."""
    from mcp_server_ipinfo.server import CONTRACT_NS

    return (tool.meta or {}).get(CONTRACT_NS, {})


class TestNewToolSchemas:
    """Constraints that agents need to see in the schema."""

    async def test_lookup_ips_caps_array_length(self, registered_tools):
        tool = registered_tools["ipinfo_lookup_ips"]
        ips_schema = tool.parameters["properties"]["ips"]
        assert ips_schema["minItems"] == 1
        # Per-record tool is capped tighter than the aggregate/map tools so a
        # large batch cannot blow the context window.
        assert ips_schema["maxItems"] == 1_000

    async def test_lookup_ips_detail_is_enum(self, registered_tools):
        tool = registered_tools["ipinfo_lookup_ips"]
        detail_schema = tool.parameters["properties"]["detail"]
        # Literal["summary","full"] should expose an enum constraint.
        assert set(detail_schema.get("enum", [])) == {"summary", "full"}
        # Token-lean default: summary (heavy nested blocks omitted).
        assert detail_schema.get("default") == "summary"

    async def test_lookup_ips_items_carry_ip_format_hint(self, registered_tools):
        tool = registered_tools["ipinfo_lookup_ips"]
        items = tool.parameters["properties"]["ips"]["items"]
        # Soft, non-enforcing schema hint so agents see the expected shape.
        assert items.get("format") == "ip"
        assert items.get("type") == "string"

    async def test_generate_map_url_caps_array_length(self, registered_tools):
        tool = registered_tools["ipinfo_generate_map_url"]
        ips_schema = tool.parameters["properties"]["ips"]
        assert ips_schema["minItems"] == 1
        assert ips_schema["maxItems"] == 500_000

    async def test_summarize_ips_caps_array_length(self, registered_tools):
        tool = registered_tools["ipinfo_summarize_ips"]
        ips_schema = tool.parameters["properties"]["ips"]
        assert ips_schema["minItems"] == 1
        assert ips_schema["maxItems"] == 500_000

    async def test_summarize_ips_group_by_is_enum_array(self, registered_tools):
        tool = registered_tools["ipinfo_summarize_ips"]
        group_schema = tool.parameters["properties"]["group_by"]
        assert group_schema["maxItems"] == 4
        assert set(group_schema["items"].get("enum", [])) == {
            "country",
            "continent",
            "asn",
            "privacy",
        }
        assert group_schema.get("default") == ["country", "asn"]

    async def test_summarize_ips_top_n_has_bounds(self, registered_tools):
        tool = registered_tools["ipinfo_summarize_ips"]
        top_n_schema = tool.parameters["properties"]["top_n"]
        assert top_n_schema["minimum"] == 1
        assert top_n_schema["maximum"] == 500
        assert top_n_schema["default"] == 50

    async def test_my_ip_takes_no_args(self, registered_tools):
        tool = registered_tools["ipinfo_lookup_my_ip"]
        # Only the implicit Context parameter remains; no required args.
        assert tool.parameters.get("required", []) == []


class TestRemovedAliases:
    """The 0.5.0 forwarding aliases were removed in 0.6.0 and must stay gone.

    Guards the removal contract: an accidental reintroduction of any legacy
    name would otherwise pass silently, since every other contract test only
    asserts the surviving tools by positive lookup.
    """

    @pytest.mark.parametrize(
        "name",
        ["get_ip_details", "get_residential_proxy_info", "get_map_url"],
    )
    async def test_alias_absent_from_registry(self, registered_tools, name):
        assert name not in registered_tools


class TestToolContract:
    """Agent-facing contract metadata: error codes, idempotency hints."""

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("ipinfo_lookup_my_ip", {"auth_invalid", "timeout", "api_error"}),
            (
                "ipinfo_lookup_ips",
                {
                    "no_valid_ips",
                    "too_many_ips",
                    "quota_exceeded",
                },
            ),
            (
                "ipinfo_summarize_ips",
                {
                    "no_valid_ips",
                    "too_many_ips",
                    "quota_exceeded",
                },
            ),
            (
                "ipinfo_check_residential_proxy",
                {"invalid_ip_address", "auth_insufficient_scope"},
            ),
            ("ipinfo_generate_map_url", {"no_valid_ips", "timeout"}),
        ],
    )
    async def test_tools_advertise_error_codes(self, registered_tools, name, expected):
        """Each tool's contract error_codes lets agents see the branch set up front."""
        tool = registered_tools[name]
        codes = set(_contract(tool).get("error_codes", []))
        assert expected <= codes, f"{name} missing {expected - codes}"

    async def test_my_ip_omits_input_only_error_codes(self, registered_tools):
        """my_ip takes no input, so input-validation codes must not appear."""
        codes = set(_contract(registered_tools["ipinfo_lookup_my_ip"])["error_codes"])
        assert "invalid_ip_address" not in codes
        assert "too_many_ips" not in codes

    @pytest.mark.parametrize(
        "name",
        ["ipinfo_lookup_ips", "ipinfo_summarize_ips", "ipinfo_generate_map_url"],
    )
    async def test_list_tools_omit_per_item_input_codes(self, registered_tools, name):
        """List tools demote per-item invalid/special IPs to the skipped list
        rather than raising, so those codes must not be advertised as raiseable."""
        codes = set(_contract(registered_tools[name])["error_codes"])
        assert "invalid_ip_address" not in codes
        assert "special_ip_unsupported" not in codes

    @pytest.mark.parametrize(
        "name",
        [
            "ipinfo_lookup_my_ip",
            "ipinfo_lookup_ips",
            "ipinfo_summarize_ips",
            "ipinfo_check_residential_proxy",
            "ipinfo_generate_map_url",
        ],
    )
    async def test_readonly_tools_are_idempotent(self, registered_tools, name):
        """Read-only lookups are safe to retry; advertise idempotentHint."""
        ann = registered_tools[name].annotations
        assert ann is not None
        assert ann.idempotentHint is True
        assert ann.readOnlyHint is True


class TestNewToolMetadata:
    """New tools carry an introduced_in marker so version diffs are visible."""

    @pytest.mark.parametrize(
        "name",
        [
            "ipinfo_lookup_my_ip",
            "ipinfo_lookup_ips",
            "ipinfo_summarize_ips",
            "ipinfo_check_residential_proxy",
            "ipinfo_generate_map_url",
        ],
    )
    async def test_introduced_in_meta(self, registered_tools, name):
        tool = registered_tools[name]
        assert tool.meta is not None
        expected = "0.6.0" if name == "ipinfo_summarize_ips" else "0.5.0"
        assert _contract(tool).get("introduced_in") == expected

    async def test_residential_proxy_marked_enterprise(self, registered_tools):
        tool = registered_tools["ipinfo_check_residential_proxy"]
        assert "enterprise" in (tool.tags or set())
        assert _contract(tool).get("plan_required") == "residential_proxy_addon"

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("ipinfo_lookup_my_ip", "not_applicable"),
            ("ipinfo_lookup_ips", "skip_per_item"),
            ("ipinfo_summarize_ips", "skip_per_item"),
            ("ipinfo_generate_map_url", "skip_per_item"),
            ("ipinfo_check_residential_proxy", "raise"),
        ],
    )
    async def test_invalid_ip_behavior_declared(self, registered_tools, name, expected):
        """Agents can see whether bad IPs are skipped per-item or raised."""
        assert _contract(registered_tools[name]).get("invalid_ip_behavior") == expected

    @pytest.mark.parametrize(
        ("name", "title"),
        [
            ("ipinfo_lookup_my_ip", "Look Up My IP"),
            ("ipinfo_lookup_ips", "Look Up IPs"),
            ("ipinfo_summarize_ips", "Summarize IPs"),
            ("ipinfo_check_residential_proxy", "Check Residential Proxy"),
            ("ipinfo_generate_map_url", "Generate IP Map URL"),
        ],
    )
    async def test_tools_carry_display_title(self, registered_tools, name, title):
        """Each tool exposes a human-facing title for capability pickers."""
        assert registered_tools[name].annotations.title == title
