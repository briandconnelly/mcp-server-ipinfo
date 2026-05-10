"""Tests for ResidentialProxyDetails derived fields and serialization."""

from mcp_server_ipinfo.models import ResidentialProxyDetails


class TestIsResidentialProxy:
    """A computed boolean lets agents branch without inspecting all-None fields."""

    def test_true_when_service_present(self):
        details = ResidentialProxyDetails(
            ip="142.250.80.46",
            last_seen="2024-01-15",
            percent_days_seen=85.7,
            service="Luminati",
        )
        assert details.is_residential_proxy is True

    def test_false_when_service_missing(self):
        """All-None fields signal 'not a known proxy'; the boolean makes that explicit."""
        details = ResidentialProxyDetails(ip="8.8.8.8")
        assert details.is_residential_proxy is False

    def test_false_when_only_service_missing(self):
        """Even with last_seen/percent_days_seen set, a missing service means not a known proxy."""
        details = ResidentialProxyDetails(
            ip="8.8.8.8",
            last_seen="2024-01-15",
            percent_days_seen=10.0,
            service=None,
        )
        assert details.is_residential_proxy is False

    def test_serialized_to_json(self):
        """The derived field appears in model_dump and JSON output (per user choice Q3)."""
        details = ResidentialProxyDetails(ip="142.250.80.46", service="Luminati")
        dump = details.model_dump()
        assert "is_residential_proxy" in dump
        assert dump["is_residential_proxy"] is True

        details_negative = ResidentialProxyDetails(ip="8.8.8.8")
        assert details_negative.model_dump()["is_residential_proxy"] is False

    def test_appears_in_serialization_schema(self):
        """The computed field shows up in the serialization schema (tool output side).

        Pydantic computed_fields are serialization-only by design (you can't
        construct from them). The ``mode="serialization"`` schema is what
        FastMCP uses for tool output_schema generation.
        """
        schema = ResidentialProxyDetails.model_json_schema(mode="serialization")
        assert "is_residential_proxy" in schema["properties"]
        assert schema["properties"]["is_residential_proxy"]["type"] == "boolean"
