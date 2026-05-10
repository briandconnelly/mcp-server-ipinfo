"""Tests for Pydantic models."""

import pytest
from pydantic import ValidationError

from mcp_server_ipinfo.ipinfo import _flatten_nested_response
from mcp_server_ipinfo.models import IPDetails, ResidentialProxyDetails


class TestIPDetails:
    """Tests for IPDetails model."""

    def test_valid_ipv4(self):
        """Test creating IPDetails with valid IPv4."""
        details = IPDetails(ip="8.8.8.8")
        assert str(details.ip) == "8.8.8.8"

    def test_valid_ipv6(self):
        """Test creating IPDetails with valid IPv6."""
        details = IPDetails(ip="2001:4860:4860::8888")
        assert str(details.ip) == "2001:4860:4860::8888"

    def test_full_details(self, sample_ip_details):
        """Test IPDetails with all fields populated."""
        assert str(sample_ip_details.ip) == "8.8.8.8"
        assert sample_ip_details.city == "Mountain View"
        assert sample_ip_details.country == "US"
        assert sample_ip_details.isEU is False
        assert sample_ip_details.timezone == "America/Los_Angeles"

    def test_optional_fields_none(self):
        """Test IPDetails with optional fields as None."""
        details = IPDetails(ip="1.1.1.1")
        assert details.hostname is None
        assert details.city is None
        assert details.asn is None
        assert details.privacy is None

    def test_invalid_country_code(self):
        """Test that invalid country codes are rejected."""
        with pytest.raises(ValidationError):
            IPDetails(ip="8.8.8.8", country="USA")  # Should be 2 letters

    def test_valid_country_code(self):
        """Test that valid country codes are accepted."""
        details = IPDetails(ip="8.8.8.8", country="US")
        assert details.country == "US"

    def test_latitude_bounds(self):
        """Test latitude validation bounds."""
        # Valid latitudes
        IPDetails(ip="8.8.8.8", latitude=0)
        IPDetails(ip="8.8.8.8", latitude=90)
        IPDetails(ip="8.8.8.8", latitude=-90)

        # Invalid latitudes
        with pytest.raises(ValidationError):
            IPDetails(ip="8.8.8.8", latitude=91)
        with pytest.raises(ValidationError):
            IPDetails(ip="8.8.8.8", latitude=-91)

    def test_longitude_bounds(self):
        """Test longitude validation bounds."""
        # Valid longitudes
        IPDetails(ip="8.8.8.8", longitude=0)
        IPDetails(ip="8.8.8.8", longitude=180)
        IPDetails(ip="8.8.8.8", longitude=-180)

        # Invalid longitudes
        with pytest.raises(ValidationError):
            IPDetails(ip="8.8.8.8", longitude=181)
        with pytest.raises(ValidationError):
            IPDetails(ip="8.8.8.8", longitude=-181)

    def test_asn_details(self):
        """Test ASN as typed model."""
        details = IPDetails(
            ip="8.8.8.8",
            asn={
                "asn": "AS15169",
                "name": "Google LLC",
                "domain": "google.com",
                "route": "8.8.8.0/24",
                "type": "hosting",
            },
        )
        assert details.asn.asn == "AS15169"
        assert details.asn.name == "Google LLC"
        assert details.asn.domain == "google.com"
        assert details.asn.route == "8.8.8.0/24"
        assert details.asn.type == "hosting"

    def test_privacy_details(self):
        """Test privacy detection as typed model."""
        details = IPDetails(
            ip="8.8.8.8",
            privacy={
                "vpn": True,
                "proxy": False,
                "tor": False,
                "relay": False,
                "hosting": True,
                "service": "NordVPN",
            },
        )
        assert details.privacy.vpn is True
        assert details.privacy.proxy is False
        assert details.privacy.tor is False
        assert details.privacy.relay is False
        assert details.privacy.hosting is True
        assert details.privacy.service == "NordVPN"


class TestResidentialProxyDetails:
    """Tests for ResidentialProxyDetails model."""

    def test_valid_details(self, sample_residential_proxy_details):
        """Test creating ResidentialProxyDetails with valid data."""
        assert str(sample_residential_proxy_details.ip) == "142.250.80.46"
        assert sample_residential_proxy_details.last_seen == "2024-01-15"
        assert sample_residential_proxy_details.percent_days_seen == 85.7
        assert sample_residential_proxy_details.service == "Luminati"

    def test_minimal_details(self):
        """Test ResidentialProxyDetails with only required fields."""
        details = ResidentialProxyDetails(ip="1.2.3.4")
        assert str(details.ip) == "1.2.3.4"
        assert details.last_seen is None
        assert details.service is None

    def test_optional_fields(self):
        """Test all optional fields can be None."""
        details = ResidentialProxyDetails(
            ip="1.2.3.4",
            last_seen=None,
            percent_days_seen=None,
            service=None,
            ts_retrieved=None,
        )
        assert details.last_seen is None
        assert details.percent_days_seen is None
        assert details.service is None


class TestFlattenNestedResponse:
    """Tests for the Core/Plus -> flat IPDetails adapter."""

    def test_flat_response_unchanged(self):
        """Standard endpoint responses (already flat) pass through with no changes."""
        flat = {
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "country": "US",
            "country_name": "United States",
            "org": "AS15169 Google LLC",
        }
        assert _flatten_nested_response(flat) == flat

    def test_geo_block_promoted_to_top_level(self):
        """Core-style nested geo block is flattened so IPDetails sees top-level fields."""
        nested = {
            "ip": "8.8.8.8",
            "geo": {
                "city": "Mountain View",
                "region": "California",
                "region_code": "CA",
                "country": "United States",
                "country_code": "US",
                "loc": "37.3860,-122.0838",
                "postal": "94035",
                "timezone": "America/Los_Angeles",
            },
        }
        flat = _flatten_nested_response(nested)

        assert "geo" not in flat
        assert flat["city"] == "Mountain View"
        assert flat["region"] == "California"
        assert flat["region_code"] == "CA"
        assert flat["country"] == "US"
        assert flat["country_name"] == "United States"
        assert flat["loc"] == "37.3860,-122.0838"
        assert flat["postal"] == "94035"
        assert flat["timezone"] == "America/Los_Angeles"

    def test_as_block_renamed_to_asn(self):
        """The 'as' key (a Python keyword) is renamed to 'asn' for IPDetails."""
        nested = {
            "ip": "8.8.8.8",
            "as": {
                "asn": "AS15169",
                "name": "Google LLC",
                "domain": "google.com",
                "type": "hosting",
            },
        }
        flat = _flatten_nested_response(nested)

        assert "as" not in flat
        assert flat["asn"]["asn"] == "AS15169"
        assert flat["asn"]["name"] == "Google LLC"

    def test_top_level_wins_over_nested(self):
        """If a top-level key is already set, the geo block does not overwrite it."""
        nested = {
            "ip": "8.8.8.8",
            "city": "Top-level Wins",
            "geo": {"city": "Should Be Ignored", "country_code": "US"},
        }
        flat = _flatten_nested_response(nested)
        assert flat["city"] == "Top-level Wins"
        assert flat["country"] == "US"

    def test_existing_asn_not_overwritten(self):
        """If both 'as' and 'asn' are present, existing 'asn' wins."""
        nested = {
            "ip": "8.8.8.8",
            "asn": {"asn": "AS-EXISTING"},
            "as": {"asn": "AS-NESTED"},
        }
        flat = _flatten_nested_response(nested)
        assert flat["asn"]["asn"] == "AS-EXISTING"
        assert "as" not in flat

    def test_geo_country_is_full_name_when_country_code_missing(self):
        """Per Core/Plus convention, geo.country is the full country name; without
        country_code we still map it to country_name (never to top-level country,
        which would fail IPDetails' alpha-2 regex)."""
        nested = {
            "ip": "8.8.8.8",
            "geo": {"city": "Mountain View", "country": "United States"},
        }
        flat = _flatten_nested_response(nested)
        assert flat["country_name"] == "United States"
        assert "country" not in flat

    def test_ipdetails_constructs_from_core_shape(self):
        """End-to-end: a Core-shaped response yields a valid IPDetails."""
        nested = {
            "ip": "8.8.8.8",
            "geo": {
                "city": "Mountain View",
                "region": "California",
                "region_code": "CA",
                "country": "United States",
                "country_code": "US",
                "loc": "37.3860,-122.0838",
            },
            "as": {
                "asn": "AS15169",
                "name": "Google LLC",
                "domain": "google.com",
                "type": "hosting",
            },
        }
        details = IPDetails(**_flatten_nested_response(nested))
        assert str(details.ip) == "8.8.8.8"
        assert details.city == "Mountain View"
        assert details.country == "US"
        assert details.country_name == "United States"
        assert details.region_code == "CA"
        assert details.asn is not None
        assert details.asn.asn == "AS15169"
        assert details.asn.name == "Google LLC"
