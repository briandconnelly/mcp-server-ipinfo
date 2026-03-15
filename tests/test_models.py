"""Tests for Pydantic models."""

import pytest
from pydantic import ValidationError

from mcp_server_ipinfo.models import (
    ASNInfo,
    ASNPrefix,
    IPDetails,
    IPRangesInfo,
    ResidentialProxyDetails,
)


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


class TestASNInfo:
    """Tests for ASNInfo model."""

    def test_valid_construction(self, sample_asn_info):
        """Test creating ASNInfo with all fields populated."""
        assert sample_asn_info.asn == "AS15169"
        assert sample_asn_info.name == "Google LLC"
        assert sample_asn_info.country == "US"
        assert sample_asn_info.allocated == "2000-03-30"
        assert sample_asn_info.registry == "arin"
        assert sample_asn_info.domain == "google.com"
        assert sample_asn_info.num_ips == 17574144
        assert sample_asn_info.type == "hosting"

    def test_optional_fields(self):
        """Test ASNInfo with only required field."""
        info = ASNInfo(asn="AS7922")
        assert info.asn == "AS7922"
        assert info.name is None
        assert info.country is None
        assert info.allocated is None
        assert info.registry is None
        assert info.domain is None
        assert info.num_ips is None
        assert info.type is None
        assert info.prefixes is None
        assert info.prefixes6 is None
        assert info.ts_retrieved is None

    def test_prefix_nesting(self, sample_asn_info):
        """Test that prefixes are properly nested as ASNPrefix objects."""
        assert len(sample_asn_info.prefixes) == 2
        assert sample_asn_info.prefixes[0].netblock == "8.8.4.0/24"
        assert sample_asn_info.prefixes[0].id == "AS15169"
        assert sample_asn_info.prefixes[0].name == "Google LLC"
        assert sample_asn_info.prefixes[0].country == "US"

        assert len(sample_asn_info.prefixes6) == 1
        assert sample_asn_info.prefixes6[0].netblock == "2001:4860::/32"

    def test_from_dict(self):
        """Test constructing ASNInfo from a dict (simulating API response)."""
        data = {
            "asn": "AS13335",
            "name": "Cloudflare, Inc.",
            "country": "US",
            "registry": "arin",
            "domain": "cloudflare.com",
            "num_ips": 1524736,
            "type": "hosting",
            "prefixes": [
                {
                    "netblock": "1.1.1.0/24",
                    "id": "AS13335",
                    "name": "Cloudflare, Inc.",
                    "country": "US",
                }
            ],
        }
        info = ASNInfo(**data)
        assert info.asn == "AS13335"
        assert len(info.prefixes) == 1
        assert info.prefixes[0].netblock == "1.1.1.0/24"


class TestIPRangesInfo:
    """Tests for IPRangesInfo model."""

    def test_valid_construction(self, sample_ip_ranges_info):
        """Test creating IPRangesInfo with all fields populated."""
        assert sample_ip_ranges_info.domain == "google.com"
        assert sample_ip_ranges_info.num_ranges == 3
        assert len(sample_ip_ranges_info.ranges) == 3
        assert "8.8.8.0/24" in sample_ip_ranges_info.ranges

    def test_optional_fields(self):
        """Test IPRangesInfo with only required field."""
        info = IPRangesInfo(domain="example.com")
        assert info.domain == "example.com"
        assert info.redirects_to is None
        assert info.num_ranges is None
        assert info.ranges is None
        assert info.ts_retrieved is None

    def test_with_redirect(self):
        """Test IPRangesInfo with redirect field."""
        info = IPRangesInfo(
            domain="www.google.com",
            redirects_to="google.com",
            num_ranges=0,
            ranges=[],
        )
        assert info.redirects_to == "google.com"
        assert info.num_ranges == 0
        assert info.ranges == []
