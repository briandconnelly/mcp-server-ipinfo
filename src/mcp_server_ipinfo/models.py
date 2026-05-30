from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, StringConstraints, computed_field
from pydantic.networks import HttpUrl, IPvAnyAddress


ToolErrorCode = Literal[
    "invalid_ip_address",
    "special_ip_unsupported",
    "no_valid_ips",
    "too_many_ips",
    "auth_invalid",
    "auth_insufficient_scope",
    "quota_exceeded",
    "timeout",
    "api_error",
    "unknown_error",
]


class ToolErrorEnvelope(BaseModel):
    """Structured error envelope serialized into a ToolError message string.

    The envelope gives agents stable symbolic codes, a repair hint, and
    retry guidance instead of an opaque prose-only error. JSON-encoded into
    a ``ToolError`` so that the wire-level ``isError: true`` still applies
    while the message body remains parseable.
    """

    code: ToolErrorCode
    """Stable symbolic identifier for branching on the error."""

    message: str
    """Human-readable summary; safe to surface to end users."""

    temporary: bool
    """True if the agent should retry after a delay; False if the call will keep failing."""

    field: str | None = None
    """Name of the offending input field, when applicable."""

    value: Any = None
    """Offending value (redact in repair hint if sensitive)."""

    retry_after_ms: int | None = None
    """Milliseconds the agent should wait before retrying, when temporary=True."""

    repair: dict[str, Any] | None = None
    """Free-form repair guidance: hint text, alternative tool, allowed values."""

    request_id: str | None = None
    """Server-generated correlation ID (hex) for this error occurrence.

    Populated on every raised envelope so an agent can cite a stable identifier
    when reporting a failure; the same ID is intended to appear in server logs
    for the request. Not an upstream IPInfo request ID."""


class ASNDetails(BaseModel):
    """
    Autonomous System Number (ASN) information.

    Available in: IPinfo Core, IPinfo Plus, IPinfo Enterprise
    """

    asn: str | None = None
    """The ASN identifier (e.g., 'AS15169')"""

    name: str | None = None
    """The organization name (e.g., 'Google LLC')"""

    domain: str | None = None
    """The primary domain of the organization"""

    route: str | None = None
    """The IP route/prefix (e.g., '8.8.8.0/24')"""

    type: str | None = None
    """Organization type: 'isp', 'hosting', 'business', 'education', or 'government'"""


class PrivacyDetails(BaseModel):
    """
    Privacy and anonymity detection information.

    Identifies whether an IP is using VPN, proxy, Tor, relay services,
    or belongs to a hosting/cloud provider.

    Available in: IPinfo Core, IPinfo Plus, IPinfo Enterprise
    """

    vpn: bool | None = None
    """Whether the IP is a VPN exit node"""

    proxy: bool | None = None
    """Whether the IP is an open web proxy"""

    tor: bool | None = None
    """Whether the IP is a Tor exit node"""

    relay: bool | None = None
    """Whether the IP is an anonymous relay (e.g., iCloud Private Relay)"""

    hosting: bool | None = None
    """Whether the IP belongs to a hosting provider, cloud service, or data center"""

    service: str | None = None
    """Name of the detected VPN/proxy service (e.g., 'NordVPN', 'ExpressVPN')"""


class CarrierDetails(BaseModel):
    """
    Mobile carrier/operator information for cellular IPs.

    Available in: IPinfo Plus, IPinfo Enterprise
    """

    name: str | None = None
    """The name of the mobile carrier (e.g., 'Verizon Wireless')"""

    mcc: str | None = None
    """Mobile Country Code - identifies the country of the carrier"""

    mnc: str | None = None
    """Mobile Network Code - identifies the specific carrier within the country"""


class CompanyDetails(BaseModel):
    """
    Company/organization information for the IP owner.

    Available in: IPinfo Plus, IPinfo Enterprise
    """

    name: str | None = None
    """The company name"""

    domain: str | None = None
    """The company's primary domain"""

    type: str | None = None
    """Company type: 'isp', 'hosting', 'business', 'education', or 'government'"""


class DomainsDetails(BaseModel):
    """
    Hosted domains (reverse IP) information.

    Shows domains hosted on this IP address.

    Available in: IPinfo Enterprise
    """

    ip: str | None = None
    """The IP address"""

    total: int | None = None
    """Total number of domains hosted on this IP"""

    domains: list[str] | None = None
    """List of domain names hosted on this IP (up to 5 in standard response)"""


class AbuseDetails(BaseModel):
    """
    Abuse contact information for reporting malicious activity.

    Available in: IPinfo Enterprise
    """

    address: str | None = None
    """Physical address of the abuse contact"""

    country: str | None = None
    """Country of the abuse contact (ISO 3166-1 alpha-2)"""

    email: str | None = None
    """Email address for abuse reports"""

    name: str | None = None
    """Name of the abuse contact or organization"""

    network: str | None = None
    """Network range covered by this abuse contact"""

    phone: str | None = None
    """Phone number for abuse reports"""


class ContinentDetails(BaseModel):
    """Continent information."""

    code: str | None = None
    """Two-letter continent code (e.g., 'NA', 'EU', 'AS', 'AF', 'OC', 'SA', 'AN')"""

    name: str | None = None
    """Full continent name (e.g., 'North America', 'Europe', 'Asia')"""


class CountryFlagDetails(BaseModel):
    """Country flag information."""

    emoji: str | None = None
    """Flag emoji character"""

    unicode: str | None = None
    """Unicode code points for the flag emoji"""


class CountryCurrencyDetails(BaseModel):
    """Country currency information."""

    code: str | None = None
    """Three-letter ISO 4217 currency code (e.g., 'USD', 'EUR', 'GBP')"""

    symbol: str | None = None
    """Currency symbol (e.g., '$', '€', '£')"""


class ResidentialProxyDetails(BaseModel):
    """
    Residential proxy detection information.

    Identifies whether an IP is part of a residential proxy network,
    which routes traffic through real residential IP addresses.

    Available in: IPinfo Enterprise (with residential proxy add-on)
    """

    ip: IPvAnyAddress
    """The IP address that was checked"""

    last_seen: str | None = None
    """Last recorded date when the proxy was active (YYYY-MM-DD format)"""

    percent_days_seen: float | None = None
    """Percentage of days the IP was seen active in the last 7-day period (0-100)"""

    service: str | None = None
    """Name of the residential proxy service (e.g., 'Luminati', 'Oxylabs')"""

    ts_retrieved: str | None = None
    """UTC ISO timestamp of when this residential-proxy lookup was performed.

    Residential-proxy lookups are not cached, so this always reflects the
    current call (unlike ``IPDetails.ts_retrieved``, which preserves the
    original lookup time across cache hits)."""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_residential_proxy(self) -> bool:
        """Whether the IP is a known residential-proxy exit node.

        Derived from ``service``: the IPInfo residential-proxy add-on returns
        a non-null ``service`` only for IPs it has classified as proxies, so
        ``service is not None`` is the canonical "yes/no" signal. Surfaces in
        JSON output so agents can branch on a stable boolean instead of
        inspecting all-None fields.
        """
        return self.service is not None


class IPDetails(BaseModel):
    """
    Comprehensive IP address information including geolocation, network, and metadata.

    Fields available depend on your IPinfo plan:
    - IPinfo Lite (free): country, country_code, continent, ASN basics
    - IPinfo Core: full geolocation, ASN details, privacy/VPN/proxy/Tor flags
    - IPinfo Plus: adds carrier and company data
    - IPinfo Enterprise: adds domains and abuse contacts; the residential-proxy
      add-on (separate purchase) powers ipinfo_check_residential_proxy
    """

    ip: IPvAnyAddress
    """The IP address (IPv4 or IPv6)"""

    hostname: str | None = None
    """Reverse DNS hostname for the IP address"""

    # Geographic location fields
    city: str | None = None
    """City name"""

    region: str | None = None
    """Region/state/province name"""

    region_code: str | None = None
    """Region/state code (e.g., 'CA' for California, 'TX' for Texas)"""

    country: Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")] | None = None
    """Two-letter ISO 3166-1 alpha-2 country code (e.g., 'US', 'GB', 'DE')"""

    country_name: str | None = None
    """Full country name"""

    loc: str | None = None
    """Geographic coordinates as 'latitude,longitude' string"""

    latitude: Annotated[Decimal, Field(ge=-90, le=90)] | None = None
    """Latitude coordinate (-90 to 90 degrees)"""

    longitude: Annotated[Decimal, Field(ge=-180, le=180)] | None = None
    """Longitude coordinate (-180 to 180 degrees)"""

    postal: str | None = None
    """Postal/ZIP code"""

    timezone: str | None = None
    """IANA timezone identifier (e.g., 'America/New_York', 'Europe/London')"""

    # Country metadata
    continent: ContinentDetails | None = None
    """Continent information"""

    country_flag: CountryFlagDetails | None = None
    """Country flag emoji and unicode data"""

    country_flag_url: HttpUrl | None = None
    """URL to country flag image"""

    country_currency: CountryCurrencyDetails | None = None
    """Country currency information"""

    isEU: bool | None = None
    """Whether the country is in the European Union"""

    # Network/organization fields
    org: str | None = None
    """Organization/ISP string (free tier format: 'AS##### Org Name')"""

    asn: ASNDetails | None = None
    """Detailed ASN information (IPinfo Core+)"""

    # Privacy and security fields
    privacy: PrivacyDetails | None = None
    """VPN/proxy/Tor/hosting detection (IPinfo Core+)"""

    anycast: bool | None = None
    """Whether this IP uses anycast routing"""

    bogon: bool | None = None
    """Whether this is a bogon (unallocated/reserved) IP address.

    In practice this server filters bogon-like inputs (private, loopback,
    multicast, link-local, reserved) at the boundary with a structured
    ``special_ip_unsupported`` error before any IPInfo call, so this field is
    typically ``None`` here. It is retained on the model so any future
    relaxation of the boundary check (or a Lite-tier response that surfaces
    a bogon flag for an apparently-public IP) is round-trippable."""

    # Extended fields (higher tiers)
    carrier: CarrierDetails | None = None
    """Mobile carrier information for cellular IPs (IPinfo Plus+)"""

    company: CompanyDetails | None = None
    """Company/organization that owns the IP (IPinfo Plus+)"""

    domains: DomainsDetails | None = None
    """Domains hosted on this IP (IPinfo Enterprise)"""

    abuse: AbuseDetails | None = None
    """Abuse contact information (IPinfo Enterprise)"""

    # Metadata
    ts_retrieved: str | None = None
    """UTC ISO timestamp of the original IPInfo lookup.

    For cached results, this preserves the original lookup time (not the time
    the cached value was returned). Compare against the current time to gauge
    freshness; the cache TTL is configurable via ``IPINFO_CACHE_TTL`` (default
    3600 seconds)."""


class SkippedIP(BaseModel):
    """A single input IP that was filtered out before reaching the upstream API."""

    ip: str
    """The original input string (preserved before normalization for traceability)."""

    reason: str
    """Readable explanation (e.g., 'private IP address. Geolocation is not available.')."""


class MapResult(BaseModel):
    """Structured response from ``ipinfo_generate_map_url``.

    Replaces the bare-URL string return so agents can see how many of the
    submitted IPs actually made the map, and which were filtered out (with
    reasons), without re-validating client-side.
    """

    url: HttpUrl
    """URL of the interactive map on ipinfo.io."""

    mapped_ip_count: int
    """Number of IPs that made it onto the map (after dedup, normalization, and validation)."""

    skipped_ips: list[SkippedIP] = Field(default_factory=list)
    """Per-IP filter reasons. Capped at 100 entries; ``truncated`` indicates overflow."""

    skipped_count: int
    """Total number of IPs filtered out, even when ``skipped_ips`` is truncated."""

    truncated: bool
    """True when ``skipped_ips`` was capped at 100 because more were filtered."""
