from pydantic import BaseModel, condecimal, constr
from pydantic.networks import HttpUrl, IPvAnyAddress


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
    """Timestamp when this information was retrieved (UTC ISO format)"""


class IPDetails(BaseModel):
    """
    Comprehensive IP address information including geolocation, network, and metadata.

    Fields available depend on your IPinfo plan:
    - IPinfo Lite (free): country, country_code, continent, asn basics
    - IPinfo Core: Full geolocation, ASN details, privacy detection
    - IPinfo Plus: Adds carrier info, accuracy radius, company data
    - IPinfo Enterprise: Adds domains, abuse contacts, WHOIS data
    """

    ip: IPvAnyAddress = None  # type: ignore
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

    country: constr(pattern=r"^[A-Z]{2}$") | None = None
    """Two-letter ISO 3166-1 alpha-2 country code (e.g., 'US', 'GB', 'DE')"""

    country_name: str | None = None
    """Full country name"""

    loc: str | None = None
    """Geographic coordinates as 'latitude,longitude' string"""

    latitude: condecimal(ge=-90, le=90) | None = None
    """Latitude coordinate (-90 to 90 degrees)"""

    longitude: condecimal(ge=-180, le=180) | None = None
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
    """Whether this is a bogon (unallocated/reserved) IP address"""

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
    """Timestamp when this lookup was performed (UTC ISO format)"""
