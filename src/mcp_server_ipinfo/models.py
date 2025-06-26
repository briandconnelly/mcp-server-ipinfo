from pydantic import BaseModel, condecimal, constr
from pydantic.networks import HttpUrl, IPvAnyAddress


class IPDetails(BaseModel):
    """
    A Pydantic model representing detailed information about an IP address.

    This model contains geographical, network, and additional metadata about an IP address,
    including location coordinates, country information, ISP details, and timezone data.
    """

    ip: IPvAnyAddress = None  # type: ignore
    """The IP address (supports both IPv4 and IPv6 formats)"""

    hostname: str | None = None
    """The hostname associated with the IP address, if available"""

    city: str | None = None
    """The city where the IP address is located"""

    region: str | None = None
    """The region/state where the IP address is located"""

    country: constr(pattern=r"^[A-Z]{2}$") | None = None
    """The two-letter ISO country code (e.g., 'US', 'GB', 'DE')"""

    loc: str | None = None
    """The geographical coordinates in the format 'latitude,longitude'"""

    org: str | None = None
    """The organization/ISP associated with the IP address (free plan only; paid plan: see `asn` field)"""

    postal: str | None = None
    """The postal/ZIP code of the IP address location"""

    timezone: str | None = None
    """The timezone of the IP address location (e.g., 'America/New_York')"""

    country_name: str | None = None
    """The full name of the country"""

    isEU: bool | None = None
    """Boolean indicating if the country is in the European Union"""

    country_flag_url: HttpUrl | None = None
    """URL to the country's flag image"""

    country_flag: dict | None = None
    """Dictionary containing country flag information"""

    country_currency: dict | None = None
    """Dictionary containing country currency information with fields:
    - code: str - The three-letter currency code (e.g., 'USD', 'EUR', 'GBP')
    - symbol: str - The currency symbol (e.g., '$', '€', '£')"""

    continent: dict | None = None
    """Dictionary containing continent information with fields:
    - code: str - The two-letter continent code (e.g., 'NA', 'EU', 'AS')
    - name: str - The full continent name (e.g., 'North America', 'Europe', 'Asia')"""

    latitude: condecimal(ge=-90, le=90) | None = None
    """The latitude coordinate, ranging from -90 to 90 degrees"""

    longitude: condecimal(ge=-180, le=180) | None = None
    """The longitude coordinate, ranging from -180 to 180 degrees"""

    asn: dict | None = None
    """Dictionary containing ASN information with fields (Basic, Standard, Business, and Enterprise plans only):
    - asn: str - The ASN number
    - name: str - The name of the ASN
    - domain: str - The domain of the ASN
    - route: str - The route of the ASN
    - type: str - The type of the ASN"""

    privacy: dict | None = None
    """Dictionary containing privacy information with fields (Standard, Business, and Enterprise plans only):
    - vpn: bool - Whether the IP address is in a VPN
    - proxy: bool - Whether the IP address is in a proxy
    - tor: bool - Whether the IP address is in a Tor exit node
    - relay: bool - Whether the IP address is in a relay node
    - hosting: bool - Whether the IP address is in a hosting provider
    - service: bool - Whether the IP address is in a service provider"""

    carrier: dict | None = None
    """Dictionary containing mobile operator information with fields (Business and Enterprise plans only):
    - name: str - The name of the mobile operator
    - mcc: str - The Mobile Country Code of the mobile operator
    - mnc: str - The Mobile Network Code of the mobile operator"""

    company: dict | None = None
    """Dictionary containing company information with fields (Business and Enterprise plans only):
    - name: str - The name of the company
    - domain: HttpUrl - The domain of the company
    - type: str - The type of the company"""

    domains: dict | None = None
    """Dictionary containing domains information with fields (Business and Enterprise plans only):
    - ip: IPvAnyAddress - The IP address of the domain
    - total: int - The total number of domains associated with the IP address
    - domains: list[HttpUrl] - The list of domains associated with the IP address"""

    abuse: dict | None = None
    """Dictionary containing abuse contact information with fields (Business and Enterprise plans only):
    - address: str - The address of the abuse contact
    - country: str - The country of the abuse contact
    - email: str - The email of the abuse contact
    - phone: str - The phone number of the abuse contact
    - network: str - The network of the abuse contact"""

    bogon: bool | None = None
    """Boolean indicating if the IP address is a bogon IP address.
    A bogon IP address is an IP address that is not assigned to a network and is used for testing or other purposes.
    This is not a reliable indicator of the IP address's location.
    """

    anycast: bool | None = None
    """Boolean indicating if the IP address is an anycast IP address"""

    ts_retrieved: str | None = None
    """The timestamp of the IP address lookup"""
