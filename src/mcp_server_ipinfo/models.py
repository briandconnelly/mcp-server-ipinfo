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

    hostname: HttpUrl | None = None
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
    """The organization/ISP associated with the IP address"""

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
