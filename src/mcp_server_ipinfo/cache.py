from datetime import datetime, timedelta

from .models import IPDetails


class IPInfoCache:
    """
    A cache for IPInfo API responses.
    """

    def __init__(self, ttl_seconds: int = 3600):
        self.cache = {}
        self.ttl_seconds = ttl_seconds

    def get(self, ip: str) -> IPDetails | None:
        if ip in self.cache:
            data, timestamp = self.cache[ip]
            if datetime.now() - timestamp < timedelta(seconds=self.ttl_seconds):
                return data
        return None

    def set(self, ip: str, data: IPDetails):
        self.cache[ip] = (data, datetime.now())
