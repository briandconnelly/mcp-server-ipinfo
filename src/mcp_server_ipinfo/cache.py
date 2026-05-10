import asyncio
import os
from datetime import datetime, timedelta, timezone

from .models import IPDetails

DEFAULT_MAX_SIZE = 4096


class IPInfoCache:
    """
    An async-safe cache for IPInfo API responses with TTL expiration.
    """

    def __init__(self, ttl_seconds: int | None = None, max_size: int | None = None):
        """
        Initialize the cache.

        Args:
            ttl_seconds: Time-to-live for cache entries in seconds.
                        Defaults to IPINFO_CACHE_TTL env var or 3600 (1 hour).
            max_size: Maximum number of entries. Oldest entries are evicted
                     when this limit is exceeded. Defaults to IPINFO_CACHE_SIZE
                     env var or 4096.
        """
        if ttl_seconds is None:
            ttl_seconds = int(os.environ.get("IPINFO_CACHE_TTL", "3600"))
        if max_size is None:
            max_size = int(os.environ.get("IPINFO_CACHE_SIZE", str(DEFAULT_MAX_SIZE)))
        if max_size < 1:
            raise ValueError(f"max_size must be at least 1, got {max_size}")
        self._cache: dict[str, tuple[IPDetails, datetime]] = {}
        self._ttl_seconds = ttl_seconds
        self._max_size = max_size
        self._lock = asyncio.Lock()

    @property
    def ttl_seconds(self) -> int:
        """Return the TTL in seconds."""
        return self._ttl_seconds

    def _evict_oldest(self) -> None:
        """Evict the oldest entries until the cache is within max_size.

        Must be called while holding the lock.
        """
        while len(self._cache) > self._max_size:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]

    async def get(self, ip: str) -> IPDetails | None:
        """
        Get a cached result for an IP address.

        Args:
            ip: The IP address to look up.

        Returns:
            The cached IPDetails if found and not expired, None otherwise.
        """
        async with self._lock:
            if ip in self._cache:
                data, timestamp = self._cache[ip]
                if datetime.now(timezone.utc) - timestamp < timedelta(
                    seconds=self._ttl_seconds
                ):
                    return data
                # Entry expired, remove it
                del self._cache[ip]
            return None

    async def set(self, ip: str, data: IPDetails) -> None:
        """
        Cache a result for an IP address.

        Args:
            ip: The IP address to cache.
            data: The IPDetails to cache.
        """
        async with self._lock:
            self._cache[ip] = (data, datetime.now(timezone.utc))
            self._evict_oldest()

    async def set_batch(self, results: dict[str, IPDetails]) -> None:
        """
        Cache multiple results at once.

        Args:
            results: Dictionary mapping IP addresses to their IPDetails.
        """
        async with self._lock:
            now = datetime.now(timezone.utc)
            for ip, data in results.items():
                self._cache[ip] = (data, now)
            self._evict_oldest()

    async def get_batch(self, ips: list[str]) -> dict[str, IPDetails]:
        """
        Get cached results for multiple IP addresses.

        Args:
            ips: List of IP addresses to look up.

        Returns:
            Dictionary mapping IP addresses to their cached IPDetails.
            Only includes IPs that were found and not expired.
        """
        results = {}
        async with self._lock:
            now = datetime.now(timezone.utc)
            expired = []
            for ip in ips:
                if ip in self._cache:
                    data, timestamp = self._cache[ip]
                    if now - timestamp < timedelta(seconds=self._ttl_seconds):
                        results[ip] = data
                    else:
                        expired.append(ip)
            # Clean up expired entries
            for ip in expired:
                del self._cache[ip]
        return results

    async def cleanup_expired(self) -> int:
        """
        Remove all expired entries from the cache.

        Returns:
            The number of entries removed.
        """
        async with self._lock:
            now = datetime.now(timezone.utc)
            expired = [
                ip
                for ip, (_, timestamp) in self._cache.items()
                if now - timestamp >= timedelta(seconds=self._ttl_seconds)
            ]
            for ip in expired:
                del self._cache[ip]
            return len(expired)

    async def clear(self) -> None:
        """Clear all entries from the cache."""
        async with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        """Return the number of entries in the cache (including expired)."""
        return len(self._cache)
