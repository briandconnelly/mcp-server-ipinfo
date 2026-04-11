"""Tests for the IPInfoCache."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import patch

import time_machine

from mcp_server_ipinfo.cache import IPInfoCache
from mcp_server_ipinfo.models import IPDetails


class TestIPInfoCache:
    """Tests for IPInfoCache."""

    async def test_set_and_get(self, cache, sample_ip_details):
        """Test basic set and get operations."""
        await cache.set("8.8.8.8", sample_ip_details)
        result = await cache.get("8.8.8.8")

        assert result is not None
        assert str(result.ip) == "8.8.8.8"

    async def test_get_missing_key(self, cache):
        """Test getting a non-existent key returns None."""
        result = await cache.get("1.2.3.4")
        assert result is None

    @time_machine.travel("2024-01-01 00:00:00+00:00", tick=False)
    async def test_ttl_expiration(self, sample_ip_details):
        """Test that entries expire after TTL."""
        cache = IPInfoCache(ttl_seconds=60)
        await cache.set("8.8.8.8", sample_ip_details)

        # Should exist immediately
        assert await cache.get("8.8.8.8") is not None

        # Jump past TTL
        with time_machine.travel(
            datetime(2024, 1, 1, 0, 1, 1, tzinfo=timezone.utc), tick=False
        ):
            assert await cache.get("8.8.8.8") is None

    async def test_ttl_from_env(self, sample_ip_details):
        """Test TTL can be configured from environment variable."""
        with patch.dict("os.environ", {"IPINFO_CACHE_TTL": "7200"}):
            cache = IPInfoCache()
            assert cache.ttl_seconds == 7200

    async def test_set_batch(self, cache, sample_ip_details):
        """Test setting multiple entries at once."""
        details1 = sample_ip_details
        details2 = IPDetails(ip="1.1.1.1", city="Sydney")

        await cache.set_batch({"8.8.8.8": details1, "1.1.1.1": details2})

        result1 = await cache.get("8.8.8.8")
        result2 = await cache.get("1.1.1.1")

        assert result1 is not None
        assert result2 is not None
        assert str(result1.ip) == "8.8.8.8"
        assert str(result2.ip) == "1.1.1.1"

    async def test_get_batch(self, cache, sample_ip_details):
        """Test getting multiple entries at once."""
        details1 = sample_ip_details
        details2 = IPDetails(ip="1.1.1.1", city="Sydney")

        await cache.set("8.8.8.8", details1)
        await cache.set("1.1.1.1", details2)

        results = await cache.get_batch(["8.8.8.8", "1.1.1.1", "2.2.2.2"])

        assert len(results) == 2
        assert "8.8.8.8" in results
        assert "1.1.1.1" in results
        assert "2.2.2.2" not in results

    @time_machine.travel("2024-01-01 00:00:00+00:00", tick=False)
    async def test_get_batch_with_expired(self, sample_ip_details):
        """Test that get_batch excludes expired entries."""
        cache = IPInfoCache(ttl_seconds=60)
        await cache.set("8.8.8.8", sample_ip_details)

        with time_machine.travel(
            datetime(2024, 1, 1, 0, 1, 1, tzinfo=timezone.utc), tick=False
        ):
            results = await cache.get_batch(["8.8.8.8"])
            assert len(results) == 0

    @time_machine.travel("2024-01-01 00:00:00+00:00", tick=False)
    async def test_cleanup_expired(self, sample_ip_details):
        """Test cleaning up expired entries."""
        cache = IPInfoCache(ttl_seconds=60)
        await cache.set("8.8.8.8", sample_ip_details)
        await cache.set("1.1.1.1", IPDetails(ip="1.1.1.1"))

        with time_machine.travel(
            datetime(2024, 1, 1, 0, 1, 1, tzinfo=timezone.utc), tick=False
        ):
            removed = await cache.cleanup_expired()
            assert removed == 2
            assert len(cache) == 0

    async def test_clear(self, cache, sample_ip_details):
        """Test clearing all entries."""
        await cache.set("8.8.8.8", sample_ip_details)
        await cache.set("1.1.1.1", IPDetails(ip="1.1.1.1"))

        assert len(cache) == 2

        await cache.clear()
        assert len(cache) == 0

    async def test_concurrent_access(self, cache, sample_ip_details):
        """Test that concurrent access is safe."""

        async def write_entry(ip: str):
            details = IPDetails(ip=ip)
            await cache.set(ip, details)
            await asyncio.sleep(0.01)
            return await cache.get(ip)

        # Run many concurrent writes
        ips = [f"1.1.1.{i}" for i in range(50)]
        results = await asyncio.gather(*[write_entry(ip) for ip in ips])

        # All writes should succeed
        assert all(r is not None for r in results)

    async def test_len(self, cache, sample_ip_details):
        """Test __len__ returns correct count."""
        assert len(cache) == 0

        await cache.set("8.8.8.8", sample_ip_details)
        assert len(cache) == 1

        await cache.set("1.1.1.1", IPDetails(ip="1.1.1.1"))
        assert len(cache) == 2

    async def test_overwrite_existing(self, cache, sample_ip_details):
        """Test overwriting an existing entry."""
        await cache.set("8.8.8.8", sample_ip_details)

        new_details = IPDetails(ip="8.8.8.8", city="New City")
        await cache.set("8.8.8.8", new_details)

        result = await cache.get("8.8.8.8")
        assert result.city == "New City"
        assert len(cache) == 1

    async def test_max_size_eviction(self, sample_ip_details):
        """Test that oldest entries are evicted when max_size is exceeded."""
        cache = IPInfoCache(ttl_seconds=3600, max_size=3)

        await cache.set("1.1.1.1", IPDetails(ip="1.1.1.1"))
        await cache.set("2.2.2.2", IPDetails(ip="2.2.2.2"))
        await cache.set("3.3.3.3", IPDetails(ip="3.3.3.3"))
        assert len(cache) == 3

        # Adding a 4th should evict the oldest (1.1.1.1)
        await cache.set("4.4.4.4", IPDetails(ip="4.4.4.4"))
        assert len(cache) == 3
        assert await cache.get("1.1.1.1") is None
        assert await cache.get("4.4.4.4") is not None

    async def test_max_size_eviction_batch(self):
        """Test that set_batch respects max_size."""
        cache = IPInfoCache(ttl_seconds=3600, max_size=2)

        await cache.set_batch(
            {
                "1.1.1.1": IPDetails(ip="1.1.1.1"),
                "2.2.2.2": IPDetails(ip="2.2.2.2"),
                "3.3.3.3": IPDetails(ip="3.3.3.3"),
            }
        )
        assert len(cache) <= 2
