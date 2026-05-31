"""Tests for server-side IP batch summaries."""

from unittest.mock import AsyncMock

from mcp_server_ipinfo.models import IPDetails, SummaryResult
from mcp_server_ipinfo.server import ipinfo_summarize_ips


def _details(ip: str, **kwargs) -> IPDetails:
    return IPDetails(ip=ip, **kwargs)


class TestIpinfoSummarizeIps:
    async def test_groups_by_country_with_counts_and_percentages(
        self, mock_context_with_state
    ):
        cache = mock_context_with_state.lifespan_context["cache"]
        await cache.set("8.8.8.8", _details("8.8.8.8", country="US"))
        await cache.set("9.9.9.9", _details("9.9.9.9", country="US"))
        await cache.set("1.1.1.1", _details("1.1.1.1", country="AU"))

        result = await ipinfo_summarize_ips(
            ips=["8.8.8.8", "9.9.9.9", "1.1.1.1"],
            group_by=("country",),
            ctx=mock_context_with_state,
        )

        assert isinstance(result, SummaryResult)
        assert result.mapped_ip_count == 3
        assert result.skipped_count == 0
        assert result.failed_count == 0
        assert result.by_country is not None
        assert [(item.key, item.count, item.percent) for item in result.by_country] == [
            ("US", 2, 66.67),
            ("AU", 1, 33.33),
        ]
        assert result.by_asn is None

    async def test_empty_group_by_returns_counts_only(self, mock_context_with_state):
        result = await ipinfo_summarize_ips(
            ips=["8.8.8.8"],
            group_by=(),
            ctx=mock_context_with_state,
        )

        assert result.mapped_ip_count == 1
        assert result.by_country is None
        assert result.by_continent is None
        assert result.by_asn is None
        assert result.by_privacy is None

    async def test_truncates_long_tail_groups(self, mock_context_with_state):
        cache = mock_context_with_state.lifespan_context["cache"]
        ips = [f"11.0.0.{i}" for i in range(1, 61)]
        for i, ip in enumerate(ips, start=1):
            await cache.set(ip, _details(ip, asn={"asn": f"AS{i}", "name": f"Org {i}"}))

        result = await ipinfo_summarize_ips(
            ips=ips,
            group_by=("asn",),
            top_n=50,
            ctx=mock_context_with_state,
        )

        assert result.by_asn is not None
        assert len(result.by_asn) == 50
        assert result.truncated_groups == {"asn": 60}

    async def test_privacy_aggregation_counts_true_flags(self, mock_context_with_state):
        cache = mock_context_with_state.lifespan_context["cache"]
        await cache.set(
            "8.8.8.8",
            _details("8.8.8.8", privacy={"vpn": True, "hosting": True}),
        )
        await cache.set(
            "9.9.9.9",
            _details("9.9.9.9", privacy={"vpn": True, "tor": True}),
        )
        await cache.set("1.1.1.1", _details("1.1.1.1"))

        result = await ipinfo_summarize_ips(
            ips=["8.8.8.8", "9.9.9.9", "1.1.1.1"],
            group_by=("privacy",),
            ctx=mock_context_with_state,
        )

        assert result.by_privacy is not None
        assert [(item.key, item.count) for item in result.by_privacy] == [
            ("vpn", 2),
            ("hosting", 1),
            ("tor", 1),
        ]

    async def test_lite_tier_without_privacy_returns_empty_privacy_group(
        self, mock_context_with_state
    ):
        result = await ipinfo_summarize_ips(
            ips=["8.8.8.8"],
            group_by=("privacy",),
            ctx=mock_context_with_state,
        )

        assert result.mapped_ip_count == 1
        assert result.by_privacy == []

    async def test_cache_records_contribute_to_summary(self, mock_context_with_state):
        cache = mock_context_with_state.lifespan_context["cache"]
        await cache.set("8.8.8.8", _details("8.8.8.8", country="US"))

        result = await ipinfo_summarize_ips(
            ips=["8.8.8.8", "1.1.1.1"],
            group_by=("country",),
            ctx=mock_context_with_state,
        )

        assert result.mapped_ip_count == 2
        assert result.by_country is not None
        assert [(item.key, item.count) for item in result.by_country] == [("US", 2)]

    async def test_reports_skipped_and_failed_counts(self, mock_context_with_state):
        handler = mock_context_with_state.lifespan_context["ipinfo_handler"]
        handler.getBatchDetails = AsyncMock(
            return_value={
                "8.8.8.8": {
                    "ip": "8.8.8.8",
                    "country": "US",
                    "org": "AS15169 Google LLC",
                }
            }
        )

        result = await ipinfo_summarize_ips(
            ips=["8.8.8.8", "1.1.1.1", "192.168.1.1", "8.8.8.8"],
            group_by=("country",),
            ctx=mock_context_with_state,
        )

        assert result.mapped_ip_count == 1
        assert result.skipped_count == 2
        assert result.failed_count == 1
        assert result.by_country is not None
        assert [(item.key, item.count) for item in result.by_country] == [("US", 1)]
