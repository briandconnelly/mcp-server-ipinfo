"""Tests for retry_after_ms population from upstream Retry-After headers.

Before 0.7.0 the envelope advertised retry_after_ms but never populated it. The
map path now reads the Retry-After header on a 429 and surfaces it in ms.
"""

import httpx

from mcp_server_ipinfo.server import _envelope_from_upstream, _parse_retry_after


class TestParseRetryAfter:
    def test_none_for_missing(self):
        assert _parse_retry_after(None) is None
        assert _parse_retry_after("") is None

    def test_delta_seconds_to_ms(self):
        assert _parse_retry_after("30") == 30_000
        assert _parse_retry_after(" 5 ") == 5_000

    def test_http_date_form_unparsed(self):
        # We intentionally do not parse the HTTP-date form; IPInfo uses seconds.
        assert _parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT") is None

    def test_negative_rejected(self):
        assert _parse_retry_after("-1") is None


class TestEnvelopeRetryAfter:
    def _http_429(self, headers: dict) -> httpx.HTTPStatusError:
        request = httpx.Request("POST", "https://ipinfo.io/map?cli=1")
        response = httpx.Response(429, headers=headers, request=request)
        return httpx.HTTPStatusError("rate limited", request=request, response=response)

    def test_429_populates_retry_after_ms(self):
        code, _msg, temporary, retry_after_ms, _repair = _envelope_from_upstream(
            self._http_429({"Retry-After": "12"})
        )
        assert code == "quota_exceeded"
        assert temporary is True
        assert retry_after_ms == 12_000

    def test_429_without_header_is_none(self):
        _code, _msg, _temp, retry_after_ms, _repair = _envelope_from_upstream(
            self._http_429({})
        )
        assert retry_after_ms is None
