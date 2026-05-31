"""Live-API smoke tests for the production tool surface.

Run with::

    IPINFO_API_TOKEN=<your-token> uv run pytest -m smoke --no-cov

Without the token the tests skip cleanly. Each run makes ~8 live API calls
(the structured-error envelope test makes zero — pure boundary rejection).
"""

import json

import pytest
from fastmcp.exceptions import ToolError

pytestmark = pytest.mark.smoke

# Envelope codes that indicate transient upstream conditions, not bugs in
# this server. When the smoke run hits one of these AND the envelope is
# marked temporary=True, skip the test instead of failing — the structured
# contract still held (we got a valid envelope), but verifying the success
# path requires the upstream to be cooperative. ``api_error`` is in the set
# because the server's upstream classifier maps 5xx responses to
# ``api_error`` with ``temporary=True``; a non-temporary ``api_error`` (4xx
# the classifier doesn't otherwise recognize) is still a real failure.
_TRANSIENT_CODES = frozenset({"quota_exceeded", "timeout", "api_error"})


def _parse_envelope(err: ToolError) -> dict:
    """Extract the JSON-encoded envelope from a ToolError message."""
    msg = str(err)
    return json.loads(msg[msg.index("{") :])


def _is_transient(env: dict) -> bool:
    """Whether an envelope represents a transient upstream condition."""
    return env.get("code") in _TRANSIENT_CODES and env.get("temporary") is True


def _skip_if_transient(err: ToolError) -> None:
    """If err is a transient upstream envelope, pytest.skip with the reason.

    Re-raises any other ToolError (real bugs, schema breakage, auth issues).
    Use inside ``except ToolError as e:`` blocks where the test wants to
    accept "API was unhappy" as a non-failure outcome.
    """
    env = _parse_envelope(err)
    if _is_transient(env):
        pytest.skip(f"transient envelope from upstream: {env['code']!r} — re-run later")
    raise err


async def test_lookup_my_ip(client):
    try:
        r = await client.call_tool("ipinfo_lookup_my_ip", arguments={})
    except ToolError as e:
        _skip_if_transient(e)
    d = r.structured_content
    assert d.get("ip"), "ip field missing"
    assert d.get("country"), "country field missing"
    assert d.get("ts_retrieved"), "ts_retrieved missing"
    assert r.is_error is False


async def test_lookup_ips_single(client):
    try:
        r = await client.call_tool("ipinfo_lookup_ips", arguments={"ips": ["8.8.8.8"]})
    except ToolError as e:
        _skip_if_transient(e)
    results = r.structured_content["result"]
    assert len(results) == 1
    assert results[0]["ip"] == "8.8.8.8"
    assert results[0]["country"] == "US"


async def test_lookup_ips_multiple_fresh(client):
    """Fresh multi-IP lookup exercises the real batch path (getBatchDetails).

    Regression guard for B0: the SDK returns fresh batch entries as raw dicts,
    which a Details-only filter silently dropped — single-IP lookups (getDetails)
    never caught it. Every requested public IP must come back.
    """
    ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
    try:
        r = await client.call_tool(
            "ipinfo_lookup_ips", arguments={"ips": ips, "detail": "full"}
        )
    except ToolError as e:
        _skip_if_transient(e)
    results = r.structured_content["result"]
    returned = {d["ip"] for d in results}
    assert returned == set(ips), f"batch dropped IPs: missing {set(ips) - returned}"


async def test_lookup_ips_summary_mode(client):
    try:
        r = await client.call_tool(
            "ipinfo_lookup_ips",
            arguments={"ips": ["8.8.8.8"], "detail": "summary"},
        )
    except ToolError as e:
        _skip_if_transient(e)
    d = r.structured_content["result"][0]
    for heavy in (
        "continent",
        "country_flag",
        "country_flag_url",
        "country_currency",
        "abuse",
        "domains",
    ):
        assert heavy not in d, f"{heavy} should be omitted in summary mode"
    assert d.get("city"), "city should survive summary mode"
    assert d.get("country"), "country should survive summary mode"


async def test_summarize_ips_returns_aggregate(client):
    ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
    try:
        r = await client.call_tool(
            "ipinfo_summarize_ips",
            arguments={"ips": ips, "group_by": ["country", "asn"], "top_n": 50},
        )
    except ToolError as e:
        _skip_if_transient(e)
    d = r.structured_content
    assert d["mapped_ip_count"] == 3
    assert d["skipped_count"] == 0
    assert d["failed_count"] == 0
    assert d["by_country"], "country summary missing"
    assert d["by_asn"], "ASN summary missing"
    assert d["truncated_groups"] == {}


async def test_check_residential_proxy_envelope_path(client):
    """Either succeeds (Enterprise + add-on) OR raises a structured envelope.

    Both outcomes are passes — what we're verifying is the structured
    contract. Bare 401s without an envelope are the failure mode.
    """
    try:
        r = await client.call_tool(
            "ipinfo_check_residential_proxy",
            arguments={"ip": "142.250.80.46"},
        )
    except ToolError as e:
        env = _parse_envelope(e)
        if _is_transient(env):
            pytest.skip(f"transient envelope: {env['code']!r}")
        assert env["code"] in {"auth_invalid", "auth_insufficient_scope"}, (
            f"unexpected envelope code: {env['code']!r}"
        )
        assert env["temporary"] is False
    else:
        d = r.structured_content
        assert "is_residential_proxy" in d


async def test_generate_map_url_returns_structured_result(client):
    try:
        r = await client.call_tool(
            "ipinfo_generate_map_url",
            arguments={"ips": ["8.8.8.8", "1.1.1.1", "208.67.222.222"]},
        )
    except ToolError as e:
        _skip_if_transient(e)
    d = r.structured_content
    assert d["url"].startswith("https://ipinfo.io/"), f"unexpected url: {d['url']}"
    assert d["mapped_ip_count"] == 3
    assert d["skipped_count"] == 0
    assert d["truncated"] is False


async def test_generate_map_url_sentinel_and_dupe_accounting(client):
    """Verifies fix from PR #47: mapped + skipped == input length."""
    ips = ["8.8.8.8", "8.8.8.8", "", "null", "192.168.1.1", "1.1.1.1"]
    try:
        r = await client.call_tool("ipinfo_generate_map_url", arguments={"ips": ips})
    except ToolError as e:
        _skip_if_transient(e)
    d = r.structured_content
    assert d["mapped_ip_count"] + d["skipped_count"] == len(ips), (
        f"accounting mismatch: {d['mapped_ip_count']} + {d['skipped_count']} != {len(ips)}"
    )
    skipped_reasons = {s["ip"]: s["reason"] for s in d["skipped_ips"]}
    assert "duplicate" in skipped_reasons.get("8.8.8.8", "").lower()
    assert "private" in skipped_reasons.get("192.168.1.1", "").lower()


async def test_deprecated_get_map_url_alias_still_works(client):
    """Forwarding alias preserves the bare-string return for 0.4.x parity."""
    try:
        r = await client.call_tool("get_map_url", arguments={"ips": ["8.8.8.8"]})
    except ToolError as e:
        _skip_if_transient(e)
    # Bare-string return — FastMCP wraps non-object roots in {"result": "<url>"}.
    url = r.structured_content["result"]
    assert isinstance(url, str)
    assert url.startswith("https://ipinfo.io/")


async def test_structured_error_envelope_on_invalid_input(client):
    """No live API call — pure boundary rejection. Verifies envelope shape."""
    with pytest.raises(ToolError) as excinfo:
        await client.call_tool("ipinfo_lookup_ips", arguments={"ips": ["not-an-ip"]})
    env = _parse_envelope(excinfo.value)
    assert env["code"] == "no_valid_ips"
    assert env["temporary"] is False
    assert env["field"] == "ips"
    assert env["repair"]["hint"]
