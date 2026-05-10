"""Test fixtures for live-API smoke tests.

These tests run against the real IPInfo API and require ``IPINFO_API_TOKEN``.
They are excluded from the default ``pytest`` invocation via the
``-m 'not smoke'`` filter in ``pyproject.toml`` and are also auto-skipped
here when the token is absent so an explicit ``pytest -m smoke`` doesn't
fire spurious 401s.
"""

import os

import pytest
from fastmcp import Client

from mcp_server_ipinfo.server import mcp


def pytest_collection_modifyitems(config, items):
    """Skip smoke tests when the live API token is absent.

    Belt-and-suspenders with the addopts marker filter:
    - Default ``pytest`` skips smoke via ``-m 'not smoke'``.
    - Explicit ``pytest -m smoke`` without a token gets a clean skip
      instead of upstream auth errors.
    """
    if os.environ.get("IPINFO_API_TOKEN"):
        return
    skip_no_token = pytest.mark.skip(
        reason="IPINFO_API_TOKEN not set; smoke tests require a live token"
    )
    for item in items:
        if "smoke" in item.keywords:
            item.add_marker(skip_no_token)


@pytest.fixture
async def client():
    """Yield a fresh in-process Client per test.

    Each Client opens its own lifespan, which gives a fresh ``IPInfoCache``
    so every test makes a real upstream call (no cross-test cache hits).
    """
    async with Client(mcp) as c:
        yield c


def sc(result):
    """Read ``structured_content`` from a CallToolResult.

    FastMCP's ``.data`` doesn't auto-rehydrate complex Pydantic types
    (``Decimal``, ``IPvAnyAddress``, ``HttpUrl``, nested models) and returns
    ``None`` when rehydration fails. Real MCP clients consume
    ``structured_content`` directly; smoke tests do the same.
    """
    return result.structured_content
