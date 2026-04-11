# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Model Context Protocol (MCP) server that provides IP geolocation, ISP lookup, and residential proxy detection using the ipinfo.io API. Built with FastMCP and Pydantic for Python 3.13+.

## Development Commands

```bash
# Install dependencies (including dev dependencies)
uv sync --extra dev

# Run the server locally
uv run mcp-server-ipinfo

# Run tests
uv run pytest

# Run tests with verbose output
uv run pytest -v

# Linting and formatting (used in CI)
uvx ruff check
uvx ruff format --check

# Format code
uvx ruff format
```

## Architecture

The server uses FastMCP's lifespan management to initialize a shared async ipinfo handler at startup, which is properly cleaned up on shutdown. All tools share this handler and an async-safe cache.

### MCP Tools

- `get_ip_details` - Look up details for one or more IP addresses (or client's own IP if none provided)
- `get_residential_proxy_info` - Check if an IP is a residential proxy

### Source Layout (`src/mcp_server_ipinfo/`)

- `server.py` - FastMCP server definition, lifespan management, and tool implementations. Entry point is `mcp.run` via the CLI script.
- `models.py` - Pydantic models: `IPDetails` for IP geolocation data, `ResidentialProxyDetails` for proxy detection
- `ipinfo.py` - Async wrapper functions for ipinfo library API calls
- `cache.py` - Async-safe TTL cache with batch operation support

### Key Patterns

- Tools use FastMCP's `@mcp.tool()` decorator with tool annotations (`readOnlyHint`, `openWorldHint`)
- Async ipinfo handler is initialized via `@asynccontextmanager` lifespan and accessed through `ctx.lifespan_context`
- IP validation uses Python's `ipaddress` module to reject private/loopback/reserved/multicast addresses
- `ToolError` from fastmcp.exceptions is used for user-facing errors
- Cache is async-safe using `asyncio.Lock` and supports batch operations

## Testing

Tests are in `tests/` and use pytest with pytest-asyncio:

- `test_models.py` - Pydantic model validation tests
- `test_cache.py` - Async cache behavior tests
- `test_tools.py` - Tool functionality tests with mocked ipinfo handler

Run tests with: `uv run pytest`

## Environment Variables

- `IPINFO_API_TOKEN` - Enables premium API features (ASN, privacy detection, carrier info, residential proxy detection)
- `IPINFO_CACHE_TTL` - Cache TTL in seconds (default: 3600)

## FastMCP Documentation

Use the `mcp__fastmcp__SearchFastMcp` tool to search FastMCP documentation for API references, patterns, and examples when working on this codebase.
