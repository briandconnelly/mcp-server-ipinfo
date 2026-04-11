# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-04-11

### Added
- Pre-commit hooks via prek: built-in checks (large files, merge conflicts, TOML/YAML validation, private key detection, trailing whitespace, EOF fixer), uv-lock, ruff check/format, and ty type checking
- Cache max-size eviction (default 4096 entries) to prevent unbounded memory growth
- Link-local IP address detection with specific error message
- Input whitespace stripping for robustness with LLM-generated input
- IP deduplication in `get_ip_details` to avoid redundant API calls
- Enforcement of the 500K IP limit in `get_map_url`
- API token forwarding in map URL requests
- `httpx` as an explicit dependency
- `ruff`, `ty`, `prek`, and `time-machine` as dev dependencies

### Changed
- **Breaking:** Requires `fastmcp>=3.2.0` (upgraded from FastMCP 2.x to 3.x)
- Lifespan context accessed via `ctx.lifespan_context` (public API) instead of `ctx.fastmcp._lifespan_result` (private)
- Tool context parameters use `CurrentContext()` default (FastMCP 3.x dependency injection)
- Replaced deprecated Pydantic v1 `constr`/`condecimal` with `Annotated` + `StringConstraints`/`Field`
- `IPDetails.ip` is now a required field (previously defaulted to `None`)
- Extracted shared `_filter_valid_ips` helper, eliminating duplicated validation logic
- Table-driven IP address type checking in `_validate_ip`
- Timestamps use `.isoformat()` via `_utc_timestamp()` helper for consistent ISO 8601 format
- Cache uses timezone-aware `datetime.now(timezone.utc)` consistently
- Simplified `ipinfo_get_map_url` signature (removed unused `IPv4Address`/`IPv6Address` handling)
- Test suite uses `time-machine` instead of `asyncio.sleep` (3.75s to 0.49s)
- Tests use `@pytest.mark.parametrize` for validation and normalization cases
- Test suite expanded to 79 tests (from 59)

## [0.3.0] - 2025-01-24

### Added
- Batch IP lookup support - `get_ip_details` now accepts a list of IPs for efficient bulk lookups
- Residential proxy detection via new `get_residential_proxy_info` tool
- Map URL generation via new `get_map_url` tool for visualizing IP locations
- Async architecture using `ipinfo.AsyncHandler` for non-blocking API calls
- Lifespan management for proper handler initialization and cleanup
- Async-safe cache with `asyncio.Lock` and batch operation support
- Configurable cache TTL via `IPINFO_CACHE_TTL` environment variable
- Tool annotations (`readOnlyHint`, `openWorldHint`) for MCP clients
- Comprehensive test suite with pytest (59 tests)
- Typed sub-models for nested response fields (ASNDetails, PrivacyDetails, CarrierDetails, etc.)
- `region_code` field in IPDetails for state/province codes

### Changed
- `get_ip_details` now returns `list[IPDetails]` instead of `IPDetails` (unified single and batch lookups)
- `get_ip_details` parameter changed from `ip: str | None` to `ips: list[str] | None`
- Cache methods are now async (`get`, `set`, `get_batch`, `set_batch`)
- IP validation now checks loopback before private (correct order of specificity)
- Nested fields (asn, privacy, carrier, company, etc.) are now typed Pydantic models instead of dicts
- Updated documentation to reflect correct API tier names (Lite, Core, Plus, Enterprise)
- Fixed `privacy.service` documentation (is a string, not boolean)

### Removed
- `get_ipinfo_api_token` tool (redundant)
- Separate `get_batch_ip_details` tool (merged into `get_ip_details`)

## [0.2.0] - 2024-12-19

### Added
- IP address validation (rejects private, loopback, multicast, reserved addresses)
- Server instructions for LLM context

### Changed
- Migrated to FastMCP framework
- Renamed `timestamp` field to `ts_retrieved` in response models

## [0.1.1] - 2024-11-15

### Added
- Initial release
- `get_ip_details` tool for single IP geolocation lookup
- `get_ipinfo_api_token` tool to check API token configuration
- Response caching with 1-hour TTL
- Pydantic models for API responses

[Unreleased]: https://github.com/briandconnelly/mcp-server-ipinfo/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/briandconnelly/mcp-server-ipinfo/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/briandconnelly/mcp-server-ipinfo/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/briandconnelly/mcp-server-ipinfo/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/briandconnelly/mcp-server-ipinfo/releases/tag/v0.1.1
