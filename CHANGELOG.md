# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/briandconnelly/mcp-server-ipinfo/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/briandconnelly/mcp-server-ipinfo/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/briandconnelly/mcp-server-ipinfo/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/briandconnelly/mcp-server-ipinfo/releases/tag/v0.1.1
