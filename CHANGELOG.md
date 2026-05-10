# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `ipinfo_lookup_my_ip` tool for looking up the calling client's own IP (no arguments)
- `ipinfo_lookup_ips` tool for looking up one or more specified IPs, with a `detail: "summary" | "full"` toggle that nulls heavy nested blocks (`continent`, `country_flag*`, `country_currency`, `abuse`, `domains`) for batch token savings while preserving shape parity
- `ipinfo_check_residential_proxy` and `ipinfo_generate_map_url` (renamed from the originals)
- `ToolErrorEnvelope` Pydantic model with stable symbolic codes (`invalid_ip_address`, `special_ip_unsupported`, `no_valid_ips`, `too_many_ips`, `auth_invalid`, `auth_insufficient_scope`, `quota_exceeded`, `timeout`, `api_error`, `unknown_error`); JSON-encoded into every `ToolError` so agents can branch on `code` without parsing prose
- Per-tool metadata: `meta={"introduced_in": "0.5.0"}` on all new tools; `tags={"enterprise"}` and `meta={"plan_required": "residential_proxy_addon"}` on `ipinfo_check_residential_proxy`
- Schema-level `maxItems: 500_000` constraint on `ips` arrays so MCP clients can reject oversized inputs without a round-trip

### Changed
- Tool errors now distinguish missing/invalid token (`auth_invalid`) from insufficient plan scope (`auth_insufficient_scope`) instead of collapsing to one opaque message
- Quota and timeout failures map to `quota_exceeded` / `timeout` codes with `temporary: true` so agents know to retry
- Server `instructions` document the structured error contract and list both current and deprecated tool names

### Deprecated
- `get_ip_details`, `get_residential_proxy_info`, `get_map_url` retained as forwarding aliases tagged `deprecated` with `meta.replaced_by`; **scheduled for removal in 0.6.0**. The `get_map_url` alias preserves the bare-URL `str` return shape from 0.4.x; new code should call `ipinfo_generate_map_url` directly to receive the structured `MapResult`.

### Changed (continued)
- **Breaking for `ipinfo_generate_map_url`:** the tool now returns a structured `MapResult` (`url`, `mapped_ip_count`, `skipped_ips`, `skipped_count`, `truncated`) instead of a bare URL string. Agents see how many of the submitted IPs made the map and which were filtered out, with a per-IP reason. `skipped_ips` is capped at 100 entries; `truncated=True` signals overflow. The deprecated `get_map_url` alias still returns just the URL string for cached-client parity.

### Added (continued)
- `MapResult` and `SkippedIP` Pydantic models for the structured map response
- httpx exception classification: `httpx.TimeoutException` → `timeout` envelope code, `httpx.HTTPStatusError` → status-aware codes (`auth_invalid` for 401, `auth_insufficient_scope` for 403, `quota_exceeded` for 429, `api_error` for other 4xx/5xx)
- Explicit timeouts on the map path: `httpx.AsyncClient(timeout=30s)` at the HTTP layer plus FastMCP's `@mcp.tool(timeout=60s)` as framework-level defense-in-depth so a hung upstream cannot block the tool indefinitely
- `ResidentialProxyDetails.is_residential_proxy`: a Pydantic `@computed_field` that returns `True` iff `service is not None`; serialized to JSON output so agents can branch on a stable boolean instead of inspecting all-None fields
- `IPINFO_CACHE_SIZE` environment variable for tuning the in-memory cache's max-entry count (default `4096`); previously only `IPINFO_CACHE_TTL` was wired
- Expanded server `instructions` with a "what this server does NOT do" section (no DNS/CIDR/historical/malice scoring; private IPs filtered at boundary), per-plan-tier capability list, cache TTL/size + `ts_retrieved` semantics, and a stdio-transport caveat for `ipinfo_lookup_my_ip`

### Fixed
- `ipinfo_generate_map_url` now reads the IPInfo token from the handler captured at startup (`handler.access_token`) instead of re-reading `IPINFO_API_TOKEN` on every call; a runtime env mutation can no longer cause the lookup and map paths to disagree on which token is in use
- `_filter_valid_ips` now records empty/placeholder values (`""`, `"null"`, `"undefined"`, `"0.0.0.0"`, `"::"`) and duplicates as explicit `SkippedIP` entries with readable reasons, so `MapResult.mapped_ip_count + skipped_count` matches the input length
- Per-IP `ctx.warning()` emissions during input filtering are capped at 100 with an aggregated summary line after the cap; a 500K batch with all entries filtered no longer floods logs or risks tripping the 60s tool-level timeout

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
