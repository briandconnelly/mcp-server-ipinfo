# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This cycle hardens the agent-facing contract from a joint Claude + Codex
audit. The headline fix is a correctness bug (B0): multi-IP lookups silently
returned nothing on a cold cache.

### Fixed
- **Batch lookups silently dropped every freshly-fetched IP.** The ipinfo SDK
  returns fresh batch entries as raw `dict`s (only cache/bogon hits are
  `Details` objects), but `ipinfo_batch_lookup` kept entries only
  `if hasattr(details, "all")` — so `ipinfo_lookup_ips` with 2+ uncached IPs
  returned `[]`. The parser now accepts both shapes. (Single-IP lookups were
  unaffected; the unit mock returned `Details` objects, masking it — the mock
  now mirrors the real raw-dict shape, and a live multi-IP smoke test guards
  the integration path.)
- `ToolErrorEnvelope.request_id` is now populated with a server-generated
  correlation id (uuid4 hex) on every raised error; previously always `null`.

### Added
- Partial batch failures are surfaced: IPs that fail upstream are logged
  per-IP (capped) and counted in the summary instead of vanishing. If a
  multi-IP batch resolves *no* IPs at all, the failure is raised rather than
  masked behind an empty list, and the two total-failure modes are told apart:
  a wholesale-empty `/batch` response (every IP missing from the response) now
  raises a non-temporary `auth_insufficient_scope` instead of a "retry"
  `api_error` — it is overwhelmingly a token-tier problem, since the SDK
  swallows the `/batch` authorization failure for Lite-tier tokens (which must
  use `/batch/lite`) and returns an empty map. The hint points the agent at
  per-IP lookups or a Core+ upgrade instead of retrying a call that can never
  succeed. A batch whose entries were returned but all failed to parse stays a
  retryable `api_error`. (#52)
- `serverInfo.version` now reports the package version (e.g. `0.5.0`) via
  `FastMCP(version=...)`; it previously leaked the FastMCP library version,
  defeating client-side capability fingerprinting and version gating.
- `website_url` on the server for discoverability.
- Per-tool `meta.error_codes` lists the stable codes each tool can raise, so
  agents see the branch set from tool introspection without parsing the
  server instructions.
- `meta.removed_in = "0.6.0"` on the deprecated aliases (was prose-only).
- `idempotentHint: true` annotation on all read-only tools.
- A `format: "ip"` JSON Schema hint on IP-string inputs (non-enforcing; soft
  runtime validation still returns structured envelopes for bad input).
- Coarse progress reporting (`ctx.report_progress`) on the batch lookup path.
- Schema-level `minItems`/`maxItems` on the deprecated `get_ip_details` alias,
  matching `ipinfo_lookup_ips`.

### Changed
- **Breaking:** `ipinfo_lookup_ips` now defaults to `detail="summary"` (was
  `"full"`). Lean-by-default for token efficiency; pass `detail="full"` for
  every field.
- **Breaking:** `detail="summary"` now **omits** the heavy nested blocks
  (`continent`, `country_flag`, `country_flag_url`, `country_currency`,
  `abuse`, `domains`) entirely rather than nulling them. The previous
  shape-parity guarantee is dropped; callers using `record.get("continent")`
  are unaffected, callers using `record["continent"]` should switch to `.get`.
  The tool's output schema is unchanged (those fields remain optional).

## [0.5.0] - 2026-05-10

This release reshapes the tool surface for better agent ergonomics: structured
error envelopes with stable codes, a split between "look up my IP" and
"look up these IPs", a typed `MapResult`, and an `ipinfo_*` naming prefix.
The previous tool names remain as forwarding aliases scheduled for removal in
0.6.0.

### Added
- `ipinfo_lookup_my_ip()` — no-args tool for the calling client's own IP.
- `ipinfo_lookup_ips(ips, detail="full")` — list lookup with a `detail`
  toggle (`"summary"` nulls heavy nested blocks — `continent`, `country_flag*`,
  `country_currency`, `abuse`, `domains` — for batch token savings while
  preserving shape parity).
- `ipinfo_check_residential_proxy(ip)` — renamed from `get_residential_proxy_info`;
  tagged `enterprise` with `meta.plan_required = "residential_proxy_addon"`.
- `ipinfo_generate_map_url(ips)` — renamed from `get_map_url`; returns the
  new structured `MapResult` (`url`, `mapped_ip_count`, `skipped_ips`,
  `skipped_count`, `truncated`) instead of a bare URL string. `skipped_ips`
  is capped at 100 entries with `truncated=True` signaling overflow.
- `ToolErrorEnvelope` with stable codes (`invalid_ip_address`,
  `special_ip_unsupported`, `no_valid_ips`, `too_many_ips`, `auth_invalid`,
  `auth_insufficient_scope`, `quota_exceeded`, `timeout`, `api_error`,
  `unknown_error`); JSON-encoded into every `ToolError` so agents branch on
  `code` instead of parsing prose. Each envelope carries `temporary`,
  optional `retry_after_ms`, and a `repair` hint.
- `ResidentialProxyDetails.is_residential_proxy` — a Pydantic
  `@computed_field` returning `True` iff `service is not None`; serialized
  to JSON output so agents see an explicit boolean instead of all-None
  fields.
- `MapResult` and `SkippedIP` Pydantic models.
- Per-tool metadata: `meta={"introduced_in": "0.5.0"}` on every new tool;
  `tags={"enterprise"}` on `ipinfo_check_residential_proxy`.
- Schema-level constraints on `ips` arrays: `minItems=1`, `maxItems=500_000`.
- httpx exception classification covering `httpx.TimeoutException` →
  `timeout` and `httpx.HTTPStatusError` → status-aware codes (401 →
  `auth_invalid`, 403 → `auth_insufficient_scope`, 429 → `quota_exceeded`,
  5xx → temporary `api_error`, other 4xx → non-temporary `api_error`).
- Map-tool timeouts: `httpx.AsyncClient(timeout=30s)` at the HTTP layer plus
  `@mcp.tool(timeout=60s)` as framework-level defense-in-depth.
- `IPINFO_CACHE_SIZE` environment variable for tuning the cache's max-entry
  count (default `4096`).
- Expanded server `instructions` with a "what this server does NOT do"
  section, per-plan-tier capability list, cache TTL/size + `ts_retrieved`
  freshness semantics, stdio transport caveat for `ipinfo_lookup_my_ip`,
  and the structured error contract.
- Field-level documentation on `IPDetails.bogon` (typically null because
  bogon-like inputs are filtered at the boundary as
  `special_ip_unsupported`) and `ts_retrieved` on both `IPDetails` and
  `ResidentialProxyDetails` (clarifying that cached `IPDetails` records
  preserve the original lookup time, while residential-proxy lookups are
  not cached).
- `token=` and `timeout=` keyword-only arguments on the internal
  `ipinfo_get_map_url` helper; both must now be passed by name.

### Changed
- **Breaking** for direct callers of `ipinfo_generate_map_url`: the tool
  returns `MapResult` instead of a bare URL string. The deprecated
  `get_map_url` alias preserves the bare-URL `str` return for 0.4.x
  cached-client parity.
- Tool errors no longer collapse credential failures: missing/invalid
  token surfaces as `auth_invalid`, insufficient plan as
  `auth_insufficient_scope`. Quota and timeout failures carry
  `temporary: true` so agents know to retry.
- Per-IP `ctx.warning()` emissions during input filtering are capped at
  100 with an aggregated summary; a 500K batch with all entries filtered
  no longer floods logs or risks tripping the 60s tool-level timeout.

### Deprecated
- `get_ip_details`, `get_residential_proxy_info`, `get_map_url` are
  forwarding aliases tagged `deprecated` with `meta.replaced_by` set —
  **scheduled for removal in 0.6.0**.

### Fixed
- `ipinfo_generate_map_url` now sources the IPInfo token from the handler
  captured at startup (`handler.access_token`) instead of re-reading
  `IPINFO_API_TOKEN` on every call; a runtime env mutation can no longer
  cause the lookup and map paths to disagree on which token is in use.
- `_filter_valid_ips` now records empty/placeholder values (`""`,
  `"null"`, `"undefined"`, `"0.0.0.0"`, `"::"`) and duplicates as explicit
  `SkippedIP` entries with readable reasons; `MapResult.mapped_ip_count +
  skipped_count` now matches the input length.

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

[Unreleased]: https://github.com/briandconnelly/mcp-server-ipinfo/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/briandconnelly/mcp-server-ipinfo/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/briandconnelly/mcp-server-ipinfo/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/briandconnelly/mcp-server-ipinfo/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/briandconnelly/mcp-server-ipinfo/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/briandconnelly/mcp-server-ipinfo/releases/tag/v0.1.1
