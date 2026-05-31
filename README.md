# IP Geolocation MCP Server

[![PyPI](https://img.shields.io/pypi/v/mcp-server-ipinfo)](https://pypi.org/project/mcp-server-ipinfo/)
[![CI](https://github.com/briandconnelly/mcp-server-ipinfo/actions/workflows/checks.yml/badge.svg)](https://github.com/briandconnelly/mcp-server-ipinfo/actions/workflows/checks.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes the [ipinfo.io](https://ipinfo.io) API to AI agents. Geolocate IPv4 and IPv6 addresses, identify ISPs and ASNs, detect VPN/proxy/Tor exit nodes, and generate interactive maps for sets of IPs.


## Installation

Sign up for a free IPInfo API token at <https://ipinfo.io/signup> if you don't have one. The server runs with no token (free Lite tier — country and ASN basics) but most fields require a token.

Most MCP clients accept the following values:

| Field | Value |
|-------|-------|
| **Command** | `uvx` |
| **Arguments** | `mcp-server-ipinfo` |
| **Environment** | `IPINFO_API_TOKEN` = `<YOUR TOKEN>` |

### Development Version

To run the latest from `main`:

| Field | Value |
|-------|-------|
| **Command** | `uvx` |
| **Arguments** | `--from`, `git+https://github.com/briandconnelly/mcp-server-ipinfo`, `mcp-server-ipinfo` |
| **Environment** | `IPINFO_API_TOKEN` = `<YOUR TOKEN>` |


## Tools

- **`ipinfo_lookup_my_ip()`** — Geolocate the calling client's own IP. Takes no arguments. On stdio transports the result reflects this server's outbound IP, not the end user's.
- **`ipinfo_lookup_ips(ips, detail="summary")`** — Geolocate one or more specified IPs. Defaults to `detail="summary"`, which **omits** heavy nested blocks (continent, flags, currency, abuse, domains) for batch token savings; pass `detail="full"` for every field. Capped at 500,000 IPs per call. Invalid or special-use addresses (private, loopback, etc.) are filtered with `ctx.warning()` and excluded from the result list, as are IPs that fail upstream — match returned `IPDetails.ip` values back to your input to detect what was dropped. If every attempted lookup fails, a temporary `api_error` is raised.
- **`ipinfo_summarize_ips(ips, group_by=("country", "asn"), top_n=50)`** — Geolocate and aggregate a batch into fixed-size counts and percentages by country, continent, ASN, and/or privacy flags. Use this for large log-analysis tasks where per-IP records would waste context. Returns mapped, skipped, and failed counts plus capped top-N groups.
- **`ipinfo_check_residential_proxy(ip)`** — Check whether an IP is a known residential-proxy exit node. Tagged `enterprise` — requires the IPInfo residential-proxy add-on.
- **`ipinfo_generate_map_url(ips)`** — Build an interactive ipinfo.io map for a set of IPs. Returns a `MapResult` with the URL, the count that made the map, the IPs filtered out (with reasons, capped at 100), and a `truncated` flag.

### Plan tiers

| Tier | Fields available |
|------|------------------|
| Free Lite (no token) | country, country_code, continent, ASN basics |
| Core | full geolocation, ASN details, privacy/VPN/proxy/Tor/hosting flags |
| Plus | adds carrier and company data |
| Enterprise | adds domains and abuse contacts |
| Residential-proxy add-on | enables `ipinfo_check_residential_proxy`. Sold separately on top of Enterprise; not included by default. |

### Errors

Every tool raises a `ToolError` whose message is a JSON-encoded envelope with a stable `code` (`invalid_ip_address`, `special_ip_unsupported`, `no_valid_ips`, `too_many_ips`, `auth_invalid`, `auth_insufficient_scope`, `quota_exceeded`, `timeout`, `api_error`, `unknown_error`), a `temporary` flag, optional `retry_after_ms`, a `repair` hint, and a `request_id` correlation id. Agents should parse the message as JSON and branch on `code`. Each tool also advertises the subset of codes it can raise via `meta.error_codes`, so you can see the branch set from tool introspection.

### Deprecated tools

`get_ip_details`, `get_residential_proxy_info`, and `get_map_url` are forwarding aliases retained from 0.4.x. They are tagged `deprecated` and **will be removed in 0.6.0**. New code should call the `ipinfo_*` tools directly.


## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `IPINFO_API_TOKEN` | IPInfo API token. Without it the server runs in free Lite mode. | unset (Lite) |
| `IPINFO_CACHE_TTL` | Per-IP cache TTL in seconds. Cached results retain their original `ts_retrieved` timestamp. | `3600` |
| `IPINFO_CACHE_SIZE` | Maximum cache entries before oldest-first eviction. | `4096` |


## License

MIT License — see [LICENSE](LICENSE). Release history in [CHANGELOG.md](CHANGELOG.md).

## Disclaimer

This project is not affiliated with [IPInfo](https://ipinfo.io).
