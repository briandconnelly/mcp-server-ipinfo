#!/usr/bin/env python
"""Generate ``manifest.json`` (the MCPB bundle manifest) from a single source
of truth.

Identity (name/version/description/author) comes from ``pyproject.toml``; the
tool list is derived from the server's own registered tools so the manifest
cannot drift from what the server actually exposes. ``tests/test_manifest.py``
asserts the committed ``manifest.json`` matches this generator's output, so
regenerate and commit whenever the version or tool surface changes.

Usage:
    uv run python scripts/gen_manifest.py            # write manifest.json
    uv run python scripts/gen_manifest.py --check     # exit 1 if stale
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tomllib
from pathlib import Path

from mcp_server_ipinfo.server import mcp

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
MANIFEST = REPO_ROOT / "manifest.json"

REPO_URL = "https://github.com/briandconnelly/mcp-server-ipinfo"
KEYWORDS = ["mcp", "ipinfo", "geolocation", "ip", "asn", "vpn"]


def _tools() -> list[dict[str, str]]:
    """Manifest ``tools`` entries, derived from the server's registered tools so
    the name/description pairs stay in lockstep with the live server. The
    description is each tool's first line (the one-sentence summary). Sorted by
    name so the generated manifest is byte-stable regardless of registration
    order (the committed file is drift-guarded by byte equality)."""
    tools = asyncio.run(mcp.list_tools())
    return sorted(
        (
            {
                "name": tool.name,
                "description": (tool.description or "")
                .strip()
                .split("\n", 1)[0]
                .strip(),
            }
            for tool in tools
        ),
        key=lambda entry: entry["name"],
    )


def build_manifest() -> dict:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    author = project["authors"][0]

    return {
        "manifest_version": "0.4",
        "name": project["name"],
        "display_name": "IP Geolocation (IPInfo)",
        "version": project["version"],
        "description": project["description"],
        "author": {"name": author["name"], "email": author["email"]},
        "repository": {"type": "git", "url": REPO_URL},
        "homepage": REPO_URL,
        "documentation": f"{REPO_URL}#readme",
        "support": f"{REPO_URL}/issues",
        "license": "MIT",
        "keywords": KEYWORDS,
        "server": {
            "type": "uv",
            "entry_point": "src/mcp_server_ipinfo/server.py",
            "mcp_config": {
                "command": "uv",
                "args": [
                    "run",
                    "--directory",
                    "${__dirname}",
                    "--frozen",
                    "mcp-server-ipinfo",
                ],
                "env": {
                    "IPINFO_API_TOKEN": "${user_config.api_token}",
                    "IPINFO_CACHE_TTL": "${user_config.cache_ttl}",
                    "IPINFO_CACHE_SIZE": "${user_config.cache_size}",
                },
            },
        },
        "compatibility": {
            "platforms": ["darwin", "linux", "win32"],
            "runtimes": {"python": ">=3.13"},
        },
        "user_config": {
            "api_token": {
                "type": "string",
                "title": "IPInfo API Token",
                "description": (
                    "Your ipinfo.io API token. Leave blank to run in the free Lite "
                    "tier (country and ASN basics). Sign up at https://ipinfo.io/signup."
                ),
                "sensitive": True,
                "required": False,
            },
            "cache_ttl": {
                "type": "number",
                "title": "Cache TTL (seconds)",
                "description": "How long per-IP results are cached before re-fetching.",
                "default": 3600,
                "required": False,
            },
            "cache_size": {
                "type": "number",
                "title": "Cache Size (entries)",
                "description": "Maximum cached IP results before oldest-first eviction.",
                "default": 4096,
                "required": False,
            },
        },
        "tools": _tools(),
    }


def render(manifest: dict) -> str:
    """Deterministic JSON rendering used for both writing and drift comparison."""
    return json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if manifest.json is missing or stale (do not write).",
    )
    args = parser.parse_args()

    rendered = render(build_manifest())

    if args.check:
        current = MANIFEST.read_text(encoding="utf-8") if MANIFEST.exists() else ""
        if current != rendered:
            print(
                "manifest.json is out of date; run: uv run python scripts/gen_manifest.py"
            )
            return 1
        print("manifest.json is up to date.")
        return 0

    MANIFEST.write_text(rendered, encoding="utf-8")
    print(f"Wrote {MANIFEST.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
