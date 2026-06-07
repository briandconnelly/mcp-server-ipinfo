"""Guards for the MCPB bundle manifest.

These mirror the project's other contract/drift tests: the committed
``manifest.json`` must equal what ``scripts/gen_manifest.py`` produces, and its
advertised tool surface must match the server's actually-registered tools.
"""

import importlib.util
import json
from pathlib import Path

import fastmcp

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "manifest.json"

# scripts/ is not an installed package, so load the generator by file path.
_spec = importlib.util.spec_from_file_location(
    "gen_manifest", REPO_ROOT / "scripts" / "gen_manifest.py"
)
assert _spec is not None and _spec.loader is not None
gen_manifest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen_manifest)


def test_manifest_in_sync():
    """Committed manifest.json byte-equals the generator output (regenerate and
    commit after bumping the version or changing tools)."""
    assert MANIFEST.exists(), "manifest.json missing; run scripts/gen_manifest.py"
    expected = gen_manifest.render(gen_manifest.build_manifest())
    assert MANIFEST.read_text(encoding="utf-8") == expected, (
        "manifest.json is stale; run: uv run python scripts/gen_manifest.py"
    )


async def test_manifest_tools_match_server():
    """The manifest's tool names match the server's registered tools exactly."""
    from mcp_server_ipinfo.server import mcp

    async with fastmcp.Client(mcp) as client:
        registered = {t.name for t in await client.list_tools()}

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    advertised = {t["name"] for t in manifest["tools"]}
    assert advertised == registered


def test_manifest_required_fields():
    """MCPB-required top-level fields are present and the server is a uv bundle."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for field in (
        "manifest_version",
        "name",
        "version",
        "description",
        "author",
        "server",
    ):
        assert field in manifest, f"missing required manifest field: {field}"

    assert manifest["manifest_version"] == "0.4"
    assert manifest["server"]["type"] == "uv"
    # The bundle's run target must be a real file shipped in the archive.
    assert (REPO_ROOT / manifest["server"]["entry_point"]).exists()

    # The token is optional (the server runs in free Lite mode without it) but
    # must be collected as a masked secret when provided.
    api_token = manifest["user_config"]["api_token"]
    assert api_token["required"] is False
    assert api_token["sensitive"] is True


def test_manifest_version_matches_package():
    """Manifest version tracks the packaged version."""
    from importlib.metadata import version

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["version"] == version("mcp-server-ipinfo")
