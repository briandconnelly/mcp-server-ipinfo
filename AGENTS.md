# AGENTS.md

## Conventions

- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.
- Follow the [Keep a Changelog](https://keepachangelog.com/) format for CHANGELOG.md.

## Releases

Releases are automated by `.github/workflows/publish.yml`, which triggers on pushing a tag matching `v*`. The workflow runs the test suite, asserts the tag matches the `pyproject.toml` version, checks `manifest.json` is in sync, builds the package, publishes to PyPI via trusted publishing (OIDC — no API token needed), and creates the GitHub release with auto-generated notes and the built `dist/*` artifacts (wheel, sdist) attached. A dependent `bundle` job (reusable `.github/workflows/mcpb.yml`) then packs the MCPB bundle (`dist/mcp-server-ipinfo-<version>.mcpb`) for one-click Claude Desktop install and uploads it to the release.

`manifest.json` is **generated** from `pyproject.toml` plus the server's registered tools by `scripts/gen_manifest.py` — do not hand-edit it. `tests/test_manifest.py` and the workflow both run `gen_manifest.py --check` to catch a stale committed manifest.

To cut a release:

1. Bump `version` in `pyproject.toml`, regenerate the manifest with `uv run python scripts/gen_manifest.py`, and fold the `CHANGELOG.md` `[Unreleased]` section into a new `[<version>] - <date>` heading (and update the compare links at the bottom). The publish workflow asserts `tag == pyproject` and that the manifest is in sync, failing the release on a mismatch.
2. Run the smoke tests (see below) before tagging — the workflow runs the default suite but **not** the smoke suite.
3. Merge to `main`, then tag and push: `git tag v<version> && git push origin v<version>` (the `v` prefix matters — it's what the workflow triggers on).

Do **not** run `uv build` / `uv publish` by hand; pushing the tag does it. If you want curated release notes instead of the auto-generated ones, create or edit the GitHub release with the CHANGELOG section — the workflow attaches artifacts but does not overwrite an existing release body.

## FastMCP Documentation

Use the `mcp__fastmcp__search_fast_mcp` tool to search FastMCP documentation for API references, patterns, and examples when working on this codebase.

## Smoke tests

Live-API smoke tests in `tests/smoke/` exercise each production tool against the real IPInfo API. They are excluded from the default `pytest` run (via the `-m 'not smoke'` filter) and from the published wheel and sdist.

Before tagging a release, run:

    IPINFO_API_TOKEN=<your-token> uv run pytest -m smoke --no-cov

Without the token the tests skip cleanly. Each run makes ~8 live API calls. The smoke suite catches upstream contract changes that mocked unit tests cannot.

Transient upstream conditions auto-skip rather than fail: any envelope with `temporary: true` and a `code` in `{quota_exceeded, timeout, api_error}` (the last covers IPInfo 5xx). If a smoke test reports SKIPPED with a "transient envelope" reason, re-run it; only persistent failures should be filed as bugs.
