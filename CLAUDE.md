# CLAUDE.md

## Conventions

- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.
- Follow the [Keep a Changelog](https://keepachangelog.com/) format for CHANGELOG.md.

## Releases

- Tag releases with the version prefixed by `v` (e.g., `v0.4.0`) and create GitHub releases from the tag.
- After tagging, publish with `uv build && uv publish`.

## FastMCP Documentation

Use the `mcp__fastmcp__search_fast_mcp` tool to search FastMCP documentation for API references, patterns, and examples when working on this codebase.

## Smoke tests

Live-API smoke tests in `tests/smoke/` exercise each production tool against the real IPInfo API. They are excluded from the default `pytest` run (via the `-m 'not smoke'` filter) and from the published wheel and sdist.

Before tagging a release, run:

    IPINFO_API_TOKEN=<your-token> uv run pytest -m smoke --no-cov

Without the token the tests skip cleanly. Each run makes ~6 live API calls. The smoke suite catches upstream contract changes that mocked unit tests cannot. A transient failure (5xx, timeout) should be re-run before being filed as a bug.
