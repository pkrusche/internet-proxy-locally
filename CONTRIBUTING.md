# Contributing

Use Python 3.11 or newer. Run `uv sync --frozen`, then `uv run ruff check .`,
`uv run ruff format --check .`, `uv run ty check`, and
`uv run python -m unittest discover -s tests -t .`.
Generated configs are refreshed automatically on startup.

Container-facing changes require `scripts/e2e-release.sh` on Linux Docker and,
when applicable, Apple `container`. Never run that script on a host where the
chosen test names or ports belong to an unrelated service.
