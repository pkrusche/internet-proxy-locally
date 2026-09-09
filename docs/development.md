# Development

Run commands through `uv`; `.python-version` selects Python and `uv.lock`
pins dependencies. Jinja renders policies; cryptography manages the optional
TLS-interception CA.

```bash
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run python -m unittest discover -s tests -t .
```

CI uses the locked tools with `--frozen`. Upgrade them deliberately with
`uv lock --upgrade-package ruff` or `uv lock --upgrade-package ty`.

## Package layout

- `cli.run` implements `ipl`; `cli.lab` implements `ipl-lab`. Shared commands
  use `cli.common`, `lifecycle`, and `backend` for both container runtimes.
- `policy` validates and renders operational policy. `lab` adds fixture
  domains through the same renderer. Operational code must not import `lab`.
- `spec` defines container names, ports, and mounts; `images` defines tags.
- `checks.egress` provides `ipl-check`; `report` renders measured findings.
- `Fail` represents actionable errors, printed by the lifecycle CLIs with
  exit status 1. Unexpected exceptions retain their tracebacks.

See [policy.md](policy.md), [lab.md](lab.md), and
[tls-interception.md](tls-interception.md) for behavior and usage.

## Files and images

The package's `data/` contains read-only templates, the starter config, and image
build contexts, all included in the wheel. Container builds require an unpacked
installation. `IPL_DATA_ROOT` overrides this location for isolated tests.

The workspace's `config.toml` holds operational and lab settings. The starter
config is copied only by `ipl init`; it is never a runtime fallback. Rendered
configs, results, and findings also live in the workspace.
`paths.workspace_root()` searches upward from the current directory for
`config.toml`, falling back to the current directory. `IPL_ROOT` overrides it.

Image pins live in `data/images/<service>/Dockerfile`. **Bump the corresponding
tag in `images.py` whenever its pins or build context change**: setup skips tags
already present. Use a `-buildN` suffix for a build-only revision, or `--rebuild`
to force a local rebuild.

Keep documentation concise in `docs/`. Source comments should explain only
non-obvious constraints; omit code narration and refactor history.
