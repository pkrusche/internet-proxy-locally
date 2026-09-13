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

An end to end release test that includes all the above and which checks whether real
proxies can be started on the current system is available in `scripts/e2e-release.sh`.

The release gate requires every operational quick check to pass. For full lab
measurements, `release.py` permits only the documented SNI/raw-tunnel/mixed-DNS
limitations of specific engines and TLS modes; missing checks, skips, errors,
and new policy failures fail the gate. Comparative `ipl-check` / `ipl-lab measure`
exit codes still describe measurement execution, not release acceptance.
Container names are shared: stop the operational instance before running the
gate. Its separate `IPL_ROOT` cannot remove an instance owned by another workspace.

Unresolved Iron denial checks print `Iron audit correlation` diagnostics to stderr:
the host's inclusive check window, audit timestamps, signed offsets from each
window boundary, and usable audit counts. Capture stderr alongside stdout in the
release log. Iron permits up to 100 ms of clock slack on either side of the
host window to accommodate small host/VM clock differences. Diagnostics show
the expanded bounds and whether a timestamp was admitted using slack. Older
or later evidence remains rejected; explicit denial, request matching,
transaction ordering, and duplicate/conflict rejection are unchanged.

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

The package's `data/` contains read-only templates and image
build contexts, all included in the wheel. Container builds require an unpacked
installation. `IPL_DATA_ROOT` overrides this location for isolated tests.

The workspace's `config.toml` is the sole source of operational and lab
settings. Rendered configs, results, and findings also live in the workspace.
`paths.workspace_root()` searches upward from the current directory for
`config.toml`, falling back to the current directory. `IPL_ROOT` overrides it.

Image pins live in `data/images/<service>/Dockerfile`. **Bump the corresponding
tag in `images.py` whenever its pins or build context change**: setup skips tags
already present. Use a `-buildN` suffix for a build-only revision, or `--rebuild`
to force a local rebuild.

Keep documentation concise in `docs/`. Source comments should explain only
non-obvious constraints; omit code narration and refactor history.
