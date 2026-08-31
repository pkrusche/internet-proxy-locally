#!/usr/bin/env bash
# End-to-end smoke test: everything the packaging refactor could not verify
# from a sandbox with no network and no container runtime.
#
# `uv sync`/`uv build` need the package index; `ipl-verify *` need a real
# Docker or Apple `container` install. TODO.md flags both as exercised only
# by inspection ("the first `uv sync` on a networked machine is the step
# that has not run"). This script is that machine's checklist, in one
# command: build the package for real, confirm the wheel still carries
# data/ (the templates, service specs and image build contexts an installed
# wheel needs to be self-contained), then run the unit suite and the
# `ipl-verify` scripts against a real backend.
#
# Every step runs even if an earlier one fails, so one bad step does not
# hide the rest — the summary at the end lists exactly what did not pass.
#
#   scripts/e2e-smoke.sh
#   scripts/e2e-smoke.sh --backend docker
#   scripts/e2e-smoke.sh --skip-sync   # re-run without refreshing the venv

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

BACKEND=""
SKIP_SYNC=0
while [ $# -gt 0 ]; do
    case "$1" in
        --backend) BACKEND="$2"; shift 2 ;;
        --skip-sync) SKIP_SYNC=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

FAILED=()

step() {
    local name="$1"; shift
    echo
    echo "=== $name"
    if "$@"; then
        echo "--- ok: $name"
    else
        echo "--- FAILED: $name"
        FAILED+=("$name")
    fi
}

# -- prerequisites: fail fast, nothing below means anything without them ----

if ! command -v uv >/dev/null 2>&1; then
    echo "error: uv is not installed (https://docs.astral.sh/uv/)" >&2
    exit 1
fi

if [ -z "$BACKEND" ]; then
    if command -v docker >/dev/null 2>&1; then
        BACKEND=docker
    elif command -v container >/dev/null 2>&1; then
        BACKEND=container
    else
        echo "error: no container backend found (install Docker or Apple \`container\`)" >&2
        exit 1
    fi
fi
echo "backend: $BACKEND"

# -- the packaging itself: never exercised for real in an offline sandbox ---

if [ "$SKIP_SYNC" -eq 0 ]; then
    step "uv sync" uv sync
fi

step "uv build" uv build --out-dir dist

check_wheel_data() {
    local wheel
    wheel=$(ls -t dist/*.whl 2>/dev/null | head -1)
    if [ -z "$wheel" ]; then
        echo "no wheel found in dist/"
        return 1
    fi
    uv run --no-sync python3 -c "
import sys, zipfile
wheel = sys.argv[1]
required = ('data/templates/', 'data/services/', 'data/images/', 'data/lab/')
names = zipfile.ZipFile(wheel).namelist()
missing = [r for r in required if not any(f'/{r}' in n for n in names)]
if missing:
    print(f'{wheel}: missing {missing} — an installed wheel could not render '
          'a policy or build an image without a checkout')
    sys.exit(1)
print(f'{wheel}: carries {\", \".join(required)}')
" "$wheel"
}
step "wheel carries data/" check_wheel_data

# -- the unit suite, against the real install rather than a sandbox stub ----

step "unit suite (216 tests)" uv run --no-sync python -m unittest discover -s tests -t .

# -- rendered configs still match the committed ones under a real toolchain -

step "ipl policy --check" uv run --no-sync ipl policy --check
step "ipl-lab policy --check" uv run --no-sync ipl-lab policy --check

# -- what only a real container runtime can prove -----------------------

step "ipl-verify loopback" uv run --no-sync ipl-verify loopback --backend "$BACKEND" --port 18089
step "ipl-verify backend" uv run --no-sync ipl-verify backend --backend "$BACKEND" --port 18089
step "ipl-verify resilience" uv run --no-sync ipl-verify resilience --backend "$BACKEND" --port 18089
step "ipl-verify sandbox" uv run --no-sync ipl-verify sandbox

# -- summary ------------------------------------------------------------

echo
if [ ${#FAILED[@]} -eq 0 ]; then
    echo "all steps passed"
    exit 0
fi
echo "${#FAILED[@]} step(s) FAILED: ${FAILED[*]}"
exit 1
