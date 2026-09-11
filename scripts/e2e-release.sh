#!/usr/bin/env bash
# Release gate for static checks, Python tests, artifacts, and live containers.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

backend="${1:-docker}"
case "$backend" in docker|container) ;; *) echo "usage: $0 [docker|container]" >&2; exit 2;; esac
command -v "$backend" >/dev/null || { echo "$backend is not installed" >&2; exit 1; }

uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen ty check
uv run --frozen python -m unittest discover -s tests -t .

sentinel="UNTRACKED-RELEASE-SENTINEL"
trap 'rm -f "$sentinel"' EXIT
printf 'must not ship\n' > "$sentinel"
rm -rf dist
uv build --out-dir dist
wheel=(dist/*.whl); sdist=(dist/*.tar.gz)
[ "${#wheel[@]}" -eq 1 ] && [ "${#sdist[@]}" -eq 1 ]
scripts/check-artifacts.py "${wheel[0]}" "${sdist[0]}"
! tar -tzf "${sdist[0]}" | grep -F "$sentinel"
! unzip -l "${wheel[0]}" | grep -F "$sentinel"

tmp="$(mktemp -d)"; trap 'rm -f "$sentinel"; rm -rf "$tmp"' EXIT
uv venv --python '>=3.11' "$tmp/venv"
uv pip install --python "$tmp/venv/bin/python" "${wheel[0]}"
cd "$tmp"
"$tmp/venv/bin/ipl" --version
"$tmp/venv/bin/ipl-lab" --help >/dev/null
"$tmp/venv/bin/ipl-check" --help >/dev/null
cd -

for engine in pipelock smokescreen squid iron; do
  scripts/smoke.sh --backend "$backend" --engine "$engine"
done
echo "Run TLS fixture/rotation cases per docs/tls-interception.md; both modes are required."
