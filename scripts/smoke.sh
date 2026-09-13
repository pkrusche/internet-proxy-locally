#!/usr/bin/env bash
# Exercise the operational lifecycle against a real container runtime.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

backend=""
engine="pipelock"
skip_setup=0
while [ $# -gt 0 ]; do
    case "$1" in
        --backend)
            [ $# -ge 2 ] || { echo "--backend requires docker or container" >&2; exit 2; }
            backend="$2"
            shift 2
            ;;
        --engine)
            [ $# -ge 2 ] || { echo "--engine requires pipelock, smokescreen, squid or iron" >&2; exit 2; }
            engine="$2"
            shift 2
            ;;
        --skip-setup)
            skip_setup=1
            shift
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

case "$engine" in
    pipelock|smokescreen|squid|iron) ;;
    *) echo "invalid engine: $engine" >&2; exit 2 ;;
esac

if [ -z "$backend" ]; then
    if command -v docker >/dev/null 2>&1; then
        backend="docker"
    elif command -v container >/dev/null 2>&1; then
        backend="container"
    else
        echo "error: no container backend found" >&2
        exit 1
    fi
fi
case "$backend" in
    docker|container) ;;
    *) echo "invalid backend: $backend" >&2; exit 2 ;;
esac
command -v "$backend" >/dev/null || { echo "$backend is not installed" >&2; exit 1; }

export IPL_ENDPOINT="${IPL_ENDPOINT:-127.0.0.1:18089}"
host="${IPL_ENDPOINT%:*}"
port="${IPL_ENDPOINT##*:}"
smoke_results="$(mktemp)"

cleanup() {
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "Smoke failed: engine=$engine backend=$backend exit=$rc" >&2
        if [ -s "$smoke_results" ]; then
            echo "--- quick-check JSON (including per-check evidence) ---" >&2
            cat "$smoke_results" >&2
        fi
        echo "--- bounded container logs before cleanup ---" >&2
        uv run --no-sync python -c '
import sys
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.spec import ServiceSpec
print(Backend(sys.argv[1]).tail_logs(ServiceSpec.load(sys.argv[2]).container_name, lines=40))
' "$backend" "$engine" >&2 || true
    fi
    uv run --no-sync ipl --backend "$backend" down >/dev/null 2>&1 || true
    rm -f "$smoke_results"
    return "$rc"
}
trap cleanup EXIT

if [ "$skip_setup" -eq 0 ]; then
    uv run --no-sync ipl --backend "$backend" --engine "$engine" setup
fi
uv run --no-sync ipl --backend "$backend" --engine "$engine" up

uv run --no-sync python -c '
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
with socket.create_connection((host, port), timeout=2):
    pass
print(f"proxy is listening on {host}:{port}")
' "$host" "$port"

if [ "$engine" = squid ]; then
    sh scripts/check-squid-runtime.sh "$backend" off
fi

check_rc=0
uv run --no-sync ipl --backend "$backend" --engine "$engine" check --json >"$smoke_results" || check_rc=$?
policy_rc=0
uv run --no-sync python -m internet_proxy_locally.release quick "$engine" "$smoke_results" || policy_rc=$?
if [ "$check_rc" -ne 0 ]; then
    echo "Quick check exited $check_rc (release validator exited $policy_rc)" >&2
    exit "$check_rc"
fi
[ "$policy_rc" -eq 0 ] || exit "$policy_rc"

uv run --no-sync ipl --backend "$backend" down
uv run --no-sync python -c '
import sys
from internet_proxy_locally.backend import Backend
from internet_proxy_locally.spec import ServiceSpec

backend, engine = sys.argv[1:]
name = ServiceSpec.load(engine).container_name
state = Backend(backend).container_state(name)
if state != "absent":
    raise SystemExit(f"error: {name} is {state} after ipl down")
print(f"{name} is absent after ipl down")
' "$backend" "$engine"

rm -f "$smoke_results"
trap - EXIT
