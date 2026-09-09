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
            [ $# -ge 2 ] || { echo "--engine requires pipelock, smokescreen or squid" >&2; exit 2; }
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
    pipelock|smokescreen|squid) ;;
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

cleanup() {
    uv run --no-sync ipl --backend "$backend" down >/dev/null 2>&1 || true
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

trap - EXIT
