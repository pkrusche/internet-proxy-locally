#!/usr/bin/env bash
# Release gate for static checks, packages, live containers, and TLS interception.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

backend="${1:-docker}"
case "$backend" in
    docker|container) ;;
    *) echo "usage: $0 [docker|container]" >&2; exit 2 ;;
esac
command -v "$backend" >/dev/null || { echo "$backend is not installed" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is not installed" >&2; exit 1; }
export IPL_ENDPOINT="${IPL_ENDPOINT:-127.0.0.1:18089}"

passed=()
failed=()
skipped=()
passed_count=0
failed_count=0
skipped_count=0
sentinel="UNTRACKED-RELEASE-SENTINEL"
tmp="$(mktemp -d)"
release_root="$tmp/workspace"
release_ca="$tmp/release-ca.pem"
rotated_ca="$tmp/rotated-ca.pem"

cleanup() {
    uv run --no-sync ipl --backend "$backend" down >/dev/null 2>&1 || true
    rm -f "$sentinel"
    rm -rf "$tmp"
}
trap cleanup EXIT

run_step() {
    local label="$1"
    shift
    echo "=== $label"
    if "$@"; then
        passed+=("$label")
        passed_count=$((passed_count + 1))
        echo "PASS: $label"
        return 0
    else
        local rc=$?
        failed+=("$label (exit $rc)")
        failed_count=$((failed_count + 1))
        echo "FAIL: $label (exit $rc)" >&2
        return "$rc"
    fi
}

skip_step() {
    skipped+=("$1")
    skipped_count=$((skipped_count + 1))
    echo "SKIP: $1"
}

static_checks() {
    uv run --frozen ruff check . &&
        uv run --frozen ruff format --check . &&
        uv run --frozen ty check
}

unit_tests() {
    uv run --frozen python -m unittest discover -s tests -t .
}

package_artifacts() {
    printf 'must not ship\n' > "$sentinel" || return
    rm -rf dist || return
    uv build --out-dir dist || return

    local wheel=(dist/*.whl)
    local sdist=(dist/*.tar.gz)
    [ "${#wheel[@]}" -eq 1 ] && [ -f "${wheel[0]}" ] || return
    [ "${#sdist[@]}" -eq 1 ] && [ -f "${sdist[0]}" ] || return
    scripts/check-artifacts.py "${wheel[0]}" "${sdist[0]}" || return
    tar -tzf "${sdist[0]}" >"$tmp/sdist-members" || return
    unzip -l "${wheel[0]}" >"$tmp/wheel-members" || return
    ! grep -F "$sentinel" "$tmp/sdist-members" || return
    ! grep -F "$sentinel" "$tmp/wheel-members" || return

    uv venv --python 3.11 "$tmp/venv" || return
    uv pip install --python "$tmp/venv/bin/python" "${wheel[0]}" || return
    (
        cd "$tmp" || exit
        "$tmp/venv/bin/ipl" --version &&
            "$tmp/venv/bin/ipl-lab" --help >/dev/null &&
            "$tmp/venv/bin/ipl-check" --help >/dev/null
    )
}

prepare_release_workspace() {
    mkdir -p "$release_root/docs" || return
    cp config.toml "$release_root/config.toml" || return
    # Includes the hand-maintained Smokescreen daemon config, which rendering
    # cannot recreate. Never copy state/ or an existing interception CA.
    cp -R config "$release_root/config" || return
    cp docs/findings.md "$release_root/docs/findings.md" || return
    export IPL_ROOT="$release_root"
}

ipl() {
    uv run --no-sync ipl --backend "$backend" "$@"
}

initialize_release_ca() {
    ipl ca init || return
    ipl ca export --out "$release_ca" || return
    [ -s "$release_ca" ]
}

expect_certificate_rejection() {
    local label="$1" diagnostic="$2" rc
    shift 2
    if "$@" 2>"$diagnostic"; then
        echo "error: $label unexpectedly succeeded" >&2
        return 1
    else
        rc=$?
    fi
    if [ "$rc" -eq 60 ]; then
        echo "$label: certificate verification rejected the connection"
        return 0
    fi
    echo "error: $label failed with curl exit $rc, expected certificate verification failure (60)" >&2
    cat "$diagnostic" >&2
    return 1
}

check_denied_destination() {
    local engine="$1" proxy="$2" codes curl_rc connect_code http_code
    codes="$(curl --disable --silent --show-error --max-time 60 --connect-timeout 15 \
        --proxy "$proxy" --noproxy "" --cacert "$release_ca" \
        --output "$tmp/$engine-denied.body" --dump-header "$tmp/$engine-denied.headers" \
        --write-out '%{http_connect} %{http_code}' https://example.com \
        2>"$tmp/$engine-denied.err")"
    curl_rc=$?
    read -r connect_code http_code <<< "$codes"
    case "$connect_code" in
        4??)
            echo "$engine: blocked example.com with CONNECT status $connect_code"
            return 0
            ;;
    esac
    # Squid can acknowledge CONNECT, then send its explicit policy denial
    # inside TLS. A generic origin 403 does not prove proxy enforcement.
    if [ "$curl_rc" -eq 0 ] && [ "$connect_code" = 200 ] && [ "$http_code" = 403 ]; then
        if grep -Fq 'internet-proxy-locally denied this request:' "$tmp/$engine-denied.body" ||
            grep -Eiq '^X-Squid-Error: *ERR_ACCESS_DENIED([[:space:]]|$)' "$tmp/$engine-denied.headers"; then
            echo "$engine: blocked example.com with HTTP 403 inside TLS (CONNECT 200)"
            return 0
        fi
    fi
    echo "error: $engine did not provide a policy denial for example.com (curl exit $curl_rc, CONNECT ${connect_code:-missing}, HTTP ${http_code:-missing})" >&2
    cat "$tmp/$engine-denied.err" "$tmp/$engine-denied.headers" >&2
    head -c 2000 "$tmp/$engine-denied.body" >&2
    return 1
}

tls_curl_check() {
    local engine="$1"
    local proxy="http://${IPL_ENDPOINT:-127.0.0.1:18089}"
    local rc=0
    local curl_args=(
        curl --disable --silent --show-error --max-time 60 --connect-timeout 15
        --proxy "$proxy" --noproxy ""
    )

    ipl --engine "$engine" setup --tls-interception || return
    ipl --engine "$engine" up --tls-interception || return

    expect_certificate_rejection "$engine without CA trust" "$tmp/$engine-untrusted.err" \
        "${curl_args[@]}" --output /dev/null https://github.com || rc=1

    if "${curl_args[@]}" --fail --cacert "$release_ca" \
        --output /dev/null https://github.com; then
        echo "$engine: trusted HTTPS request to github.com succeeded"
    else
        echo "error: $engine failed a trusted HTTPS request to github.com" >&2
        rc=1
    fi

    check_denied_destination "$engine" "$proxy" || rc=1

    ipl down || rc=1
    return "$rc"
}

rotation_check() {
    local proxy="http://${IPL_ENDPOINT:-127.0.0.1:18089}"
    local curl_args=(
        curl --disable --silent --show-error --max-time 60 --connect-timeout 15
        --proxy "$proxy" --noproxy "" --output /dev/null
    )
    local rc=0

    ipl down || return
    ipl ca rotate || return
    ipl ca export --out "$rotated_ca" || return
    if cmp -s "$release_ca" "$rotated_ca"; then
        echo "error: CA rotation did not change the certificate" >&2
        return 1
    fi

    ipl --engine pipelock up --tls-interception || return
    expect_certificate_rejection "pipelock with the pre-rotation CA" "$tmp/pre-rotation-ca.err" \
        "${curl_args[@]}" --cacert "$release_ca" https://github.com || rc=1
    if "${curl_args[@]}" --fail --cacert "$rotated_ca" https://github.com; then
        echo "pipelock: the rotated CA trusts a new connection"
    else
        echo "error: the rotated CA did not trust a new connection" >&2
        rc=1
    fi
    ipl down || rc=1
    return "$rc"
}

lab_measurement() {
    IPL_ROOT="$release_root" uv run --no-sync ipl-lab --backend docker measure
}

print_summary() {
    echo
    echo "=== release summary"
    local label
    for label in ${passed[@]+"${passed[@]}"}; do
        echo "PASS  $label"
    done
    for label in ${failed[@]+"${failed[@]}"}; do
        echo "FAIL  $label"
    done
    for label in ${skipped[@]+"${skipped[@]}"}; do
        echo "SKIP  $label"
    done
    echo "$passed_count passed, $failed_count failed, $skipped_count skipped"
    if [ "$failed_count" -eq 0 ]; then
        echo "RELEASE GATE PASSED"
    else
        echo "RELEASE GATE FAILED"
    fi
}

run_step "static analysis" static_checks || true
run_step "Python unit tests" unit_tests || true
run_step "package artifacts and installed entry points" package_artifacts || true

if run_step "isolated release workspace" prepare_release_workspace; then
    for engine in pipelock smokescreen squid iron; do
        run_step "$engine operational smoke (TLS off)" \
            scripts/smoke.sh --backend "$backend" --engine "$engine" || true
    done

    if run_step "TLS CA initialization and export" initialize_release_ca; then
        for engine in pipelock squid iron; do
            run_step "$engine TLS interception and curl" tls_curl_check "$engine" || true
        done
        run_step "TLS CA rotation and stale-trust rejection" rotation_check || true
    else
        for engine in pipelock squid iron; do
            skip_step "$engine TLS interception and curl (CA initialization failed)"
        done
        skip_step "TLS CA rotation and stale-trust rejection (CA initialization failed)"
    fi

    if [ "$backend" = docker ]; then
        run_step "lab measurement in every supported TLS mode" lab_measurement || true
    else
        skip_step "lab measurement (Docker only)"
    fi
else
    skip_step "live container checks (release workspace failed)"
fi

print_summary
[ "$failed_count" -eq 0 ]
