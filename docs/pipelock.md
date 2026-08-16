# Pipelock engine

Default engine (subject to the parity results in docs/comparison.md).
Upstream: <https://github.com/luckyPipewrench/pipelock>.

## Operating mode

Strict standard forward proxy only:

* `mode: strict`, `enforce: true` — default deny, allowlist in
  `api_allowlist`;
* `forward_proxy.enabled: true` — standard `HTTP_PROXY`/`HTTPS_PROXY`
  semantics (absolute-form HTTP + CONNECT);
* `forward_proxy.sni_verification: true` — the TLS ClientHello SNI inside
  a CONNECT tunnel must match the CONNECT target (blocks domain fronting);
* `forward_proxy.sni_require_tls: true` — bytes inside a CONNECT tunnel
  must be TLS (blocks raw protocol smuggling through allowed tunnels);
* MCP / A2A / fetch-API features: unused, nothing routes to them;
* `tls_interception.enabled: false` — see below.

The container runs `run --config /config/pipelock.yaml --listen
0.0.0.0:8888` with the config bind-mounted read-only; the host publishes
`127.0.0.1:18080 → 8888`.

Config keys were taken from the upstream configuration docs at the time
of pinning. **After every version bump, re-validate the keys against the
pinned release's docs** (upstream `docs/configuration.md`) — this is
required by the plan and enforced socially, not mechanically.

## Image and pinning

* `ghcr.io/luckypipewrench/pipelock`, release tag pinned in
  `services/pipelock.toml` (`3.3.0` at time of writing; never `latest`).
  Registry tags are unprefixed — the git tag is `v3.3.0`, the image tag is
  `3.3.0` — and only recent releases stay published, so a stale pin will
  404 on pull;
* the immutable digest is recorded by `./run.py pin pipelock` and required
  by `up`;
* upstream publishes signed, SBOM-backed releases — verify the signature
  of a new release before re-pinning (see upstream release notes for the
  cosign invocation);
* multi-arch (amd64/arm64) per upstream packaging; confirm on first pull
  per platform.

## TLS interception

Disabled for v1, deliberately: no local CA lifecycle, no CA private-key
custody, no trust-store changes in agent images, no cert-pinning
breakage, simpler debugging, smaller surface. Accepted consequence: no
HTTPS request-body inspection — destination control only (docs/security.md).
A later experiment may evaluate interception specifically for
exfiltration control to allowlisted domains.

## Logging and privacy

Pipelock can emit rich audit evidence (signed action receipts, scan
verdicts). For this deployment:

* only default denial/access logging is intended; do not enable receipt
  signing or additional evidence stores without understanding what they
  persist (hostnames, URLs, timestamps, volumes — and potentially more);
* no implicit telemetry: anything beyond stdout logs must be an explicit,
  reviewed config change;
* logs are viewed with `./run.py logs` and live only in the container's
  log stream (removed by `down`/recreate).

No provider API keys exist anywhere in this service, by design.
