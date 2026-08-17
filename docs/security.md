# Security model

## What this service defends against

The client is assumed hostile: a coding agent (or code it wrote) running
inside `project-sandbox` with `HTTP_PROXY`/`HTTPS_PROXY` pointed here and
all other egress dropped by iptables. The proxy's job is to limit **where**
that client can connect:

* only allowlisted Internet hostnames;
* never private, loopback, link-local, or metadata addresses — including
  via DNS tricks (public hostname → private A/AAAA record, rebinding,
  mixed answers);
* no CONNECT tunnel abuse **where the engine supports detecting it**
  (SNI ↔ CONNECT target mismatch / domain fronting, non-TLS bytes inside
  a tunnel). Pipelock does; Smokescreen does not — see below.

## What it does not defend against

* **Exfiltration to an allowed HTTPS destination.** Without TLS
  interception the proxy cannot see encrypted request bodies. If
  `github.com` is allowed, data can be pushed to any reachable GitHub
  repository. Interception is out of scope for v1 deliberately — it would
  add a local CA lifecycle and private-key custody, trust-store changes in
  every agent image, and cert-pinning breakage — so this service controls
  destinations only (docs/architecture.md's non-goals). A later experiment
  may revisit it specifically for exfiltration control.
* Anything reachable without traversing the proxy. Preventing direct
  egress is `project-sandbox`'s iptables responsibility.
* Malicious content in allowed responses.

## Fail-closed properties

* `up` refuses to start with an invalid or non-strict policy file.
* `up` refuses unpinned images (no digest / no source SHA) and `latest` tags.
* `up` refuses the endpoint when an unknown process occupies it.
* The post-start health check requires the proxy to *deny* a
  non-allowlisted probe host; a proxy that answers 2xx/3xx for it is
  treated as broken, not healthy. It grades on `status >= 400` rather than
  a specific code, which is what lets one check cover both engines
  (Pipelock denies with `403`, Smokescreen with `407`).
* If the proxy container dies, nothing listens on `127.0.0.1:18080` — the
  sandbox loses Internet rather than gaining unfiltered access. There is
  no automatic restart policy; restarts are explicit (`./run.py restart`).
* Open modes are rejected by validation (`action: open`,
  `--unsafe-allow-private-ranges`, `tls_interception.enabled: true`,
  non-`strict` Pipelock modes).

## The adversarial suite

```bash
./run.py check --quick   # ordinary allow/deny behavior
./run.py up --test-policy && ./run.py check --full
```

`checks/egress.py` runs identically against both engines and emits
comparable text or `--json` results. The full suite covers private
IPv4/IPv6, metadata, DNS-resolved private targets (nip.io / sslip.io
fixtures), DNS rebinding (rbndr.us, recorded with per-attempt evidence),
SNI mismatch, raw bytes inside a CONNECT tunnel, IP-form CONNECT, and a
concurrency sanity check.

Each result carries, where relevant: a best-effort denial-cause
classification (`hostname-not-allowlisted`, `private-ip`, `metadata`,
`sni-mismatch`, `non-tls-in-tunnel`, `timeout`, `unknown`), timing,
per-attempt evidence including what the checker itself resolved each DNS
fixture hostname to, response headers on the allow-path checks, decoded
TLS alert records instead of raw bytes for the tunnel-abuse checks, and
(when run via `./run.py check`, which wires it automatically) the
engine's own log lines for that test's exact window. `checks/egress.py
--diff A.json B.json` prints only the rows that diverge between two prior
`--json` runs.

Measured results are in docs/comparison.md; the 2026-08-17 run there
predates this tooling. Two gaps it exposed are now addressed at the
tooling level, pending a re-run against real engines to confirm in
practice (no network/container runtime in the environment that built
this):

* **The rebinding check.** It used to report an aggregate `denied=N
  established=M` with no way to tell a cached DNS answer from a real
  defence. It now issues a fresh, cache-busted hostname per attempt and
  resolves it locally alongside the CONNECT, so the output says whether
  the fixture varied at all — uniform local answers across six fresh
  hostnames mean a caching resolver, and a uniform engine result is then
  evidence of nothing. It stays `record` rather than graded: `rbndr.us`
  answers each query with one of its two IPs at random, so the checker's
  lookup and the engine's are independent draws and neither an
  established tunnel nor a denial attributes to what the engine resolved.
  A conclusive rebinding grade needs the local DNS fixture below, not
  `rbndr.us`; the graded proof that an allowlisted hostname cannot reach a
  private address remains `dns-private-ipv4`/`ipv6`.
* **A denial's cause.** `classify_denial()` gives a best-effort taxonomy
  bucket per denial (see above) instead of only a status code. Its
  accuracy against real engine wording is unverified here; the engine
  -log-capture feature is the more reliable way to attribute a denial —
  it attaches the actual log lines the engine produced during that test's
  window, so "verify engine logs" is no longer a manual instruction.

### Tunnel-layer enforcement is engine-dependent

Measured: Pipelock rejects both SNI/CONNECT mismatch and non-TLS bytes
inside a tunnel; **Smokescreen allows both**. Under Smokescreen, a client
that can reach an allowlisted host on 443 can speak any protocol to it,
and can present any SNI — so a CDN-fronted allowlist entry effectively
extends to whatever that CDN edge routes by SNI. If tunnel abuse is in
your threat model, this is the reason to keep Pipelock as the engine
(docs/comparison.md).

### Local DNS fixture for mixed answers

Public wildcard-DNS services cannot serve mixed public+private answer
sets reliably. To run the `dns-mixed-answers` test, point the proxy
container at a local dnsmasq with a crafted record, e.g.:

```bash
dnsmasq --no-daemon --port 5353 \
  --host-record=mixed.fixture.test,93.184.216.34,10.0.0.1
```

then add `mixed.fixture.test` to the *test* policy, run the engine with
its DNS pointed at that resolver, and verify the proxy refuses the
connection (an engine picking "just the public answer" silently is a
finding worth recording in docs/comparison.md).

## Endpoint exposure

The container publishes `127.0.0.1:18080` only. That is a convenience
boundary, not the security boundary: the policy remains enforced even for
traffic that reaches the engine's internal address from another local
container. No unauthenticated open-proxy mode exists in the shipped
configuration; client authentication is deferred until multiple caller
identities need different policies (see docs/architecture.md).
