# Security model

## What this service defends against

The client is assumed hostile: a coding agent (or code it wrote) running
inside `project-sandbox` with `HTTP_PROXY`/`HTTPS_PROXY` pointed here and
all other egress dropped by iptables. The proxy's job is to limit **where**
that client can connect:

* only allowlisted Internet hostnames;
* never private, loopback, link-local, or metadata addresses — including
  via DNS tricks (public hostname → private A/AAAA record, rebinding,
  mixed answers). **Smokescreen is measured as non-compliant on the
  mixed-answer case**: given a name resolving to both a public and a
  private address it connects to the public one rather than refusing the
  name (docs/comparison.md, "Mixed DNS answers"). It does not connect to the
  private address, so this is a weaker guarantee rather than an open door,
  but it is a difference worth knowing before choosing that engine;
* no CONNECT tunnel abuse **where the engine supports detecting it**
  (SNI ↔ CONNECT target mismatch / domain fronting, non-TLS bytes inside
  a tunnel). Pipelock does; Smokescreen and Squid do not — see below.

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
  a specific code, which is what lets one check cover every engine
  (Pipelock and Squid deny with `403`, Smokescreen with `407`).
* If the proxy container dies, nothing listens on `127.0.0.1:18080` — the
  sandbox loses Internet rather than gaining unfiltered access. There is
  no automatic restart policy; restarts are explicit (`./run.py restart`).
* Open modes are rejected by validation (`action: open`,
  `--unsafe-allow-private-ranges`, `tls_interception.enabled: true`,
  non-`strict` Pipelock modes, `http_access allow all` and
  `ssl_bump ... bump` for Squid).
* A destination written as a bare address is refused by Squid before the
  allowlist is consulted, because Squid would otherwise retry the miss as
  a reverse lookup and match whatever name the address's PTR record claims
  — a bypass measured and then closed (docs/comparison.md). `ptr-allowlist`
  in the suite guards it, and `up` refuses a policy that drops the rule.
* For Squid, where the SSRF floors are configuration rather than engine
  code, `up` additionally refuses a policy that has lost a required deny
  range or that places the allowlist above those denies — `http_access` is
  first-match-wins, so rule order *is* the policy (docs/policy.md).

## The adversarial suite

```bash
./run.py check --quick   # ordinary allow/deny behavior
./run.py up --test-policy && ./run.py check --full
```

`checks/egress.py` runs identically against every engine and emits
comparable text or `--json` results. The full suite covers private
IPv4/IPv6, metadata, DNS-resolved private targets (nip.io / sslip.io
fixtures), mixed public+private answer sets and DNS rebinding (both from
the local fixture, see below), reverse-DNS allowlist bypass, SNI mismatch, raw bytes inside a CONNECT tunnel, IP-form CONNECT, and a
concurrency sanity check. Nothing skips any more: every row is graded or
deliberately recorded.

Each result carries, where relevant: a best-effort denial-cause
classification (`hostname-not-allowlisted`, `private-ip`, `metadata`,
`sni-mismatch`, `non-tls-in-tunnel`, `port-not-allowed`, `dns-failure`,
`unparseable-destination`, `timeout`, `unknown`), timing,
per-attempt evidence — what the checker itself resolved each public DNS
fixture hostname to, and for the local fixture, the addresses it actually
handed the engine — response headers on the allow-path checks, decoded
TLS alert records instead of raw bytes for the tunnel-abuse checks, and
(when run via `./run.py check`, which wires it automatically) the
engine's own log lines for that test's exact window. `checks/egress.py
--diff A.json B.json` prints only the rows that diverge between two prior
`--json` runs.

Measured results are in docs/comparison.md. The 2026-08-17 run there
predates this tooling; the 2026-08-19 re-run confirmed it against real
Pipelock and Smokescreen, and Squid was measured on 2026-08-25. Two gaps
the original run exposed are addressed at the tooling level:

* **The rebinding check.** It used to report an aggregate `denied=N
  established=M` against `rbndr.us`, with no way to tell a cached DNS
  answer from a real defence — that fixture answered each query with one
  of its two addresses at random, so the checker's lookup and the engine's
  were independent draws and neither outcome attributed to anything. It is
  now graded against the local fixture below, which hands out a private
  address on the second lookup and listens on it, so the grade rests on
  whether the engine connected there rather than on what the checker
  guessed it resolved.
* **A denial's cause.** `classify_denial()` gives a best-effort taxonomy
  bucket per denial (see above) instead of only a status code. Its
  accuracy against each engine's real wording is pinned by
  `tests/test_egress.py::ClassifyDenialRealWordingTest`; the engine
  -log-capture feature remains the more reliable way to attribute a denial —
  it attaches the actual log lines the engine produced during that test's
  window, so "verify engine logs" is no longer a manual instruction.

### Tunnel-layer enforcement is engine-dependent

Measured: Pipelock rejects both SNI/CONNECT mismatch and non-TLS bytes
inside a tunnel; **Smokescreen and Squid allow both**. Under either of
those, a client that can reach an allowlisted host on 443 can speak any
protocol to it and can present any SNI — so a CDN-fronted allowlist entry
effectively extends to whatever that CDN edge routes by SNI. If tunnel
abuse is in your threat model, this is the reason to keep Pipelock as the
engine (docs/comparison.md).

Squid is the interesting case here, because it *can* do this: `ssl_bump
peek` reads the ClientHello without decrypting anything, and `splice`
passes the connection through untouched. That configuration was built and
measured before being rejected — it crashes the daemon on any terminated
peek without a signing CA, needs a private key in the image to avoid
that, and answers every CONNECT with `200` before evaluating policy.
Details and the exact assertion are in docs/comparison.md and at the top
of `config/squid.conf`. Squid's tunnel exposure is a deliberate choice
between two bad options, not an oversight.

One thing Squid does that neither of the others does: it restricts
CONNECT to port 443 (`http_access deny CONNECT !TLS_ports`), so its
tunnels cannot be used as a general-purpose TCP relay to an allowlisted
host on some other port. That narrows the smuggling surface without
looking inside the tunnel.

### The local DNS fixture

Public DNS cannot serve either of the two fixtures the suite needs — a
mixed public+private answer set, or an answer that changes between
lookups — so both run against a container this repository builds and
starts. `./run.py up --test-policy` brings it up,
reads its address, and starts the engine with `--dns <that address>`; a
normal `./run.py up` removes it. It publishes no host port and is never
running under the real policy.

**Mixed answers.** The records live in `config/dns-fixture.hosts`, served
by dnsmasq — a control name with one public address, and two names
carrying one public and one private address in both orderings, so an
engine that validates only the first answer is distinguished from one that
validates all of them. The control must establish before anything is
graded; without it, a denial could not be attributed to mixed-answer
handling and the row skips.

**Rebinding.** dnsmasq delegates `rebind.fixture.test` to a small stdlib
responder (`images/dnsfixture/rebind.py`), which answers the *first* lookup
of a name with a public address and every later one with the fixture's own
private address — where it also listens. Each name is probed twice, with a
pause between the passes, so the second answer is actually handed out; two
probes in the same second are served from one lookup by any resolver cache
with second granularity, and the rebind never happens.

That listener is the point. `dns-rebinding` grades on one thing: whether
anything connected to the trap. "Did the engine reach a private address"
stops being an inference from counts — which is what made the old
`rbndr.us` row ungradable — and becomes an observation by the thing that
would have received the connection. A repeat probe that succeeds while the
trap stays silent is *not* a failure: it means the engine reused the
address it had already validated, which is a legitimate defense. Both
behaviors are recorded, because the engines split on exactly this
(docs/comparison.md, "DNS rebinding").

Two things about this are worth knowing before changing it:

* **A bind-mounted `/etc/hosts` does not work**, though it looks like it
  should. Duplicate names in a hosts file are collapsed to a single
  address by the resolvers involved — musl's `getent hosts` returns the
  first, Squid's own hosts parser keeps the last — so the engine never
  sees more than one address, and the check silently measures which record
  survived. dnsmasq's `--addn-hosts` aggregates them and returns both.
* **`--host-record=name,addr1,addr2` does not give two IPv4 answers.** The
  second slot is the IPv6 address; passing a second IPv4 there replaces
  the first rather than adding to it (measured: the query returns only
  `10.0.0.1`). An earlier revision of this file recommended exactly that
  and would have produced a single-address fixture.

The measured outcome — Pipelock and Squid refuse both orderings,
Smokescreen connects to the public address instead of refusing the name —
is docs/comparison.md, "Mixed DNS answers".

## Endpoint exposure

The container publishes `127.0.0.1:18080` only. That is a convenience
boundary, not the security boundary: the policy remains enforced even for
traffic that reaches the engine's internal address from another local
container. No unauthenticated open-proxy mode exists in the shipped
configuration; client authentication is deferred until multiple caller
identities need different policies (see docs/architecture.md).
