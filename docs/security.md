# Security model

## What this service defends against

The client is assumed hostile: a coding agent (or code it wrote) running
inside `project-sandbox` with `HTTP_PROXY`/`HTTPS_PROXY` pointed here and
all other egress dropped by iptables. The proxy's job is to limit **where**
that client can connect:

* only allowlisted Internet hostnames;
* never private, loopback, link-local or metadata addresses — including via
  DNS tricks (public hostname → private A/AAAA record, rebinding, mixed
  answers);
* no CONNECT tunnel abuse **where the engine supports detecting it** — SNI
  ↔ CONNECT target mismatch (domain fronting) and non-TLS bytes inside a
  tunnel. Pipelock does; Smokescreen and Squid do not.

Two of those are engine-dependent, which is why the engine choice is a
security decision and not a preference. **Smokescreen is measured as
non-compliant on mixed DNS answers**: given a name resolving to both a
public and a private address it connects to the public one rather than
refusing the name. It does not connect to the private address, so this is a
weaker guarantee rather than an open door — but the suite *records* that row
rather than failing it, so a green run on Smokescreen is not a claim of
compliance here. Both points are measured in
[findings.md](findings.md) (§1, §2), which is what to read before choosing
an engine other than the default.

## What it does not defend against

* **Exfiltration to an allowed HTTPS destination.** Without TLS
  interception the proxy cannot see encrypted request bodies. If
  `github.com` is allowed, data can be pushed to any reachable GitHub
  repository. This service controls destinations only.
* Anything reachable without traversing the proxy. Preventing direct egress
  is `project-sandbox`'s iptables responsibility — and
  `scripts/verify_sandbox.py` records that, as installed here, it does not
  yet route through this proxy at all.
* Malicious content in allowed responses.

## Non-goals

Deliberately out of scope, so that the surface stays small enough to
reason about: TLS interception, managing a private CA, inspecting HTTPS
bodies. Interception would add a local CA lifecycle and private-key
custody, trust-store changes in every agent image, and cert-pinning
breakage; a later experiment may revisit it specifically for exfiltration
control. It is also why `ssl_bump` stays out of the Squid configuration
([findings.md](findings.md), "Rejected: tunnel peeking on Squid").

Also out of scope: replacing Agentgateway, proxying MCP or AI-provider
credentials, transparent networking, redirecting arbitrary TCP, Docker
Compose, one proxy container per sandbox, shared per-project container
networks, fleet management, exposing the proxy to the LAN, and accepting
dynamic domain changes from `project-sandbox`.

Client authentication is deferred until multiple caller identities need
different policies. v1 has one.

## Fail-closed properties

* `up` refuses to start with an invalid or non-strict policy file.
* `up` refuses unpinned images (no digest / no source SHA) and `latest`
  tags.
* `up` refuses the endpoint when an unknown process occupies it.
* The post-start health check requires the proxy to *deny* a
  non-allowlisted probe host; a proxy that answers 2xx/3xx for it is
  treated as broken, not healthy. It grades on `status >= 400` rather than
  a specific code, which is what lets one check cover every engine
  (Pipelock and Squid deny with `403`, Smokescreen with `407`).
* Open modes are rejected by validation: `action: open`,
  `--unsafe-allow-private-ranges`, `tls_interception.enabled: true`,
  non-`strict` Pipelock modes, `http_access allow all` and
  `ssl_bump ... bump` for Squid.
* A destination written as a bare address is refused by Squid before the
  allowlist is consulted, because Squid would otherwise retry the miss as a
  reverse lookup and match whatever name the address's PTR record claims —
  a bypass measured and then closed ([findings.md](findings.md) §5).
  `ptr-allowlist` guards it, and `up` refuses a policy that drops the rule.
* For Squid, where the SSRF floors are configuration rather than engine
  code, `up` additionally refuses a policy that has lost a required deny
  range or that places the allowlist above those denies — `http_access` is
  first-match-wins, so rule order *is* the policy.
* If the proxy container dies, nothing listens on `127.0.0.1:18080` — the
  sandbox loses Internet rather than gaining unfiltered access. There is no
  automatic restart policy; restarts are explicit.

  **Measured 2026-08-28** (`scripts/verify_resilience.py`, all three
  engines): with two request streams running continuously — one for an
  allowlisted host, one for a denied host — the container was removed
  mid-load and then restarted. The endpoint stopped accepting the moment
  the engine died, the allowed stream broke and recovered, and across the
  whole run **not one request for the denied host ever succeeded**. That
  last point is the property: the danger in a crash or a restart is not the
  outage, it is a half-started engine accepting connections before its
  policy is loaded, and that window was never observed.

## The adversarial suite

`checks/egress.py` runs identically against every engine and emits
comparable text or `--json` results.

```bash
./run.py check     # ordinary allow/deny behavior, against the live proxy
./lab.py up && ./lab.py check    # the full adversarial suite (docs/lab.md)
```

The full group covers private IPv4/IPv6, metadata, DNS-resolved private
targets, mixed public+private answer sets, DNS rebinding, reverse-DNS
allowlist bypass, SNI mismatch, raw bytes inside a CONNECT tunnel, IP-form
CONNECT, and a concurrency sanity check. Nothing skips: every row is graded
or deliberately recorded. It needs the test policy and the DNS fixture,
which is why it lives in the other lane — [lab.md](lab.md).

Each result carries, where relevant: a best-effort denial-cause
classification (`hostname-not-allowlisted`, `private-ip`, `metadata`,
`sni-mismatch`, `non-tls-in-tunnel`, `port-not-allowed`, `dns-failure`,
`unparseable-destination`, `timeout`, `unknown`), timing, per-attempt
evidence, response headers on the allow-path checks, decoded TLS alert
records rather than raw bytes for the tunnel-abuse checks, and the engine's
own log lines for that test's exact window.

`classify_denial()`'s accuracy against each engine's real wording is pinned
by `tests/test_egress.py::ClassifyDenialRealWordingTest`. Its patterns match
a **stated reason** only — never an address the engine echoes back, and
never a reason word the checker itself wrote. Both were real bugs: an engine
reports `domain not in allowlist: 127.0.0.1`, so a pattern for a bare
`127.0.0.1` reads the *target* and mislabels a plain allowlist denial as
`private-ip`. Attempts are classified individually and then combined,
because classifying concatenated text reports whichever bucket comes first
in the taxonomy rather than what the set actually contained.

Measured results: [findings.md](findings.md).

## Endpoint exposure

The container publishes `127.0.0.1:18080` only. That is a convenience
boundary, not the security boundary: the policy remains enforced even for
traffic reaching the engine's internal address from another local container.

That binding is one `--publish 127.0.0.1:…` argument, and a backend release
that stopped honouring the address half would widen the endpoint to every
interface silently. `scripts/verify_loopback.py` re-checks it against each
installed runtime — from the runtime's own report of the binding *and* by
confirming the endpoint refuses every non-loopback address this host has —
and is meant to be re-run after a backend upgrade ([lab.md](lab.md)). If a
release ever fails it, the binding must not be widened to compensate.

## Logging

Engine logs are the audit trail (`./run.py logs`). They record request
targets, verdicts and denial reasons — hostnames, not payloads. No request
bodies are captured, because none are decrypted. `forwarded_for delete` in
the Squid configuration keeps the client address internal.
