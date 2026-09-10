# Security model

## What this service defends against

The client is assumed hostile: a coding agent (or code it wrote) running
inside a sandbox (such as [project-sandbox](https://github.com/pkrusche/project-sandbox)) 
with `HTTP_PROXY`/`HTTPS_PROXY` pointed here and
all other egress dropped by iptables. The proxy's job is to limit where
that client can connect:

* only allowlisted Internet hostnames;
* never private, loopback, link-local or metadata addresses — including via
  DNS tricks (public hostname → private A/AAAA record, rebinding, mixed
  answers);
* no CONNECT tunnel abuse **where the engine supports detecting it** — SNI
  ↔ CONNECT target mismatch (domain fronting) and non-TLS bytes inside a
  tunnel. Pipelock does unconditionally; Squid does too when
  `--tls-interception` is on ([tls-interception.md](tls-interception.md));
  Smokescreen never does. Iron examines SNI in passthrough mode, but permits
  HTTP inside CONNECT and does not require CONNECT-target/SNI equality;
  see its measured results and [Iron notes](tls-interception.md#iron).

## What it does not defend against

* **Exfiltration to an allowed destination.** By default the proxy cannot see
  encrypted request bodies. Even with interception, the shipped policy does
  not prohibit uploads or restrict an allowed service to a particular account. If
  `github.com` is allowed, data can be pushed to any reachable GitHub
  repository; this service controls destinations only. Turning on
  `--tls-interception` ([tls-interception.md](tls-interception.md)) enables inspection but does not
  itself close this gap, and requires the engine to custody a private key
  and every connected sandbox needing that CA in its trust store
* Anything reachable without traversing the proxy. Preventing direct egress
  is the responsibility of the sandbox.
* Malicious content in allowed responses.

## Fail-closed properties

* `up` regenerates policy files from validated `config.toml` before start,
  so a hand edit cannot change the policy it runs.
* `up` refuses to start on an image that has not been built.
* Every image is pinned in its own Dockerfile — an explicit base tag or
  manifest digest, an exact apk version, a full commit SHA. The unit suite
  refuses a floating `FROM`, a `latest` tag, an unpinned `apk add`, and a
  tag constant that no longer matches the pin its Dockerfile names.
* `up` refuses the endpoint when an unknown process occupies it.
* The post-start health check requires the proxy to *deny* a
  non-allowlisted probe host; a proxy that answers 2xx/3xx for it is
  treated as broken, not healthy. Health requires an attributable policy
  denial; a DNS/origin 5xx is inconclusive and fails startup.
* Open modes and private-range escape hatches are absent from the fixed
  templates. Pipelock is rendered in strict mode, Smokescreen in enforce
  mode, and Squid ends in default deny. `--tls-interception` selects
  complete CA-backed recipes for Pipelock, Squid and Iron; partial states are not
  generated ([tls-interception.md](tls-interception.md)).
* `up` refuses to start an engine with `--tls-interception` and no CA
  generated yet, and the CA's private key is written `0600` at creation
  time (never `chmod`ed after), so there is no window where it is
  world-readable.
* A destination written as a bare address is refused by Squid before the
  allowlist is consulted, because Squid would otherwise retry the miss as a
  reverse lookup and match whatever name the address's PTR record claims.
* For Squid, where the SSRF floors are configuration rather than engine
  code, the fixed template places the required deny ranges above the
  allowlist — `http_access` is first-match-wins, so rule order *is* the
  policy. The lab checks exercise the resulting behavior.
* If the proxy container dies, nothing listens on `127.0.0.1:18080` — the
  sandbox loses Internet rather than gaining unfiltered access. There is no
  automatic restart policy; restarts are explicit.

## The adversarial suite

`src/internet_proxy_locally/checks/egress/` runs identically against every engine and emits
comparable text or `--json` results — one check per file, assembled in order
by `checks/egress/catalogue.py`.

```bash
ipl check     # ordinary allow/deny behavior, against the live proxy
ipl-lab up && ipl-lab check    # the full adversarial suite (docs/lab.md)
```

See [lab.md](lab.md).

Each result carries, where relevant: a best-effort denial-cause
classification (`hostname-not-allowlisted`, `private-ip`, `metadata`,
`sni-mismatch`, `non-tls-in-tunnel`, `port-not-allowed`, `dns-failure`,
`unparseable-destination`, `timeout`, `proxy-access-denied`,
`unknown`), timing, per-attempt
evidence, response headers on the allow-path checks, decoded TLS alert
records rather than raw bytes for the tunnel-abuse checks, and the engine's
own log lines for that test's exact window.

`classify_denial()`'s accuracy against each engine's real wording is pinned
by `tests/egress/test_denial.py::ClassifyDenialRealWordingTest`. Its patterns match
a **stated reason** only — never an address the engine echoes back, and
never a reason word the checker itself wrote. Both were real bugs: an engine
reports `domain not in allowlist: 127.0.0.1`, so a pattern for a bare
`127.0.0.1` reads the *target* and mislabels a plain allowlist denial as
`private-ip`. Attempts are classified individually and then combined,
because classifying concatenated text reports whichever bucket comes first
in the taxonomy rather than what the set actually contained.

`proxy-access-denied` records an explicit Squid access-denial response inside
TLS. Un-attributable closures and TLS failures are inconclusive, not policy
passes. Iron's DNS/private-address probes can use an explicit IP refusal
from the same CONNECT transaction in the current check's audit-log window.
The result retains the client error and identifies the log-based evidence;
missing, ambiguous, stale, or conflicting evidence cannot produce a pass.
The historical `aborted-after-connect` cause remains readable for
older measurements. See
[tls-interception.md](tls-interception.md#late-denials-and-how-the-suite-grades-them).

Measured results: [findings.md](findings.md).

## Endpoint exposure and logging

The container publishes `127.0.0.1:18080` only. 

Engine logs are the audit trail (`ipl logs`). Depending on engine and mode they
can contain full URLs and query strings, targets, verdicts, and denial reasons.
Plain HTTP is visible with interception off. The shipped configuration does not
deliberately log bodies/headers, but makes no general redaction guarantee.

Runtime retention is operator-controlled; treat logs as sensitive. With
interception on, the engine sees decrypted requests — see
[tls-interception.md](tls-interception.md) for what changes.
