# Pipelock vs Smokescreen — measured comparison

The default-backend decision is empirical: run the same suite against both
engines and record the results here. Feature tables alone do not decide it.

> **Re-run 2026-08-19** with the richer `checks/egress.py` collection
> (TODO.md §1) on the **Docker** backend, both engines. Every denial now
> carries an attributed cause — no row reads `unknown` on either engine —
> and the previously "unattributed" `allowed-http` difference (finding 5)
> is resolved. The re-run also invalidated two things the 2026-08-17 run
> had scored as passes; see findings 1 and 6.

## Measurement conditions

| | |
| --- | --- |
| Date | 2026-08-17 (original), 2026-08-19 (re-run) |
| Host | macOS 26.6.1, arm64 (Apple Silicon) |
| Backend | Apple `container` (2026-08-17); Docker 29.7.2 (2026-08-19) |
| Pipelock | `ghcr.io/luckypipewrench/pipelock:3.3.0` @ `sha256:42b58a42…b011f7` |
| Smokescreen | local build from `stripe/smokescreen` @ `131fba29ce1e` |
| Policy | test policy (`up --test-policy`) — DNS fixtures allowlisted |
| Command | `./run.py check --full` |

## How to reproduce

```bash
./run.py --engine pipelock setup
./run.py --engine pipelock up --test-policy
./run.py check --full --json > results/pipelock-$(date +%Y%m%d).json

./run.py --engine smokescreen setup
./run.py --engine smokescreen up --test-policy
./run.py check --full --json > results/smokescreen-$(date +%Y%m%d).json

./run.py up   # back to the real policy
```

## Results

Both runs exit 0. Pipelock: `15 pass, 2 record, 1 skip`. Smokescreen:
`13 pass, 4 record, 1 skip`.

**The pass-count difference is a grading change, not a behavior
difference.** `ENGINE_EXPECTATIONS` in `checks/egress.py` grades
`connect-sni-mismatch` and `connect-raw-tunnel` as `deny` for Pipelock but
`record` for Smokescreen, so those two move out of the graded pool. Both
engines pass an identical set of **13 graded checks**.

Outcomes below are stable across both runs. The bracketed values are the
**attributed cause** from the 2026-08-19 re-run — what the engine said it
was rejecting, not what the check is named after. Several rows pass for a
reason other than the one the check implies; that is finding 1.

| Check | Pipelock | Smokescreen | Notes |
| --- | --- | --- | --- |
| allowed-http | PASS (200) | PASS (301) | attributed in finding 5 |
| allowed-https | PASS | PASS | TLSv1.3, SNI = CONNECT target |
| blocked-host-connect | PASS (403) [allowlist] | PASS (407) [allowlist] | |
| blocked-host-http | PASS (403) [allowlist] | PASS (407) [allowlist] | |
| direct-ip-connect | PASS [allowlist] | PASS [allowlist] | *not* IP-layer logic |
| loopback-ipv4 | PASS [allowlist] | PASS [allowlist] | *not* IP-layer logic |
| rfc1918-ipv4 | PASS [allowlist] | PASS [allowlist] | 10/192.168/172.16 all denied |
| link-local-ipv4 | PASS [allowlist] | PASS [allowlist] | *not* IP-layer logic |
| metadata-endpoint | PASS [allowlist] | PASS [allowlist] | denied for both CONNECT and GET; *not* metadata logic |
| loopback-ipv6 | PASS [allowlist] | PASS [**unparseable**] | see finding 1 |
| private-ipv6 | PASS [allowlist] | PASS [**unparseable**] | `fd00::1`, `fe80::1` |
| dns-private-ipv4 (nip.io) | PASS [private-ip + metadata] | PASS [private-ip] | **allowlisted** hostname → private IP, denied |
| dns-private-ipv6 (sslip.io) | PASS [private-ip] | PASS [private-ip] | fixture corrected — finding 6 |
| dns-rebinding (rbndr.us) | RECORD 6× dns-failure | RECORD 6× dns-failure | fixture is gone — see below |
| dns-mixed-answers | SKIP | SKIP | needs the local dnsmasq fixture |
| connect-sni-mismatch | PASS (denied) | RECORD **allowed** | **discriminator** |
| connect-raw-tunnel | PASS (denied) | RECORD **allowed** | **discriminator** |
| concurrency-sanity | RECORD 10/10 | RECORD 10/10 | |

## Findings

### 1. Enforcement is equivalent, but most rows prove less than their names suggest

Every deny floor holds on both engines: unknown hostname, bare IP,
loopback, RFC1918, link-local, cloud metadata, IPv6 loopback/private.
That much was already known on 2026-08-17. What the 2026-08-19 causes add
is *why* each one held, and the answer is not what the check names imply.

**The direct-IP-literal rows are allowlist denials, not IP-layer
denials.** Asked to CONNECT to `127.0.0.1:80`, Pipelock answers `domain
not in allowlist: 127.0.0.1` and Smokescreen answers `default rule policy
used` — neither engine ever reaches its private-IP logic, because a bare
address is not on the allowlist and is rejected on that basis first. The
same is true of `rfc1918-ipv4`, `link-local-ipv4`, `direct-ip-connect`,
`metadata-endpoint` and (on Pipelock) the IPv6 rows. `metadata-endpoint`
is the one to watch: a bare `169.254.169.254` is refused as
not-allowlisted, so the row demonstrates nothing about metadata-specific
handling. The genuine metadata verdict appears only in `dns-private-ipv4`,
where an *allowlisted* hostname resolves there and Pipelock answers
`resolves to cloud metadata endpoint`. Under a default-deny allowlist these rows can
only ever demonstrate the allowlist. They are still worth keeping as
regression guards — an engine that allowed them would be badly broken —
but they are not evidence of SSRF defence.

**Smokescreen never parses the IPv6 literals at all.** `[::1]:80` and
`[fd00::1]:80` are rejected with `Destination host cannot be determined`,
which is a parse failure ahead of any policy evaluation. Its pass on
`loopback-ipv6`/`private-ipv6` therefore says nothing about either its
allowlist or its private-IP handling. This is why `unparseable-destination`
is a separate cause bucket rather than being folded into a generic denial.

**The DNS-fixture checks remain the only real evidence**, and they are
now unambiguous. The fixture hostnames are *deliberately allowlisted*
under the test policy, so the denial can only have come from re-validating
the resolved IP after DNS — and both engines say so in as many words:

* Pipelock: `SSRF blocked: 10.0.0.1.nip.io resolves to internal IP 10.0.0.1`
* Smokescreen: `no valid IP found among resolved addresses - 10.0.0.1
  denied by rule 'Deny: Private Range'`

Both validate post-resolution, as required by docs/policy.md. That
conclusion is unchanged; it now rests on two rows that state it outright
rather than on nine rows that mostly did not.

### 2. The engines diverge inside the CONNECT tunnel

This is the only substantive behavioral difference, and it is a capability
gap rather than a misconfiguration.

**SNI mismatch.** CONNECT to `pypi.org:443`, then send a ClientHello for
`files.pythonhosted.org`:

* Pipelock closes the connection at the ClientHello
  (`SSL: UNEXPECTED_EOF_WHILE_READING`) — `forward_proxy.sni_verification`.
* Smokescreen completes the TLSv1.3 handshake. It authorizes the CONNECT
  target and then goes blind; it never reads the ClientHello.

Both hosts are allowlisted, so this is not a policy bypass on its face.
The exposure is that the destination is then chosen by the *CDN*: both of
those hosts are Fastly-fronted, so allowlisting one Fastly-fronted domain
effectively reaches whatever else that edge will route by SNI.

**Raw protocol smuggling.** CONNECT to `pypi.org:443`, then send plaintext
HTTP bytes:

* Pipelock closes the tunnel with no response — `forward_proxy.sni_require_tls`.
* Smokescreen forwards the bytes. The reply was
  `\x15\x03\x03\x00\x02\x022` + `\x15\x03\x03\x00\x02\x01\x00` — two TLS
  alert records: `fatal(2) decode_error(50)`, then `warning(1)
  close_notify(0)`. **That rejection came from pypi.org, not the proxy.**
  The bytes made the full round trip; only the destination's own
  strictness stopped them.

Smokescreen therefore forwards arbitrary protocols to any allowlisted host
on port 443. Whether that matters depends on whether tunnel-layer abuse is
in scope — see docs/security.md.

### 3. The rebinding measurement is inconclusive on both engines

**As of 2026-08-19 the fixture is gone.** `rbndr.us` no longer resolves
at all from the measurement host — not the generated names, not the apex
domain — while `nip.io` and `sslip.io` resolve normally. All six attempts
on both engines are now `dns-failure`:

* Pipelock: `DNS lookup for 01010101.7f000002.rbndr.us returned no such host`
* Smokescreen: `502 Failed to resolve remote hostname: lookup …`

Six identical NXDOMAINs are not a rebinding measurement. The per-attempt
evidence is what makes that legible: without it these would appear as six
denials on each engine and read as a clean pass. The row is still
`record`, and the conclusion below is unchanged — but the reason is now
simply that the fixture is unavailable, which is a stronger argument for
the local fixture in TODO.md §3 than the original one.

The 2026-08-17 output, for the record, was:

```
pipelock:     denied=0  established=6
smokescreen:  denied=6  established=0
```

Tempting to read as a Smokescreen win. It is not — this output cannot
establish that. `rbndr.us` alternates between `127.0.0.1` and `1.1.1.1`
per query, so genuine per-connection resolution should trend toward ~3/3
on either engine. A clean 6/0 in *either direction* is the signature of a
cached answer being reused: Pipelock's resolver pinned the public IP (6
legitimate tunnels), Smokescreen's pinned loopback (6 correct denials).
**Neither run actually exercised a rebind.**

This is exactly why the check is graded `record`, and why it stays that
way: each `rbndr.us` query is an independent random draw, so nothing the
checker resolves can attribute the engine's outcome. The current tooling
makes the ambiguity visible rather than implicit — fresh hostname per
attempt, each attempt's local resolution recorded, and an explicit note
when a caching resolver flattened the fixture. Making the row *conclusive*
needs the local DNS fixture (TODO.md §3). The evidence that both engines
block loopback-behind-a-hostname is `dns-private-ipv4`/`ipv6`, not this
row.

### 4. Denial status codes are engine-specific

Pipelock answers `403 Forbidden`. Smokescreen answers `407 Proxy
Authentication Required` ("Request rejected by proxy" on CONNECT).

407 is semantically wrong for a policy denial — it instructs the client to
retry with credentials, and some HTTP clients will prompt or retry-loop
rather than surface the block. It is upstream Smokescreen behavior, not
something this repository configures.

This validated one design decision: `probe_proxy()` in `run.py` grades the
post-start health check on `status >= 400` rather than matching a specific
code, so it accepted the 407 as healthy with no engine-specific branch.

### 5. Attributed: `allowed-http` returned 200 vs 301

The difference persisted into the 2026-08-19 re-run, and the captured
response headers attribute it to the upstream tier that answered, not to
either proxy:

| | Pipelock (200) | Smokescreen (301) |
| --- | --- | --- |
| `Server` | `gunicorn` | `Varnish` |
| `Location` | — | `https://pypi.org/` |
| `X-Served-By` | 4 Fastly hops, origin-backed | 1 Fastly hop |

Smokescreen's request was answered at the Fastly edge with the ordinary
HTTP→HTTPS redirect; Pipelock's reached pypi.org's origin (`gunicorn`)
through a longer cache chain. Nothing in `config/pipelock.yaml` requests
redirect-following, and neither engine rewrote the request. Both pass
(`< 400`) and it does not affect the decision.

This is CDN behavior as originally suspected, now with the evidence to
say so. One residual question is worth a targeted test if it ever
matters: a plain-HTTP request to a Fastly-fronted host returning `200`
from origin rather than a redirect is unusual enough that confirming
Pipelock does not normalize the upstream request would close it properly.

### 6. The IPv6 DNS fixture was invalid and had never run

`dns-private-ipv6`'s loopback target was `--1.sslip.io`. It resolves to
`::1` and looks correct, but a DNS label may not begin with two hyphens —
it is a reserved IDNA form. Both engines rejected the *name*, never the
address:

* Smokescreen: `invalid domain "--1.sslip.io": idna: invalid label "--1"`
* Pipelock: `DNS lookup for --1.sslip.io returned no such host`

The check still scored `pass`, because a denial was all it asked for. So
one third of the IPv6 SSRF evidence — the loopback case specifically —
had been vacuous since the fixture was written, on both engines and in
the 2026-08-17 run too. The target is now `0--1.sslip.io`, the equivalent
valid spelling of the same address, and both engines reach the intended
check: Pipelock reports `SSRF blocked … resolves to internal IP`, and the
row's cause is `private-ip` on both.

The classifier is what surfaced this: the attempt was the only one in
either run that would not classify, and `unknown` on a passing row was
the thing worth pulling on.

## Not yet measured

* `dns-mixed-answers` — needs the dnsmasq fixture in docs/security.md.
* Crash → fail-closed (kill the container, confirm the sandbox loses
  Internet rather than gaining unfiltered access).
* `./run.py restart` behavior.
* Startup time, image size, resource usage, upgrade friction.

The Docker backend was exercised end to end on 2026-08-19 (setup → up →
`check --full`, both engines) and is no longer an open item. It did
surface one backend-specific defect: Docker publishes the host port as
soon as the container is created, so the post-start health probe could
connect seconds before the engine was listening behind it and `up` failed
with `non-HTTP response: ''` on a proxy that was in fact healthy. Apple
`container` does not accept early, which is why the 2026-08-17 run never
hit it. `probe_proxy()` now distinguishes a not-ready-yet probe (retried
until the deadline) from a real verdict; a proxy that *answers* and allows
the probe is still an immediate failure and is never retried.

## Decision

**Pipelock remains the default** (`DEFAULT_ENGINE` in `run.py`), and the
reasoning is now measured rather than hypothesised: the two engines are
interchangeable for every graded check, and part company only after
CONNECT succeeds. Pipelock inspects the tunnel's first bytes; Smokescreen
does not.

**Smokescreen remains a viable fallback.** It passed every graded check.
Choosing it means accepting that tunnel contents to allowlisted hosts are
unconstrained — a reasonable trade if operational maturity matters more
than domain-fronting and smuggling resistance for a given deployment.

Revisit if the rebinding check is made conclusive (TODO.md) and the two
engines then differ.
