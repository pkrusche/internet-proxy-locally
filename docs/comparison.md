# Pipelock vs Smokescreen vs Squid — measured comparison

The default-backend decision is empirical: run the same suite against every
engine and record the results here. Feature tables alone do not decide it.

> **`dns-mixed-answers` is now a graded check** (2026-08-25, all three
> engines, Apple `container`). It was the last unconditional `skip` in the
> suite. **Smokescreen fails it**: given a name resolving to both a public
> and a private address it connects to the public one instead of refusing
> the name, which is a documented deviation from docs/policy.md and the
> only graded failure any engine has ever produced here. Pipelock and Squid
> refuse both orderings. Finding 9 has the evidence and finding 11 the
> decision it forces.
>
> Finding 9 also **corrects an earlier claim in this file**: the
> 2026-08-25 `/etc/hosts` experiment did not show what it was said to show.

> **Squid added 2026-08-25** (Apple `container`, macOS arm64). Two things
> distinguish it, in opposite directions: its SSRF floors are configuration
> rather than engine code — which makes several rows attribute to the IP
> layer that read as allowlist denials on the others (finding 7) — and its
> tunnel-layer enforcement is absent for reasons that took a measurement to
> establish (finding 8).

> **Re-run 2026-08-19** with the richer `checks/egress.py` collection
> (TODO.md §1) on the **Docker** backend, both engines. Every denial now
> carries an attributed cause — no row reads `unknown` on either engine —
> and the previously "unattributed" `allowed-http` difference (finding 5)
> is resolved. The re-run also invalidated two things the 2026-08-17 run
> had scored as passes; see findings 1 and 6.

## Measurement conditions

| | |
| --- | --- |
| Date | 2026-08-17 (original), 2026-08-19 (re-run), 2026-08-25 (Squid) |
| Host | macOS 26.6.1, arm64 (Apple Silicon) |
| Backend | Apple `container` (2026-08-17, 2026-08-25); Docker 29.7.2 (2026-08-19) |
| Pipelock | `ghcr.io/luckypipewrench/pipelock:3.3.0` @ `sha256:42b58a42…b011f7` |
| Smokescreen | local build from `stripe/smokescreen` @ `131fba29ce1e` |
| Squid | local build of Alpine `squid=6.12-r0` on `alpine:3.22.1` |
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

./run.py --engine squid setup
./run.py --engine squid up --test-policy
./run.py check --full --json > results/squid-$(date +%Y%m%d).json

./run.py up   # back to the real policy
```

## Results

Since `dns-mixed-answers` became graded, Pipelock exits 0 with
`16 pass, 2 record`, Squid exits 0 with `14 pass, 4 record`, and
**Smokescreen exits 1** with `13 pass, 4 record, 1 fail`. No row skips on
any engine any more.

**Most of the pass-count difference is a grading change, not a behavior
difference.** `ENGINE_EXPECTATIONS` in `checks/egress.py` grades
`connect-sni-mismatch` and `connect-raw-tunnel` as `deny` for Pipelock but
`record` for Smokescreen and Squid, so those two move out of the graded
pool for those engines. Of the **14 graded checks**, all three engines pass
the same 13; the fourteenth, `dns-mixed-answers`, is the first that has
ever separated them on enforcement rather than on grading.

Outcomes below are stable across both runs. The bracketed values are the
**attributed cause** from the 2026-08-19 re-run — what the engine said it
was rejecting, not what the check is named after. Several rows pass for a
reason other than the one the check implies; that is finding 1.

| Check | Pipelock | Smokescreen | Squid | Notes |
| --- | --- | --- | --- | --- |
| allowed-http | PASS (200) | PASS (301) | PASS (301) | attributed in finding 5 |
| allowed-https | PASS | PASS | PASS | TLSv1.3, SNI = CONNECT target |
| blocked-host-connect | PASS (403) [allowlist] | PASS (407) [allowlist] | PASS (403) [allowlist] | |
| blocked-host-http | PASS (403) [allowlist] | PASS (407) [allowlist] | PASS (403) [allowlist] | |
| direct-ip-connect | PASS [allowlist] | PASS [allowlist] | PASS [allowlist] | `1.1.1.1` is public, so the allowlist is the correct floor |
| loopback-ipv4 | PASS [allowlist] | PASS [allowlist] | PASS [**private-ip**] | finding 7 |
| rfc1918-ipv4 | PASS [allowlist] | PASS [allowlist] | PASS [**private-ip**] | 10/192.168/172.16 all denied |
| link-local-ipv4 | PASS [allowlist] | PASS [allowlist] | PASS [**private-ip**] | finding 7 |
| metadata-endpoint | PASS [allowlist] | PASS [allowlist] | PASS [**metadata**] | denied for both CONNECT and GET |
| loopback-ipv6 | PASS [allowlist] | PASS [**unparseable**] | PASS [**private-ip**] | see findings 1 and 7 |
| private-ipv6 | PASS [allowlist] | PASS [**unparseable**] | PASS [**private-ip**] | `fd00::1`, `fe80::1` |
| dns-private-ipv4 (nip.io) | PASS [private-ip + metadata] | PASS [private-ip] | PASS [private-ip + metadata] | **allowlisted** hostname → private IP, denied |
| dns-private-ipv6 (sslip.io) | PASS [private-ip] | PASS [private-ip] | PASS [private-ip] | fixture corrected — finding 6 |
| dns-rebinding (rbndr.us) | RECORD 6× dns-failure | RECORD 6× dns-failure | RECORD 6× dns-failure | fixture is gone — see below |
| dns-mixed-answers | PASS [private-ip] | **FAIL** | PASS [private-ip] | finding 9 — local dnsmasq fixture |
| connect-sni-mismatch | PASS (denied) | RECORD **allowed** | RECORD **allowed** | **discriminator** |
| connect-raw-tunnel | PASS (denied) | RECORD **allowed** | RECORD **allowed** | **discriminator** |
| concurrency-sanity | RECORD 10/10 | RECORD 10/10 | RECORD 10/10 | |

## Findings

### 1. Enforcement is equivalent, but most rows prove less than their names suggest

*This finding is about Pipelock and Smokescreen; Squid's causes differ,
and finding 7 explains why.*

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
gap rather than a misconfiguration. Squid behaves as Smokescreen does
here; finding 8 covers what it would take for it not to, and why that was
rejected.

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
in scope — see docs/security.md. Squid's rows here are identical
(`connect-sni-mismatch` accepted at TLSv1.3, `connect-raw-tunnel` answered
by pypi.org with the same `fatal(2) decode_error(50)` / `warning(1)
close_notify(0)` alert pair), with the one difference that its tunnels are
confined to port 443.

### 3. The rebinding measurement is inconclusive on every engine

**As of 2026-08-19 the fixture is gone.** `rbndr.us` no longer resolves
at all from the measurement host — not the generated names, not the apex
domain — while `nip.io` and `sslip.io` resolve normally. All six attempts
are `dns-failure` on every engine:

* Pipelock: `DNS lookup for 01010101.7f000002.rbndr.us returned no such host`
* Smokescreen: `502 Failed to resolve remote hostname: lookup …`
* Squid: `503` / `Unable to determine IP address from host name … The DNS
  server returned: Server Failure` (2026-08-25)

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
needs the local DNS fixture (TODO.md §3). The evidence that the engines
block loopback-behind-a-hostname is `dns-private-ipv4`/`ipv6`, not this
row.

### 4. Denial status codes are engine-specific

Pipelock answers `403 Forbidden`, as does Squid. Smokescreen answers `407
Proxy Authentication Required` ("Request rejected by proxy" on CONNECT).

407 is semantically wrong for a policy denial — it instructs the client to
retry with credentials, and some HTTP clients will prompt or retry-loop
rather than surface the block. It is upstream Smokescreen behavior, not
something this repository configures.

This validated one design decision: `probe_proxy()` in `run.py` grades the
post-start health check on `status >= 400` rather than matching a specific
code, so it accepted the 407 as healthy with no engine-specific branch —
and accepted Squid three engines later with no change at all.

Squid needed one piece of work to reach parity on *reasons* rather than
codes. Its stock denial page says only "Access control configuration
prevents your request from being allowed at this time", which classifies
as `unknown` and distinguishes nothing. `deny_info` plus four one-line
templates in `images/squid/errors` make each denial state its own cause,
which is what puts the `private-ip` / `metadata` / `port-not-allowed`
attributions in the table above. The exact strings are pinned in
`tests/test_egress.py::ClassifyDenialRealWordingTest`.

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

### 7. Squid attributes the IP-literal rows to the IP layer, because its floors are configuration

Finding 1 says the direct-IP rows on Pipelock and Smokescreen prove only
that a bare address is not on the allowlist. On Squid they prove more,
and the reason is structural rather than a quality difference.

Pipelock and Smokescreen check the allowlist first and reach their
built-in private-IP logic only afterwards. Squid has no built-in, so
`config/squid.conf` states the floors as `dst` ACLs *above* the allowlist
— `http_access` is first-match-wins — and a bare `127.0.0.1:80` therefore
matches `private_ip` before anything looks at names:

* Squid: `SSRF blocked, the destination resolves to a private, loopback,
  link-local or otherwise non-public address` (403)
* Pipelock: `domain not in allowlist: 127.0.0.1` (403)
* Smokescreen: `default rule policy used` (407)

Five rows change cause on Squid: `loopback-ipv4`, `rfc1918-ipv4`,
`link-local-ipv4`, `loopback-ipv6`, `private-ipv6` read `private-ip`, and
`metadata-endpoint` reads `metadata`. Squid is also the only engine that
parses `[::1]:80` and `[fd00::1]:80` as addresses at all rather than
failing on the literal (contrast Smokescreen's `unparseable-destination`
in finding 1), so its IPv6 rows are the only ones that actually exercise
IPv6 SSRF defence outside the sslip.io fixture.

This cuts both ways and should not be read as "Squid is stricter". The
enforcement outcome is identical on all three; what differs is that
Squid's floors are ours to get right. That is why `validate_policy_file()`
checks the required ranges and the rule order for Squid specifically
(docs/policy.md) — on the other two, deleting the equivalent protection
would take a deliberate `--unsafe-allow-private-ranges`, while on Squid it
would take deleting a line.

### 8. Squid can inspect tunnels, and the configuration that does it was rejected

Squid supports `ssl_bump peek` + `splice`: it reads the TLS ClientHello,
applies ACLs to the SNI, and then passes the connection through without
decrypting anything. On paper that closes exactly the gap finding 2
identifies, with no CA and no interception. It was built and measured.
Three results, in order of severity:

1. **It crashes the daemon.** The first connection that has to be
   terminated after a peek — a non-allowlisted SNI, or non-TLS bytes —
   aborts the process:

   ```text
   FATAL: assertion failed: client_side.cc:2714: "port->secure.signingCa.cert.get()"
   ```

   Squid reaches for a signing certificate on a path that never signs
   anything. Any client can trigger it, and it takes the whole proxy down.
   The fail-closed consequence is benign (nothing listens on 18080, so the
   sandbox loses Internet) but a trivially remote-triggerable abort is not
   a proxy anyone should run.
2. **Avoiding the crash means a CA in the image.** Supplying
   `cert=`/`sslcrtd_program` with a signing key is what the assertion
   wants, and private-key custody is an explicit non-goal
   (docs/architecture.md). `generate-host-certificates=off` looks like a
   way out and is not: it silently disables bumping on the port
   altogether, so the config *appears* to enforce and does not. That was
   caught here only because the raw-tunnel bytes reached pypi.org and came
   back as TLS alerts, exactly like Smokescreen's row.
3. **Every CONNECT is answered `200` before policy runs.** With `ssl-bump`
   on the port, Squid acknowledges the tunnel, peeks, and only then
   applies `http_access`, aborting afterwards. Its own log is explicit —
   `TCP_DENIED_ABORTED/200 CONNECT 127.0.0.1:80` — so policy does hold and
   nothing reaches the destination. But the client is told the tunnel
   succeeded, which breaks the contract that a denial is visible to the
   caller, and it makes every deny row in the suite fail on a proxy that
   is enforcing correctly.

So Squid ships without `ssl_bump`, with the same tunnel exposure
Smokescreen has. The one thing it does add at that layer is a port
restriction: `http_access deny CONNECT !TLS_ports` confines tunnels to
443, so an allowlisted host cannot be reached over an arbitrary port the
way it can on the other two. That is narrower than inspecting the tunnel,
but it is not nothing, and it costs no capability.

### 9. Mixed public+private DNS answers: Smokescreen connects, the other two refuse

`dns-mixed-answers` was an unconditional `skip` from the day the suite was
written, because no public wildcard-DNS service serves a mixed answer set.
It is now graded, against a dnsmasq container that `up --test-policy`
starts and points the engine's resolver at (`--dns`). The records are in
`config/dns-fixture.hosts`:

| Name | Answer |
| --- | --- |
| `public-only.fixture.test` | `9.9.9.9` |
| `mixed-public-first.fixture.test` | `9.9.9.9`, then `10.0.0.1` |
| `mixed-private-first.fixture.test` | `10.0.0.1`, then `9.9.9.9` |

All three are allowlisted in the test policy, so a denial can only come
from the address check. The control probe runs first and must establish;
without it a denial below would be unattributable and the row skips rather
than banking a pass. Both orderings are present so that an engine
validating only the first answer is distinguished from one validating all
of them.

**Result:**

* **Pipelock — denied, both orderings.** `SSRF blocked:
  mixed-public-first.fixture.test resolves to internal IP 10.0.0.1`.
* **Squid — denied, both orderings.** Its `dst` ACL matches when any
  address in the answer set is in a denied range.
* **Smokescreen — established, both orderings.** This is the failure.

Smokescreen's own log says exactly what it did:

```json
{"msg":"CANONICAL-PROXY-DECISION","allow":true,
 "decision_reason":"host matched allowed domain in rule",
 "requested_host":"mixed-private-first.fixture.test:443"}
{"msg":"CANONICAL-PROXY-CN-CLOSE","outbound_remote_addr":"9.9.9.9:443"}
```

It received both addresses, picked the routable one, and connected there —
**it did not connect to `10.0.0.1`**. That bounds the severity: this is not
an SSRF hole on its own. It is the behavior its denial wording has always
implied — "no valid IP found among resolved addresses" fires only when
*every* address is invalid, so a single public answer is enough to allow
the name. Pipelock and Squid reject the name outright instead.

Which is right depends on a policy question the repository has already
answered on paper. docs/policy.md says "a public hostname resolving to a
private address is rejected", and under that rule Smokescreen does not
comply. The residual risk is not the connection it made but the ones it
might make later: an engine that treats a mixed answer as acceptable has
to be trusted never to fall back to the other address on a retry, and
never to re-resolve without re-validating. Neither is visible from
outside. Finding 11 is the decision that follows.

### 10. Squid's `dstdomain` allowlist can be satisfied by a reverse lookup

Found while building the fixture, not looked for. With dnsmasq serving the
fixture, `direct-ip-connect` — a bare `CONNECT 1.1.1.1:443`, which every
engine had always denied — started **passing through Squid**.

The cause is documented Squid behavior: for `dstdomain` and `dstdom_regex`,
"a reverse lookup is tried if an IP based URL is used and no match is
found". dnsmasq synthesizes PTR records from its hosts entries, so
`1.1.1.1` reverse-resolved to an allowlisted `*.fixture.test` name and the
allowlist matched.

The fixture now uses `9.9.9.9`, disjoint from anything the suite CONNECTs
to by address, which confines the side effect. But the underlying property
is real and is not an artifact: **under Squid, a bare-IP destination can
satisfy a hostname allowlist if that IP's PTR record resolves to an
allowlisted name.** PTR records are controlled by whoever holds the address
block, so an attacker who controls a destination controls its PTR — and
Squid does not forward-confirm the result. Pipelock and Smokescreen match
the literal and never reverse-resolve.

This does not defeat the SSRF floors: `private_ip`/`metadata_ip` are `dst`
rules evaluated before the allowlist and are unaffected. The exposure is
limited to reaching a *public* address that is not on the allowlist, which
under the shipped policy means egress to an attacker-chosen host. It is
worth closing; a candidate check and the likely fix (`dns_defnames`-style
hardening is not it — Squid has no switch to disable the reverse-lookup
fallback, so the fix is to match IP literals with a `dst` ACL before the
`dstdomain` rules are reached) are in TODO.md §5.

### 11. `dns-mixed-answers` is the first check that separates the engines on enforcement

Every previous difference was a capability gap graded as `record`
(findings 2 and 8) or a difference in which rule fired first (findings 1
and 7). This one is a graded failure against the policy in docs/policy.md,
and it needs a decision rather than a note:

1. **Leave it as a failure.** Smokescreen exits 1 on `check --full`,
   documenting a real deviation. This is the current state, and it is
   consistent with treating docs/policy.md as the contract.
2. **Relax the stated rule** to "must not *connect to* a private address",
   which all three engines satisfy, and re-grade the row for everyone.
   Honest, but it weakens the policy to match the weakest engine.
3. **Grade it `record` for Smokescreen** via `ENGINE_EXPECTATIONS`, as was
   done for the tunnel checks. Consistent with precedent, but those are
   capability gaps in a layer the engine cannot see into; this is a
   deliberate choice about addresses it *did* see.

Option 1 is what ships, on the grounds that a suite exists to test the
stated policy and this is the first time it has caught something. It does
not change the default engine — Pipelock already was, and passes. It does
change what choosing Smokescreen means, which belongs in
docs/security.md rather than in a silent expectation override.

## Not yet measured

* Squid and the DNS fixture on the **Docker** backend. Its build is an ordinary Dockerfile and
  its runtime is one read-only bind mount, so nothing about it is
  backend-specific, but that is reasoning rather than a measurement.
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
reasoning is measured rather than hypothesised: all three engines are
interchangeable for every graded check, and part company only after
CONNECT succeeds. Pipelock inspects the tunnel's first bytes; neither
Smokescreen nor Squid does.

**Smokescreen remains a viable fallback.** It passed every graded check.
Choosing it means accepting that tunnel contents to allowlisted hosts are
unconstrained — a reasonable trade if operational maturity matters more
than domain-fronting and smuggling resistance for a given deployment.

**Squid is the third option, and the one to choose when the policy itself
needs to be auditable.** It passed every graded check. Its tunnel exposure
matches Smokescreen's (finding 8), narrowed slightly by the CONNECT port
restriction. What it offers in exchange is that every rule is visible in
one file with a stated evaluation order, rather than being engine
behavior you have to trust and cannot inspect — which is also the reason
`up` validates that file harder than the other two (finding 7). It is also
the most widely deployed and longest-lived of the three, which matters for
CVE response and for finding someone who already knows how to read the
config.

Revisit if the rebinding check is made conclusive (TODO.md) and the
engines then differ.
