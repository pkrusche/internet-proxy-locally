# Pipelock vs Smokescreen vs Squid — measured comparison

The engine choice is empirical: run `checks/egress.py` against all three
and record what happens. Feature tables do not decide it.

This file is the current state, not a changelog. Where a result corrects
an earlier one, that is recorded under [corrections](#corrections-to-earlier-runs)
rather than left in place.

## Results

| | Pipelock | Smokescreen | Squid |
| --- | --- | --- | --- |
| `check --full` | 18 pass, 1 record | 15 pass, 3 record, **1 fail** | 16 pass, 3 record |
| Exit code | 0 | **1** | 0 |

Of the **16 checks graded on every engine**, all three pass the same 15.
The sixteenth — `dns-mixed-answers` — is the only check that has ever
separated them on enforcement, and Smokescreen fails it
([§2](#2-mixed-dns-answers-smokescreen-connects-where-the-others-refuse)).

The rest of the pass-count spread is grading, not behavior:
`ENGINE_EXPECTATIONS` in `checks/egress.py` grades `connect-sni-mismatch`
and `connect-raw-tunnel` as `deny` for Pipelock but `record` for the other
two, so those rows leave the graded pool there
([§1](#1-tunnel-layer-enforcement-pipelock-only)). `concurrency-sanity` is
`record` everywhere. Nothing skips on any engine.

Bracketed values are the **attributed cause** — what the engine said it was
rejecting, not what the check is named after. `[allowlist]` is shorthand
for `hostname-not-allowlisted`.

| Check | Pipelock | Smokescreen | Squid | |
| --- | --- | --- | --- | --- |
| allowed-http | PASS (200) | PASS (301) | PASS (301) | CDN tier, [corrections](#corrections-to-earlier-runs) |
| allowed-https | PASS | PASS | PASS | TLSv1.3, SNI = CONNECT target |
| blocked-host-connect | PASS (403) [allowlist] | PASS (407) [allowlist] | PASS (403) [allowlist] | |
| blocked-host-http | PASS (403) [allowlist] | PASS (407) [allowlist] | PASS (403) [allowlist] | |
| direct-ip-connect | PASS [allowlist] | PASS [allowlist] | PASS [**ip-literal**] | [§5](#5-squid-a-bare-ip-could-satisfy-the-allowlist-through-a-reverse-lookup) |
| loopback-ipv4 | PASS [allowlist] | PASS [allowlist] | PASS [**private-ip**] | [§4](#4-where-the-ssrf-floors-live) |
| rfc1918-ipv4 | PASS [allowlist] | PASS [allowlist] | PASS [**private-ip**] | 10/192.168/172.16 |
| link-local-ipv4 | PASS [allowlist] | PASS [allowlist] | PASS [**private-ip**] | [§4](#4-where-the-ssrf-floors-live) |
| metadata-endpoint | PASS [allowlist] | PASS [allowlist] | PASS [**metadata**] | CONNECT and GET |
| loopback-ipv6 | PASS [allowlist] | PASS [**unparseable**] | PASS [**private-ip**] | [reading the results](#reading-the-results) |
| private-ipv6 | PASS [allowlist] | PASS [**unparseable**] | PASS [**private-ip**] | `fd00::1`, `fe80::1` |
| dns-private-ipv4 | PASS [private-ip + metadata] | PASS [private-ip] | PASS [private-ip + metadata] | nip.io; **allowlisted** name → private IP |
| dns-private-ipv6 | PASS [private-ip] | PASS [private-ip] | PASS [private-ip] | sslip.io |
| dns-rebinding | PASS [private-ip] | PASS [private-ip] | PASS | [§3](#3-dns-rebinding-two-different-defences) |
| dns-mixed-answers | PASS [private-ip] | **FAIL** | PASS [private-ip] | [§2](#2-mixed-dns-answers-smokescreen-connects-where-the-others-refuse) |
| ptr-allowlist | PASS [allowlist] | PASS [allowlist] | PASS [**ip-literal**] | [§5](#5-squid-a-bare-ip-could-satisfy-the-allowlist-through-a-reverse-lookup) |
| connect-sni-mismatch | PASS (denied) | RECORD **allowed** | RECORD **allowed** | [§1](#1-tunnel-layer-enforcement-pipelock-only) |
| connect-raw-tunnel | PASS (denied) | RECORD **allowed** | RECORD **allowed** | [§1](#1-tunnel-layer-enforcement-pipelock-only) |
| concurrency-sanity | RECORD 10/10 | RECORD 10/10 | RECORD 10/10 | |

## Measurement conditions

| | |
| --- | --- |
| Host | macOS 26.6.1, arm64 (Apple Silicon) |
| Backend | Apple `container`; Docker 29.7.2 for the 2026-08-19 Pipelock/Smokescreen run |
| Dates | 2026-08-17 first run · 2026-08-19 causes and Docker · 2026-08-25 Squid and mixed answers · 2026-08-26 rebinding and the PTR fix |
| Pipelock | `ghcr.io/luckypipewrench/pipelock:3.3.0` @ `sha256:42b58a42…b011f7` |
| Smokescreen | local build from `stripe/smokescreen` @ `131fba29ce1e` |
| Squid | local build of Alpine `squid=6.12-r0` on `alpine:3.22.1` |
| Policy | test policy (`up --test-policy`) — DNS fixtures allowlisted, local fixture running |
| Command | `./run.py check --full` |

## How to reproduce

```bash
for engine in pipelock smokescreen squid; do
  ./run.py --engine "$engine" setup
  ./run.py --engine "$engine" up --test-policy
  ./run.py check --full --json > "results/$engine-$(date +%Y%m%d).json"
done

./run.py up   # back to the real policy, and remove the DNS fixture

checks/egress.py --diff results/pipelock-*.json results/smokescreen-*.json
```

## Reading the results

**Most deny rows demonstrate the allowlist, not SSRF defence.** Asked to
CONNECT to `127.0.0.1:80`, Pipelock answers `domain not in allowlist:
127.0.0.1` and Smokescreen answers `default rule policy used`. Neither
reaches its private-IP logic, because a bare address is not on the
allowlist and is rejected on that basis first. The same holds for
`rfc1918-ipv4`, `link-local-ipv4`, `direct-ip-connect` and
`metadata-endpoint`: a bare `169.254.169.254` is refused as
not-allowlisted, so that row shows nothing about metadata handling. Under
a default-deny allowlist these rows can only ever demonstrate the
allowlist. They are worth keeping as regression guards — an engine that
allowed them would be badly broken — but they are not evidence of SSRF
defence. Squid is the exception, for two structural reasons: its SSRF
floors sit above the allowlist ([§4](#4-where-the-ssrf-floors-live)), and
it refuses address-form destinations outright
([§5](#5-squid-a-bare-ip-could-satisfy-the-allowlist-through-a-reverse-lookup)).

**Smokescreen never parses the IPv6 literals.** `[::1]:80` and
`[fd00::1]:80` are rejected with `Destination host cannot be determined` —
a parse failure ahead of any policy evaluation. Its pass on
`loopback-ipv6`/`private-ipv6` says nothing about its allowlist or its
private-IP handling, which is why `unparseable-destination` is a separate
cause bucket instead of being folded into a generic denial.

**The fixture rows are the real evidence.** `dns-private-ipv4`,
`dns-private-ipv6`, `dns-mixed-answers` and `dns-rebinding` use hostnames
that are *deliberately allowlisted*, so a denial can only have come from
re-validating the resolved address. All three engines validate after
resolution, as docs/policy.md requires, and say so:

* Pipelock: `SSRF blocked: 10.0.0.1.nip.io resolves to internal IP 10.0.0.1`
* Smokescreen: `no valid IP found among resolved addresses - 10.0.0.1 denied by rule 'Deny: Private Range'`
* Squid: `SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address`

**Denial status codes differ and do not matter.** Pipelock and Squid answer
`403`; Smokescreen answers `407 Proxy Authentication Required`, which is
semantically wrong for a policy denial — it tells the client to retry with
credentials, and some clients prompt or retry-loop instead of surfacing the
block. That is upstream behavior, not something configured here.
`probe_proxy()` grades the health check on `status >= 400` rather than a
specific code, which is why it accepted Smokescreen's 407 and then accepted
a third engine with no change at all.

Squid needed work to report *reasons* rather than just codes: its stock
page says only "Access control configuration prevents your request from
being allowed at this time", which classifies as `unknown`. `deny_info`
plus five one-line templates in `images/squid/errors` make each denial
state its cause, which is what fills the bracketed column above. The exact
strings are pinned in
`tests/test_egress.py::ClassifyDenialRealWordingTest`.

## The differences that matter

### 1. Tunnel-layer enforcement: Pipelock only

The only capability gap, and the reason Pipelock is the default.

**SNI mismatch** — CONNECT to `pypi.org:443`, then send a ClientHello for
`files.pythonhosted.org`. Pipelock closes the connection at the
ClientHello (`SSL: UNEXPECTED_EOF_WHILE_READING`, from
`forward_proxy.sni_verification`). Smokescreen and Squid complete the
TLSv1.3 handshake: they authorize the CONNECT target and then go blind.

Both hosts are allowlisted, so this is not a bypass on its face. The
exposure is that the destination is then chosen by the *CDN* — both are
Fastly-fronted, so allowlisting one Fastly-fronted domain reaches whatever
else that edge routes by SNI.

**Raw protocol smuggling** — CONNECT to `pypi.org:443`, then send plaintext
HTTP. Pipelock closes the tunnel with no response
(`forward_proxy.sni_require_tls`). Smokescreen and Squid forward the bytes;
the reply was `fatal(2) decode_error(50)` then `warning(1)
close_notify(0)` — **TLS alerts from pypi.org, not from the proxy**. The
bytes made the full round trip and only the destination's own strictness
stopped them.

So under Smokescreen or Squid, a client that can reach an allowlisted host
on 443 can speak any protocol to it and present any SNI. Squid narrows
this slightly: `http_access deny CONNECT !TLS_ports` confines tunnels to
443, so an allowlisted host cannot be reached on an arbitrary port the way
it can on the other two. Squid could close the gap properly and the
configuration that does it was measured and rejected — see
[rejected: tunnel peeking](#rejected-tunnel-peeking-on-squid).

### 2. Mixed DNS answers: Smokescreen connects where the others refuse

The one graded failure. A name resolving to both a public and a private
address, served by the local fixture (docs/security.md), all three names
allowlisted so a denial can only come from the address check:

| Name | Answer |
| --- | --- |
| `public-only.fixture.test` | `9.9.9.9` — the control, must establish |
| `mixed-public-first.fixture.test` | `9.9.9.9`, then `10.0.0.1` |
| `mixed-private-first.fixture.test` | `10.0.0.1`, then `9.9.9.9` |

Both orderings are present so that an engine validating only the first
answer is distinguished from one validating all of them. The control runs
first: without it a denial would be unattributable, and the row skips
rather than banking a pass.

* **Pipelock** — denied, both orderings: `SSRF blocked:
  mixed-public-first.fixture.test resolves to internal IP 10.0.0.1`.
* **Squid** — denied, both orderings. Its `dst` ACL matches when *any*
  address in the answer set is in a denied range.
* **Smokescreen** — established, both orderings.

Smokescreen's own log says exactly what it did:

```json
{"msg":"CANONICAL-PROXY-DECISION","allow":true,
 "decision_reason":"host matched allowed domain in rule",
 "requested_host":"mixed-private-first.fixture.test:443"}
{"msg":"CANONICAL-PROXY-CN-CLOSE","outbound_remote_addr":"9.9.9.9:443"}
```

It received both addresses, picked the routable one, and connected there.
**It did not connect to `10.0.0.1`**, which bounds the severity: this is
not an SSRF hole on its own. It is what its denial wording always implied —
"no valid IP found among resolved addresses" fires only when *every*
address is invalid, so one public answer is enough to allow the name.

docs/policy.md says "a public hostname resolving to a private address is
rejected", and under that rule Smokescreen does not comply. The residual
risk is not the connection it made but the ones it might make later: an
engine that accepts a mixed answer has to be trusted never to fall back to
the other address on a retry and never to re-resolve without
re-validating. Neither is visible from outside.

**What to do about it** — three options, and the choice is a policy call:

1. **Leave it failing.** Smokescreen exits 1, documenting a real deviation.
   This is what ships, on the grounds that the suite exists to test the
   stated policy and this is the first time it has caught anything.
2. **Relax the rule** to "must not *connect to* a private address", which
   all three satisfy. Honest, but it weakens the policy to match the
   weakest engine.
3. **Grade it `record` for Smokescreen**, as was done for the tunnel
   checks. Consistent with precedent — but those are capability gaps in a
   layer the engine cannot see into, whereas this is a deliberate choice
   about addresses it *did* see.

It does not change the default engine; Pipelock already was, and passes.
It does change what choosing Smokescreen means, which belongs in
docs/security.md rather than in a silent expectation override.

### 3. DNS rebinding: two different defences

The fixture answers the **first** lookup of a name with a public address
and **every later one** with its own private address, on which it listens
as a trap. Each name is probed twice, either side of a pause, so the
second answer is actually handed out. **Only a trap hit fails the check**:
"did the engine reach a private address" is reported by the thing that
would have received the connection, not inferred from counts.

| | Pipelock | Smokescreen | Squid |
| --- | --- | --- | --- |
| Names rebound (of 3) | 3 | 3 | **0** |
| Lookups | 9 | 6 | 3 |
| Repeat probes denied | 3 | 3 | 0 (established) |
| Trap hits | 0 | 0 | 0 |

**Pipelock and Smokescreen re-resolve and re-validate.** Both were handed
the private address on every repeat lookup and refused all three, cause
`private-ip`. That is a rebind offered and declined.

**Squid never re-resolves, so it was never offered one.** Its ipcache pins
the address it validated: one lookup served six CONNECTs to the same name,
and a separate probe confirmed the entry survives **at least 68 seconds**
of repeated requests despite the fixture answering with TTL 0. That is a
legitimate defence — you cannot follow a rebind you never observe — but it
is a different mechanism, and `positive_dns_ttl` defaults to six hours, so
the address Squid connects to can be that stale (TODO.md).

Both designs pass, and neither is weaker than the other. The point is that
the row now says *which* one an engine has.

### 4. Where the SSRF floors live

Pipelock and Smokescreen block private destinations in engine code; the
configuration only turns that on, and disabling it would take a deliberate
`--unsafe-allow-private-ranges`. Squid has no built-in, so
`config/squid.conf` states the floors as `dst` ACLs *above* the allowlist —
`http_access` is first-match-wins — and disabling one would take deleting a
line.

That changes what six rows attribute to. A bare `127.0.0.1:80` matches
`private_ip` before anything looks at names, so `loopback-ipv4`,
`rfc1918-ipv4`, `link-local-ipv4`, `loopback-ipv6` and `private-ipv6` read
`private-ip` on Squid and `metadata-endpoint` reads `metadata`, where the
other two read `allowlist`. Squid is also the only engine that parses
`[::1]:80` and `[fd00::1]:80` as addresses rather than failing on the
literal, so its IPv6 rows are the only ones exercising IPv6 SSRF defence
outside the sslip.io fixture.

This is not "Squid is stricter" — the enforcement outcome is identical on
all three. What differs is that Squid's floors are ours to get right, which
is why `validate_policy_file()` checks the required ranges and the rule
order for Squid specifically (docs/policy.md).

### 5. Squid: a bare IP could satisfy the allowlist through a reverse lookup

**Found 2026-08-25, fixed 2026-08-26.** Found by accident while building
the DNS fixture: with the fixture serving DNS, `direct-ip-connect` — a bare
`CONNECT 1.1.1.1:443`, denied by every engine until then — started passing
through Squid.

The cause is documented Squid behavior: for `dstdomain` and `dstdom_regex`,
"a reverse lookup is tried if a IP based URL is used and no match is
found". So an address that matches nothing in the allowlist gets a second
chance under whatever name its PTR record claims — and PTR records belong
to whoever holds the address block, with no forward confirmation.

Measured deliberately afterwards, against the **real** policy
(github/pypi/npm only) with a resolver claiming `PTR(1.1.1.1) = pypi.org`:

| | `CONNECT 1.1.1.1:443` | `CONNECT 9.9.9.9:443` |
| --- | --- | --- |
| Pipelock | 403 `domain not in allowlist: 1.1.1.1` | 403 |
| Smokescreen | 407 `default rule policy used` | 407 |
| Squid (before the fix) | **200 Connection established** | 403 |

The PTR record was the only difference between the two addresses. That is a
full bypass of the destination allowlist — the control this service exists
to provide — and it sits squarely in the threat model: an agent
exfiltrating to a host its operator controls only has to set that host's
reverse DNS. Pipelock and Smokescreen match the literal and never
reverse-resolve.

It never defeated the SSRF floors — `private_ip`/`metadata_ip` are `dst`
rules evaluated first — so the exposure was reaching a *public* address
that is not on the allowlist.

**The fix.** Squid has no switch to disable the fallback, so
`config/squid.conf` now refuses address-form destinations before any
`dstdomain` rule is reached:

```squid
acl ip_literal dstdom_regex -i ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$
acl ip_literal dstdom_regex -i ^\[?[0-9a-f]*:[0-9a-f:.]*\]?$
http_access deny ip_literal
```

Nothing is lost: docs/policy.md allowlists by hostname and never by
address, so a bare address could only ever have been denied. Matching the
literal form is also what keeps the fix itself out of the trap — the
reverse lookup happens only when *no* match is found, and these patterns
match, so evaluation stops and no PTR query is made. `direct-ip-connect`
now reports `ip-literal-destination` on Squid instead of `allowlist`.

**The guard.** `ptr-allowlist` is a graded check: the fixture answers PTR
for `1.0.0.1` with `pypi.org`, and connecting to `1.0.0.1:443` must still
be denied. It was verified to fail against the unfixed config and pass
against the fixed one. Two things make it worth having as its own row:
`direct-ip-connect` passed throughout the bug's lifetime, because it uses
an address with no PTR claim — the existing suite could not see this. And
`validate_policy_file()` now requires `http_access deny ip_literal` ahead
of the allowlist, so deleting the rule fails `up` rather than silently
reopening the hole.

## Rejected: tunnel peeking on Squid

Squid supports `ssl_bump peek` + `splice`: read the TLS ClientHello, apply
ACLs to the SNI, pass the connection through undecrypted. On paper that
closes [§1](#1-tunnel-layer-enforcement-pipelock-only) with no CA and no
interception. It was built and measured. Three results, worst first:

1. **It crashes the daemon.** The first connection that must be terminated
   after a peek — a non-allowlisted SNI, or non-TLS bytes — aborts the
   process:

   ```text
   FATAL: assertion failed: client_side.cc:2714: "port->secure.signingCa.cert.get()"
   ```

   Squid reaches for a signing certificate on a path that never signs
   anything. Any client can trigger it. The fail-closed consequence is
   benign — nothing listens on 18080, so the sandbox loses Internet — but a
   trivially remote-triggerable abort is not a proxy anyone should run.
2. **Avoiding it means a CA in the image.** Supplying
   `cert=`/`sslcrtd_program` with a signing key is what the assertion
   wants, and private-key custody is an explicit non-goal
   (docs/architecture.md). `generate-host-certificates=off` looks like a
   way out and is not: it silently disables bumping on the port, so the
   config *appears* to enforce and does not.
3. **Every CONNECT is answered `200` before policy runs.** Squid
   acknowledges the tunnel, peeks, then applies `http_access` and aborts —
   `TCP_DENIED_ABORTED/200 CONNECT 127.0.0.1:80` in its own log. Policy
   holds and nothing reaches the destination, but the client is told the
   tunnel succeeded, which breaks the contract that a denial is visible to
   the caller.

So Squid ships without `ssl_bump`. The reasoning is repeated at the top of
`config/squid.conf` so nobody re-enables it from first principles.

## Corrections to earlier runs

Things measured wrong and later fixed. Kept because each was believed for
a while, and the reasons are reusable.

* **The IPv6 fixture had never run.** `dns-private-ipv6`'s loopback target
  was `--1.sslip.io`, which resolves to `::1` but is a reserved IDNA form —
  a label may not start with two hyphens. Both engines rejected the *name*
  (`idna: invalid label "--1"` / `no such host`), never the address, and
  the row still scored `pass` because a denial was all it asked for. One
  third of the IPv6 SSRF evidence had been vacuous since the fixture was
  written. Now `0--1.sslip.io`. The classifier surfaced it: `unknown` on a
  passing row was the thing worth pulling on.
* **`/etc/hosts` cannot express a mixed answer.** A bind-mounted hosts file
  looked like a cheap fixture and is not: duplicate names collapse to one
  address (musl keeps the first, Squid's own parser the last), so the
  engine never sees more than one and the check measures which record
  survived. An earlier revision of this file reported a Squid result from
  exactly that setup; it did not show what it was said to show.
* **`--host-record=name,v4,v4` gives one address.** The second slot is the
  IPv6 address, so a second IPv4 replaces the first. The dnsmasq recipe in
  docs/security.md used to recommend it.
* **`rbndr.us` was never gradable.** It answered each query with one of its
  two addresses at random, so the checker's lookup and the engine's were
  independent draws and neither outcome attributed to anything; the
  2026-08-17 `denied=0 established=6` / `denied=6 established=0` split was
  a cached answer on each side, not a difference in defence. It then
  stopped resolving entirely, making the row six identical `dns-failure`s.
  Replaced by the local fixture ([§3](#3-dns-rebinding-two-different-defences)).
* **`allowed-http` returns 200 on Pipelock and 301 on the others.** Captured
  headers attribute it to the upstream tier, not the proxy: Smokescreen and
  Squid were answered at the Fastly edge (`Server: Varnish`, `Location:
  https://pypi.org/`), Pipelock at pypi.org's origin (`Server: gunicorn`,
  four Fastly hops). CDN variation. Both pass and it affects nothing.
* **Docker publishes the host port before the engine listens.** The
  post-start probe could connect seconds early and `up` failed with
  `non-HTTP response: ''` on a healthy proxy. Apple `container` does not
  accept early, which is why the first run never hit it. `probe_proxy()`
  now separates a not-ready-yet probe (retried until the deadline) from a
  real verdict; a proxy that *answers* and allows the probe still fails
  immediately.

## Not yet measured

* **Squid and the DNS fixture on the Docker backend.** Squid's build is an
  ordinary Dockerfile and its runtime is one bind mount, so nothing there
  is backend-specific. The fixture is: `up --test-policy` reads the fixture
  container's address out of `inspect`, and the two CLIs report it
  differently. Both shapes are parsed and unit-tested; only the Apple path
  has met a real runtime.
* Crash → fail-closed: kill the container mid-session and confirm the
  sandbox loses Internet rather than gaining unfiltered access.
* `./run.py restart` behavior under load.
* Startup time, image size, resource usage, upgrade friction.

## Decision

**Pipelock remains the default** (`DEFAULT_ENGINE` in `run.py`). It passes
every graded check, and it is the only engine that enforces inside the
CONNECT tunnel ([§1](#1-tunnel-layer-enforcement-pipelock-only)). Nothing
measured since has argued against it.

**Squid is the alternative to reach for when the policy itself has to be
auditable.** It passes every graded check. Its tunnel exposure matches
Smokescreen's, narrowed by the CONNECT port restriction. In exchange,
every rule is visible in one file with a stated evaluation order rather
than being engine behavior you must trust and cannot inspect — which is
also why `up` validates that file harder than the other two
([§4](#4-where-the-ssrf-floors-live)).

The case against it is the shape of its one serious defect. The PTR
allowlist bypass
([§5](#5-squid-a-bare-ip-could-satisfy-the-allowlist-through-a-reverse-lookup))
was a complete hole in the destination allowlist, it was found by accident
rather than by the suite, and it existed because Squid brings behavior we
did not ask for — a large general-purpose proxy has more of that than a
small purpose-built one. It is fixed and now guarded, but the class of
problem is not closed, and it is a fair argument for preferring an engine
with less surface. Squid is also the only engine that never re-resolves,
which cuts both ways ([§3](#3-dns-rebinding-two-different-defences)).

**Smokescreen is a fallback with a known deviation.** It fails
`dns-mixed-answers`
([§2](#2-mixed-dns-answers-smokescreen-connects-where-the-others-refuse)),
so `check --full` exits 1 against it. That failure is bounded — it connects
to the public address, not the private one, and reaching it needs an
*allowlisted* name to resolve to a private address, which an agent cannot
arrange for `github.com`. Choosing Smokescreen means accepting that and
unconstrained tunnel contents to allowlisted hosts.

Worth stating plainly, because the exit codes invite the opposite reading:
a graded failure is not automatically the worse defect. Smokescreen's
deviation grants no reach it did not already have. Squid's PTR bypass
granted egress to any address on the Internet and produced no failing row
at all until a check was written for it. The suite measures what it has
been taught to measure, which is an argument for reading
[§2](#2-mixed-dns-answers-smokescreen-connects-where-the-others-refuse)
and [§5](#5-squid-a-bare-ip-could-satisfy-the-allowlist-through-a-reverse-lookup)
before reading the pass counts.
