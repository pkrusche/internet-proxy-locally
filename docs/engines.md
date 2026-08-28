# Pipelock vs Smokescreen vs Squid — what the results mean

The numbers are in [comparison.md](comparison.md), which is **generated**
from `results/*.json` by `scripts/report.py` and holds no opinions. This
file holds the opinions: how to read those rows, where the engines really
differ, what was measured wrong before, and which engine to use.

The engine choice is empirical: run `checks/egress.py` against all three
and record what happens. Feature tables do not decide it.

## How to reproduce the numbers

```bash
scripts/report.py --run                  # all three engines, then rewrite comparison.md
scripts/report.py --run --backend docker # or pin the backend
scripts/report.py --check                # CI: fail if comparison.md is stale
```

`--run` drives, per engine, `./run.py --engine E setup`, `up --test-policy`
and `check --full --json`, writes `results/E.json`, and finishes with a
`down` so no engine and no DNS fixture is left running. The result files
are committed: without them the generated file could not be re-derived or
checked, only believed.

To compare two runs directly rather than re-reading the table:

```bash
checks/egress.py --diff results/pipelock.json results/smokescreen.json
```

## Reading the results

**Most deny rows demonstrate the allowlist, not SSRF defence.** Asked to
CONNECT to `127.0.0.1:80`, Pipelock answers `domain not in allowlist:
127.0.0.1` and Smokescreen answers `default rule policy used`. Neither
reaches its private-IP logic, because a bare address is not on the
allowlist and is rejected on that basis first. The same holds for
`rfc1918-ipv4`, `link-local-ipv4`, `direct-ip-connect` and
`metadata-endpoint`: a bare `169.254.169.254` is refused as
not-allowlisted, so that row shows nothing about metadata handling. Under a
default-deny allowlist these rows can only ever demonstrate the allowlist.
They are worth keeping as regression guards — an engine that allowed them
would be badly broken — but they are not evidence of SSRF defence. Squid is
the exception, for two structural reasons: its SSRF floors sit above the
allowlist ([§4](#4-where-the-ssrf-floors-live)), and it refuses
address-form destinations outright
([§5](#5-squid-a-bare-ip-could-satisfy-the-allowlist-through-a-reverse-lookup)).
This is why the generated file separates "different behavior" from "same
behavior, different stated reason": the second list is where this shows up.

**Smokescreen never parses the IPv6 literals.** `[::1]:80` and
`[fd00::1]:80` are rejected with `Destination host cannot be determined` —
a parse failure ahead of any policy evaluation. Its pass on
`loopback-ipv6`/`private-ipv6` says nothing about its allowlist or its
private-IP handling, which is why `unparseable-destination` is a separate
cause bucket instead of being folded into a generic denial.

**The fixture rows are the real evidence.** `dns-private-ipv4`,
`dns-private-ipv6`, `dns-mixed-answers`, `dns-rebinding` and
`ptr-allowlist` use hostnames that are *deliberately allowlisted*, so a
denial can only have come from re-validating the resolved address. Two of
the three engines validate after resolution, as docs/policy.md requires,
and say so:

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
state its cause, which is what fills the bracketed column in the generated
table. The exact strings are pinned in
`tests/test_egress.py::ClassifyDenialRealWordingTest`, and
`validate_policy_file()` now refuses a Squid config whose `deny_info` lines
have come loose from the ACLs they name — renaming `private_ip` without
updating its page would turn every SSRF denial back into `unknown` while
leaving a config that starts and still denies the right things.

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

The one place an engine's *behavior* deviates from docs/policy.md. A name
resolving to both a public and a private address, served by the local
fixture (docs/security.md), all three names allowlisted so a denial can
only come from the address check:

| Name | Answer |
| --- | --- |
| `public-only.fixture.test` | `9.9.9.9` — the control, must establish |
| `mixed-public-first.fixture.test` | `9.9.9.9`, then `10.0.0.1` |
| `mixed-private-first.fixture.test` | `10.0.0.1`, then `9.9.9.9` |

Both orderings are present so that an engine validating only the first
answer is distinguished from one validating all of them. The control runs
first: without it a denial would be unattributable, and the row skips
rather than banking a pass. The names, the addresses and the orderings all
come from `[fixture]` in config.toml, which renders
`config/dns-fixture.hosts` and refuses a record the test policy does not
allowlist.

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

**How it is graded, and why.** `record` for Smokescreen, an override in
`ENGINE_EXPECTATIONS`. The row is the same measurement either way — it
still says `established`, with both orderings, in the generated table — but
the grade was doing a job it cannot do. `check --full` exited 1 on *every*
Smokescreen run, which made the exit code useless for the thing an exit
code is for: telling "this engine has a known, bounded deviation I have
already read about" apart from "something just broke". A permanent failure
is not a signal, it is noise with a red label.

The two arguments considered and rejected:

* **Leave it failing.** Honest, and it was what shipped first. But a suite
  whose exit code is permanently 1 on one engine stops being run on that
  engine, and a deviation nobody re-measures is worse than one recorded in
  a table.
* **Relax the rule** to "must not *connect to* a private address", which
  all three satisfy. That weakens the stated policy to match the weakest
  engine, and docs/policy.md would then no longer describe what Pipelock
  and Squid actually enforce.

Recording it keeps the policy as written, keeps the behavior visible, and
puts the cost where it belongs: in docs/security.md, "Choosing an engine",
which is what someone selecting Smokescreen has to read. It does not change
the default engine — Pipelock already was, and refuses these names.

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
the address Squid connects to can be that stale.

Both designs pass, and neither is weaker than the other. The point is that
the row now says *which* one an engine has, and the generated file lists it
under "same behavior, different stated reason" rather than hiding it in a
pass count.

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
other two read `hostname-not-allowlisted`. Squid is also the only engine
that parses `[::1]:80` and `[fd00::1]:80` as addresses rather than failing
on the literal, so its IPv6 rows are the only ones exercising IPv6 SSRF
defence outside the sslip.io fixture.

This is not "Squid is stricter" — the enforcement outcome is identical on
all three. What differs is that Squid's floors are ours to get right, which
is why `validate_policy_file()` checks the required ranges, the rule order
and the `deny_info` wiring for Squid specifically (docs/policy.md).

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
`templates/squid.conf.j2` now refuses address-form destinations before any
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
now reports `ip-literal-destination` on Squid instead of
`hostname-not-allowlisted`.

**The guard.** `ptr-allowlist` is a graded check: the fixture answers PTR
for `1.0.0.1` with `pypi.org`, and connecting to `1.0.0.1:443` must still
be denied. It was verified to fail against the unfixed config and pass
against the fixed one. Two things make it worth having as its own row:
`direct-ip-connect` passed throughout the bug's lifetime, because it uses
an address with no PTR claim — the existing suite could not see this. And
`validate_policy_file()` now requires `http_access deny ip_literal` ahead
of the allowlist, so deleting the rule fails `up` rather than silently
reopening the hole.

### 6. Pipelock follows redirects; the other two do not

**Measured 2026-08-28 by `scripts/upstream_fidelity.py`.** `allowed-http`
returns **200** through Pipelock and **301** through Smokescreen and Squid.
This was previously attributed to CDN variation. It is not.

pypi.org's edge answers a plain-HTTP request with `301 Location:
https://pypi.org/…`. Smokescreen and Squid hand that 301 to the client.
Pipelock fetches the target over HTTPS and hands back *that* response —
which for `/` is the origin's 200, `Server: gunicorn`, four Fastly hops.
Its own log states it, for a probe path unusual enough not to be confused
with anything else:

```json
{"event":"redirect","message":"redirect followed","hop":1,
 "original_url":"http://pypi.org/<probe>/probe?ipl=<probe>",
 "redirect_url":"https://pypi.org/<probe>/probe"}
{"event":"forward_http","url":"http://pypi.org/<probe>/probe?ipl=<probe>",
 "status_code":404}
```

Two things follow, and they point in opposite directions.

**The request itself is not rewritten.** `forward_http` quotes the request
target exactly as sent, query string and all, and the same probe through
Smokescreen and Squid comes back with the destination echoing that target
in its `Location`. No engine normalizes the request; the original question
is answered, and the answer is no.

**But the response the client gets is not always the destination's own
first answer.** Under Pipelock, a plain-HTTP request can be answered from a
*different URL* — a different scheme, a different path, potentially a
different host — chosen by the destination rather than by the client. The
proxy also originates the TLS connection for that fetch, on the plain-HTTP
path, where the client asked for no such thing.

**The redirect target is re-authorized.** This is the question that
matters — an engine that followed a redirect without re-checking would let
any allowlisted host redirect an agent anywhere — and it is answered.
`scripts/upstream_fidelity.py --redirect-authz` settles it with a
two-sided experiment, because a refusal on its own proves nothing:

| | Policy | Result |
| --- | --- | --- |
| Control | `github.com`, `*.github.com`, `*.githubusercontent.com` | **200**, the file's bytes arrive — the cross-host redirect really is followed, so the experiment can see a follow |
| Narrowed | `github.com`, `*.github.com` only | **403**, no bytes |

`github.com/octocat/Hello-World/raw/master/README` redirects to
`raw.githubusercontent.com`, a different host. Under a policy that allows
the source and not the target, Pipelock refuses before fetching, and says
why:

```json
{"event":"redirect","original_url":"http://github.com/octocat/Hello-World/raw/master/README",
 "redirect_url":"https://raw.githubusercontent.com/octocat/Hello-World/master/README"}
{"event":"blocked","url":"https://raw.githubusercontent.com","scanner":"allowlist",
 "reason":"redirect blocked: domain not in allowlist: raw.githubusercontent.com"}
```

Neither policy in that experiment is the shipped one: both are rendered to
a temporary file for the run, and `config.toml` is not touched. The
narrowing is the only way to reach the question, because every host in the
real allowlist redirects only to itself.

So redirect-following costs less than it first appeared. What remains true
is that under Pipelock a client can be answered from a URL it did not ask
for — every hop is *authorized*, but the response the client reads may
come from a different path, scheme or host than the one it requested, and
the proxy originates the TLS for that fetch on the plain-HTTP path.
Smokescreen and Squid hand the redirect back and let the client decide.
That is a difference in who follows the chain, not in what the allowlist
permits.

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
`templates/squid.conf.j2` so nobody re-enables it from first principles.

## Corrections to earlier runs

Things measured wrong and later fixed. Kept because each was believed for
a while, and the reasons are reusable.

* **`allowed-http`'s 200-vs-301 split was not CDN variation.** It was
  attributed to the upstream tier on captured headers: Smokescreen and
  Squid answered at the Fastly edge, Pipelock at pypi.org's origin. Both
  observations were correct and the conclusion drawn from them was wrong —
  Pipelock reaches the origin *because it follows the edge's redirect*, not
  because it was routed differently ([§6](#6-pipelock-follows-redirects-the-other-two-do-not)).
  The lesson is that "which tier answered" and "why that tier answered" are
  different questions, and response headers only answer the first.
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
  survived. An earlier revision reported a Squid result from exactly that
  setup; it did not show what it was said to show.
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
* **Docker publishes the host port before the engine listens.** The
  post-start probe could connect seconds early and `up` failed with
  `non-HTTP response: ''` on a healthy proxy. Apple `container` does not
  accept early, which is why the first run never hit it. `probe_proxy()`
  now separates a not-ready-yet probe (retried until the deadline) from a
  real verdict; a proxy that *answers* and allows the probe still fails
  immediately.

## Operational numbers

Measured 2026-08-28 on Docker by `scripts/verify_resilience.py`. Reported,
not graded: they are inputs to a judgement, not a pass or a fail.

| | Pipelock | Smokescreen | Squid |
| --- | --- | --- | --- |
| `up` to a healthy probe | 1.5s | 0.6s | 1.0s |
| Image size | 13 MB | 9 MB | 9 MB |
| Survives crash under load | yes, nothing leaked | yes, nothing leaked | yes, nothing leaked |
| Survives `restart` under load | yes, recovered | yes, recovered | yes, recovered |

Two things are worth reading off that table rather than the numbers. All
three are small and start in about a second, so startup and size are not
a reason to prefer any of them. And Squid is the one engine whose *first*
request after a cold start can take seconds — it resolves the destination
before it can serve anything — which is invisible in steady state and was
initially misread here as a failure to serve at all.

## Not yet measured

* Resource usage in steady state, and upgrade friction — the two
  operational numbers still uncollected.

## Decision

**Pipelock remains the default** (`DEFAULT_ENGINE` in `run.py`). It passes
every graded check, and it is the only engine that enforces inside the
CONNECT tunnel ([§1](#1-tunnel-layer-enforcement-pipelock-only)). The one
thing measured since is redirect-following
([§6](#6-pipelock-follows-redirects-the-other-two-do-not)): it is the only
engine that answers a client from a URL the client did not ask for. That
looked like it might be a hole in the allowlist and is not — every hop is
re-authorized, measured — so what is left is a difference in who follows
the chain, which does not outweigh being the only engine that can see
inside a tunnel.

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

**Smokescreen is a fallback with a known deviation.** It connects to the
public address of a mixed answer set
([§2](#2-mixed-dns-answers-smokescreen-connects-where-the-others-refuse)),
which docs/policy.md says it should refuse. That deviation is bounded — it
connects to the public address, not the private one, and reaching it needs
an *allowlisted* name to resolve to a private address, which an agent
cannot arrange for `github.com`. Choosing Smokescreen means accepting that
and unconstrained tunnel contents to allowlisted hosts.

Worth stating plainly, because pass counts invite the opposite reading: a
graded failure is not automatically the worse defect, and grading something
`record` does not make it go away. Smokescreen's deviation grants no reach
it did not already have. Squid's PTR bypass granted egress to any address
on the Internet and produced no failing row at all until a check was
written for it. The suite measures what it has been taught to measure,
which is an argument for reading
[§2](#2-mixed-dns-answers-smokescreen-connects-where-the-others-refuse),
[§5](#5-squid-a-bare-ip-could-satisfy-the-allowlist-through-a-reverse-lookup)
and [§6](#6-pipelock-follows-redirects-the-other-two-do-not) before reading
the counts in [comparison.md](comparison.md).
