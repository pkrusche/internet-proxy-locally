# Pipelock vs Smokescreen vs Squid — measured

Three engines, one adversarial suite, one conclusion: **Pipelock is the
default**, because it is the only one that enforces inside a CONNECT
tunnel. Everything below is why, and what it costs.

The tables are **generated** from `results/*.json` by `ipl-lab report` and
hold no opinions. The prose around them is written by hand and holds
nothing else. A stale table is therefore a diff (`ipl-lab report --check`),
not a belief.

The engine choice is empirical: run `ipl-check` against all three and
record what happens. Feature tables do not decide it.

## Conditions

<!-- BEGIN GENERATED conditions -->

| | Pipelock | Smokescreen | Squid |
| --- | --- | --- | --- |
| Measured | 2026-08-28T22:19:24Z | 2026-08-28T22:19:28Z | 2026-08-28T22:19:32Z |
| Backend | docker | docker | docker |
| Host | Darwin 25.6.0 arm64 | Darwin 25.6.0 arm64 | Darwin 25.6.0 arm64 |
| Image | `ghcr.io/luckypipewrench/pipelock@sha256:42b58a428defca8f57d74b005e865898deb9568c9d742e46b32c80b0d2b011f7` | `internet-proxy-locally/smokescreen:131fba29ce1e` | `internet-proxy-locally/squid:6.12-r0` |
| Policy | test (`ipl-lab up`) | test (`ipl-lab up`) | test (`ipl-lab up`) |
| Endpoint | `http://127.0.0.1:18081` | `http://127.0.0.1:18081` | `http://127.0.0.1:18081` |
| Result | 18 pass, 1 record | 15 pass, 4 record | 16 pass, 3 record |
| Exit code | 0 | 0 | 0 |

Source files: `results/pipelock.json`, `results/smokescreen.json`, `results/squid.json`.

<!-- END GENERATED conditions -->

To re-measure and rewrite every table in this file:

```bash
ipl-lab measure                    # all three engines, then rewrite
ipl-lab measure --backend docker   # or pin the backend
ipl-lab report --check             # CI: fail if these tables are stale
```

The result files are committed: without them the generated blocks could not
be re-derived or checked, only believed. How the lab works — the test
policy, the DNS fixture, what `ipl-lab up` does — is [lab.md](lab.md).

## Summary

<!-- BEGIN GENERATED summary -->

15 of the 19 checks are graded `pass`/`fail` on every engine. In that common pool:

* **Pipelock** passes all of them.
* **Smokescreen** passes all of them.
* **Squid** passes all of them.

**Passing that pool is not the same as behaving identically**, and the 4 check(s) it leaves out are where the engines differ: [`dns-mixed-answers`](#dns-mixed-answers), [`connect-sni-mismatch`](#connect-sni-mismatch), [`connect-raw-tunnel`](#connect-raw-tunnel), [`concurrency-sanity`](#concurrency-sanity). Each is graded `record` on at least one engine, which takes it out of any pass count — a `record` grade means no verdict is defined there, never that the behavior was the same. What each engine actually did is below.

**Different behavior** on 3 check(s) — one engine allowed what another refused:

* [`dns-mixed-answers`](#dns-mixed-answers) — Pipelock/Squid PASS [private-ip]; Smokescreen RECORD (allowed)
* [`connect-sni-mismatch`](#connect-sni-mismatch) — Pipelock PASS [sni-mismatch]; Smokescreen/Squid RECORD (allowed)
* [`connect-raw-tunnel`](#connect-raw-tunnel) — Pipelock PASS [non-tls-in-tunnel]; Smokescreen/Squid RECORD (allowed)

**Same behavior, different stated reason** on 10 check(s). These are not behavioral differences — the request was refused either way — but they say which rule did the refusing, which is what decides whether a row is evidence of the thing it is named after:

* [`direct-ip-connect`](#direct-ip-connect) — Pipelock/Smokescreen PASS [hostname-not-allowlisted]; Squid PASS [ip-literal-destination]
* [`loopback-ipv4`](#loopback-ipv4) — Pipelock/Smokescreen PASS [hostname-not-allowlisted]; Squid PASS [private-ip]
* [`rfc1918-ipv4`](#rfc1918-ipv4) — Pipelock/Smokescreen PASS [hostname-not-allowlisted]; Squid PASS [private-ip]
* [`link-local-ipv4`](#link-local-ipv4) — Pipelock/Smokescreen PASS [hostname-not-allowlisted]; Squid PASS [private-ip]
* [`metadata-endpoint`](#metadata-endpoint) — Pipelock/Smokescreen PASS [hostname-not-allowlisted]; Squid PASS [metadata]
* [`loopback-ipv6`](#loopback-ipv6) — Pipelock PASS [hostname-not-allowlisted]; Smokescreen PASS [unparseable-destination]; Squid PASS [private-ip]
* [`private-ipv6`](#private-ipv6) — Pipelock PASS [hostname-not-allowlisted]; Smokescreen PASS [unparseable-destination]; Squid PASS [private-ip]
* [`dns-private-ipv4`](#dns-private-ipv4) — Pipelock/Squid PASS [metadata+private-ip]; Smokescreen PASS [private-ip]
* [`dns-rebinding`](#dns-rebinding) — Pipelock/Smokescreen PASS [private-ip]; Squid PASS
* [`ptr-allowlist`](#ptr-allowlist) — Pipelock/Smokescreen PASS [hostname-not-allowlisted]; Squid PASS [ip-literal-destination]

<!-- END GENERATED summary -->

## Reading the results

**Most deny rows demonstrate the allowlist, not SSRF defence.** Asked to
CONNECT to `127.0.0.1:80`, Pipelock answers `domain not in allowlist:
127.0.0.1` and Smokescreen answers `default rule policy used`. Neither
reaches its private-IP logic, because a bare address is not on the
allowlist and is rejected on that basis first. The same holds for
`rfc1918-ipv4`, `link-local-ipv4`, `direct-ip-connect` and
`metadata-endpoint`. Under a default-deny allowlist these rows can only
ever demonstrate the allowlist. They are worth keeping as regression guards
— an engine that allowed them would be badly broken — but they are not
evidence of SSRF defence. Squid is the exception, for two structural
reasons: its SSRF floors sit above the allowlist (§4), and it refuses
address-form destinations outright (§5). This is why the summary above
separates "different behavior" from "same behavior, different stated
reason": the second list is where this shows up.

**Smokescreen never parses the IPv6 literals.** `[::1]:80` and `[fd00::1]:80`
are rejected with `Destination host cannot be determined` — a parse failure
ahead of any policy evaluation. Its pass on `loopback-ipv6`/`private-ipv6`
says nothing about its allowlist or its private-IP handling, which is why
`unparseable-destination` is a separate cause bucket.

**The fixture rows are the real evidence.** `dns-private-ipv4`,
`dns-private-ipv6`, `dns-mixed-answers`, `dns-rebinding` and
`ptr-allowlist` use hostnames that are *deliberately allowlisted*, so a
denial can only have come from re-validating the resolved address. Two of
the three engines validate after resolution, as [policy.md](policy.md)
requires, and say so:

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

Squid needed work to report *reasons* rather than just codes: its stock page
says only "Access control configuration prevents your request", which
classifies as `unknown`. `deny_info` plus five one-line templates in
`data/images/squid/errors` make each denial state its cause, which is what fills
the bracketed column in the matrix. The exact strings are pinned in
`tests/egress/test_denial.py::ClassifyDenialRealWordingTest`, and
the generated Squid config keeps the `deny_info` mappings beside the ACLs
they name. The live lab checks verify that each denial stays attributable.

## The differences that matter

### 1. Tunnel-layer enforcement: Pipelock only

The only capability gap, and the reason Pipelock is the default.

**SNI mismatch** — CONNECT to `pypi.org:443`, then send a ClientHello for
`files.pythonhosted.org`. Pipelock closes the connection at the ClientHello
(`SSL: UNEXPECTED_EOF_WHILE_READING`, from
`forward_proxy.sni_verification`). Smokescreen and Squid complete the
TLSv1.3 handshake: they authorize the CONNECT target and then go blind.

Both hosts are allowlisted, so this is not a bypass on its face. The
exposure is that the destination is then chosen by the *CDN* — both are
Fastly-fronted, so allowlisting one Fastly-fronted domain reaches whatever
else that edge routes by SNI.

**Raw protocol smuggling** — CONNECT to `pypi.org:443`, then send plaintext
HTTP. Pipelock closes the tunnel with no response
(`forward_proxy.sni_require_tls`). Smokescreen and Squid forward the bytes;
the reply was `fatal(2) decode_error(50)` then `warning(1) close_notify(0)`
— **TLS alerts from pypi.org, not from the proxy**. The bytes made the full
round trip and only the destination's own strictness stopped them.

So under Smokescreen or Squid, a client that can reach an allowlisted host
on 443 can speak any protocol to it and present any SNI. Squid narrows this
slightly: `http_access deny CONNECT !TLS_ports` confines tunnels to 443, so
an allowlisted host cannot be reached on an arbitrary port the way it can on
the other two. Squid could close the gap properly, and the configuration
that does it was measured and rejected — see [Rejected: tunnel peeking on
Squid](#rejected-tunnel-peeking-on-squid).

### 2. Mixed DNS answers: Smokescreen connects where the others refuse

The one place an engine's *behavior* deviates from [policy.md](policy.md). A
name resolving to both a public and a private address, served by the local
fixture, all three names allowlisted so a denial can only come from the
address check:

| Name | Answer |
| --- | --- |
| `public-only.fixture.test` | `9.9.9.9` — the control, must establish |
| `mixed-public-first.fixture.test` | `9.9.9.9`, then `10.0.0.1` |
| `mixed-private-first.fixture.test` | `10.0.0.1`, then `9.9.9.9` |

Both orderings are present so that an engine validating only the first
answer is distinguished from one validating all of them. The control runs
first: without it a denial would be unattributable, and the row skips rather
than banking a pass.

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
**It did not connect to `10.0.0.1`**, which bounds the severity: this is not
an SSRF hole on its own. It is what its denial wording always implied — "no
valid IP found among resolved addresses" fires only when *every* address is
invalid, so one public answer is enough to allow the name.

[policy.md](policy.md) says "a public hostname resolving to a private
address is rejected", and under that rule Smokescreen does not comply. The
residual risk is not the connection it made but the ones it might make
later: an engine that accepts a mixed answer has to be trusted never to fall
back to the other address on a retry and never to re-resolve without
re-validating. Neither is visible from outside.

**How it is graded, and why.** `deny` for every engine, the same expectation
`dns-mixed-answers` carries everywhere else. The suite used to carry a
per-engine override table (`ENGINE_EXPECTATIONS`) that turned this row
`record` for Smokescreen specifically, on the reasoning that a permanent
`fail` on one engine made the exit code useless for telling "a known,
bounded deviation" apart from "something just broke". That table is gone:
this repo ships one engine, Pipelock, and grading against what the shipped
config actually enforces is simpler and more honest than maintaining a
second, engine-shaped table of exceptions to it. Smokescreen now fails this
row like any other deny check would — which is accurate, since
[policy.md](policy.md) requires the connection not be made and Smokescreen
made it.

### 3. DNS rebinding: two different defences

The fixture answers the **first** lookup of a name with a public address and
**every later one** with its own private address, on which it listens as a
trap. Each name is probed twice, either side of a pause. **Only a trap hit
fails the check**: "did the engine reach a private address" is reported by
the thing that would have received the connection, not inferred from counts.

| | Pipelock | Smokescreen | Squid |
| --- | --- | --- | --- |
| Names rebound (of 3) | 3 | 3 | **0** |
| Lookups | 9 | 6 | 3 |
| Repeat probes denied | 3 | 3 | 0 (established) |
| Trap hits | 0 | 0 | 0 |

**Pipelock and Smokescreen re-resolve and re-validate.** Both were handed the
private address on every repeat lookup and refused all three, cause
`private-ip`. That is a rebind offered and declined.

**Squid never re-resolves, so it was never offered one.** Its ipcache pins
the address it validated: one lookup served six CONNECTs to the same name,
and a separate probe confirmed the entry survives **at least 68 seconds** of
repeated requests despite the fixture answering with TTL 0. That is a
legitimate defence — you cannot follow a rebind you never observe — but it
is a different mechanism, and `positive_dns_ttl` defaults to six hours, so
the address Squid connects to can be that stale.

Both designs pass, and neither is weaker than the other. The point is that
the row says *which* one an engine has, rather than hiding it in a pass
count.

### 4. Where the SSRF floors live

Pipelock and Smokescreen block private destinations in engine code; the
configuration only turns that on, and disabling it would take a deliberate
`--unsafe-allow-private-ranges`, which `ipl` refuses to load. Squid has
no built-in, so `config/squid.conf` states the floors as `dst` ACLs *above*
the allowlist — `http_access` is first-match-wins — and disabling one would
take deleting a line.

That changes what six rows attribute to. A bare `127.0.0.1:80` matches
`private_ip` before anything looks at names, so `loopback-ipv4`,
`rfc1918-ipv4`, `link-local-ipv4`, `loopback-ipv6` and `private-ipv6` read
`private-ip` on Squid and `metadata-endpoint` reads `metadata`, where the
other two read `hostname-not-allowlisted`. Squid is also the only engine
that parses `[::1]:80` and `[fd00::1]:80` as addresses rather than failing
on the literal, so its IPv6 rows are the only ones exercising IPv6 SSRF
defence outside the sslip.io fixture.

This is not "Squid is stricter" — the enforcement outcome is identical on
all three. What differs is that Squid's floors are ours to maintain.
They are fixed together in `data/templates/squid.conf.j2`: the required
ranges, their position before the first allow, the final default deny,
`cache deny all`, the complete opt-in interception recipe, and the five
`deny_info` mappings. The policy and live lab tests cover the generated
configuration and its behavior. Squid says nothing about a `deny_info` whose ACL no
longer exists — the page never fires and the denial falls back to the stock
page — so renaming `private_ip` without updating its page would turn every
SSRF denial into `unknown` while leaving a config that starts, validates and
denies exactly the same requests.

**Wildcards need two ACLs.** Squid refuses to start when a `dstdomain` list
holds both `d` and `.d`, and its `.d` form matches the apex as well — so it
cannot express `*.d` the way the shared policy means it. `d` becomes `acl
allowlist_exact dstdomain d`; `*.d` becomes `acl allowlist_wild dstdom_regex
-i \.d$`, an anchored suffix that matches subdomains only. The `squid_wild`
template filter writes that form and `_squid_regex_to_glob()` reads it back;
a test asserts they are inverses, so the generated file and any cross-engine
comparison cannot disagree about what a wildcard means.

### 5. Squid: a bare IP could satisfy the allowlist through a reverse lookup

**Found 2026-08-25, fixed 2026-08-26.** Found by accident while building the
DNS fixture: with the fixture serving DNS, `direct-ip-connect` — a bare
`CONNECT 1.1.1.1:443`, denied by every engine until then — started passing
through Squid.

The cause is documented Squid behavior: for `dstdomain` and `dstdom_regex`,
"a reverse lookup is tried if a IP based URL is used and no match is found".
So an address that matches nothing in the allowlist gets a second chance
under whatever name its PTR record claims — and PTR records belong to
whoever holds the address block, with no forward confirmation.

Measured deliberately afterwards, against the **real** policy
(github/pypi/npm only) with a resolver claiming `PTR(1.1.1.1) = pypi.org`:

| | `CONNECT 1.1.1.1:443` | `CONNECT 9.9.9.9:443` |
| --- | --- | --- |
| Pipelock | 403 `domain not in allowlist: 1.1.1.1` | 403 |
| Smokescreen | 407 `default rule policy used` | 407 |
| Squid (before the fix) | **200 Connection established** | 403 |

The PTR record was the only difference between the two addresses. That is a
full bypass of the destination allowlist — the control this service exists
to provide — and it sits squarely in the threat model: an agent exfiltrating
to a host its operator controls only has to set that host's reverse DNS.
Pipelock and Smokescreen match the literal and never reverse-resolve.

It never defeated the SSRF floors — `private_ip`/`metadata_ip` are `dst`
rules evaluated first — so the exposure was reaching a *public* address not
on the allowlist.

**The fix.** Squid has no switch to disable the fallback, so
`data/templates/squid.conf.j2` refuses address-form destinations before any
`dstdomain` rule is reached:

```squid
acl ip_literal dstdom_regex -i ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$
acl ip_literal dstdom_regex -i ^\[?[0-9a-f]*:[0-9a-f:.]*\]?$
http_access deny ip_literal
```

Nothing is lost: [policy.md](policy.md) allowlists by hostname and never by
address, so a bare address could only ever have been denied. Matching the
literal form also keeps the fix itself out of the trap — the reverse lookup
happens only when *no* match is found, and these patterns match, so
evaluation stops and no PTR query is made.

**The guard.** `ptr-allowlist` is a graded check: the fixture answers PTR for
`1.0.0.1` with `pypi.org`, and connecting to `1.0.0.1:443` must still be
denied. It was verified to fail against the unfixed config and pass against
the fixed one. Two things make it worth its own row: `direct-ip-connect`
passed throughout the bug's lifetime, because it uses an address with no PTR
claim — the existing suite could not see this. The fixed Squid template
places `http_access deny ip_literal` ahead of the allowlist, and the graded
check catches regressions in the behavior.

### 6. Pipelock follows redirects; the other two do not

**Measured 2026-08-28.** `allowed-http` returns **200** through Pipelock and
**301** through Smokescreen and Squid. This was previously attributed to CDN
variation. It is not.

pypi.org's edge answers a plain-HTTP request with `301 Location:
https://pypi.org/…`. Smokescreen and Squid hand that 301 to the client.
Pipelock fetches the target over HTTPS and hands back *that* response —
which for `/` is the origin's 200. Its own log states it, for a probe path
unusual enough not to be confused with anything else:

```json
{"event":"redirect","message":"redirect followed","hop":1,
 "original_url":"http://pypi.org/<probe>/probe?ipl=<probe>",
 "redirect_url":"https://pypi.org/<probe>/probe"}
{"event":"forward_http","url":"http://pypi.org/<probe>/probe?ipl=<probe>",
 "status_code":404}
```

Two things follow, pointing in opposite directions.

**The request itself is not rewritten.** `forward_http` quotes the request
target exactly as sent, query string and all, and the same probe through
Smokescreen and Squid comes back with the destination echoing that target in
its `Location`. No engine normalizes the request; the original suspicion —
that a proxy was silently upgrading plain HTTP to HTTPS — is answered, and
the answer is no.

**But the response the client gets is not always the destination's own first
answer.** Under Pipelock, a plain-HTTP request can be answered from a
*different URL* — a different scheme, path, or host — chosen by the
destination rather than by the client. The proxy also originates the TLS
connection for that fetch, on the plain-HTTP path, where the client asked for
no such thing.

**The redirect target is re-authorized.** This is the question that matters —
an engine that followed a redirect without re-checking would let any
allowlisted host redirect an agent anywhere — and it is answered by a
two-sided experiment, because a refusal on its own proves nothing:

| | Policy | Result |
| --- | --- | --- |
| Control | `github.com`, `*.github.com`, `*.githubusercontent.com` | **200**, the file's bytes arrive — the cross-host redirect really is followed, so the experiment can see a follow |
| Narrowed | `github.com`, `*.github.com` only | **403**, no bytes |

`github.com/octocat/Hello-World/raw/master/README` redirects to
`raw.githubusercontent.com`, a different host. Under a policy that allows the
source and not the target, Pipelock refuses before fetching, and says why:

```json
{"event":"blocked","url":"https://raw.githubusercontent.com","scanner":"allowlist",
 "reason":"redirect blocked: domain not in allowlist: raw.githubusercontent.com"}
```

The narrowing is the only way to reach the question, because every host in
the real allowlist redirects only to itself.

So redirect-following costs less than it first appeared. What remains true is
that under Pipelock a client can be answered from a URL it did not ask for —
every hop is *authorized*, but the response may come from a different path,
scheme or host, and the proxy originates the TLS for that fetch on the
plain-HTTP path. Smokescreen and Squid hand the redirect back and let the
client decide. That is a difference in who follows the chain, not in what the
allowlist permits.

## Rejected: tunnel peeking on Squid

Squid supports `ssl_bump peek` + `splice`: read the TLS ClientHello, apply
ACLs to the SNI, pass the connection through undecrypted. On paper that
closes §1 with no CA and no interception. It was built and measured. Three
results, worst first:

1. **It crashes the daemon.** The first connection that must be terminated
   after a peek — a non-allowlisted SNI, or non-TLS bytes — aborts the
   process:

   ```text
   FATAL: assertion failed: client_side.cc:2714: "port->secure.signingCa.cert.get()"
   ```

   Squid reaches for a signing certificate on a path that never signs
   anything. Any client can trigger it. The fail-closed consequence is benign
   — nothing listens on 18080, so the sandbox loses Internet — but a
   trivially remote-triggerable abort is not a proxy anyone should run.
2. **Avoiding it means a CA in the image.** Supplying `cert=`/`sslcrtd_program`
   with a signing key is what the assertion wants, and private-key custody is
   an explicit non-goal ([security.md](security.md)).
   `generate-host-certificates=off` looks like a way out and is not: it
   silently disables bumping on the port, so the config *appears* to enforce
   and does not.
3. **Every CONNECT is answered `200` before policy runs.** Squid acknowledges
   the tunnel, peeks, then applies `http_access` and aborts —
   `TCP_DENIED_ABORTED/200 CONNECT 127.0.0.1:80` in its own log. Policy holds
   and nothing reaches the destination, but the client is told the tunnel
   succeeded, which breaks the contract that a denial is visible to the
   caller.

So Squid ships without `ssl_bump` **by default**. The reasoning above is
repeated at the top of `data/templates/squid.conf.j2` so nobody re-enables
it from first principles.

**Addendum, opt-in TLS interception (docs/tls-interception.md):** the
three failures above are all specific to `peek` + `splice` *without* a
signing CA — the configuration that was actually built and measured here.
Full `ssl_bump ... bump` *with* a real CA is a structurally different
mode: Squid becomes the real TLS endpoint, decrypts, evaluates
`http_access` against the actual request, and answers a real HTTP 4xx
instead of aborting an opaque tunnel — which is exactly what closes
failure 1 (there is now a signing certificate to reach for) and failure 3
(policy runs before the client is told anything succeeded). This mode
ships as opt-in (`[policy].tls_interception = true`), off by default, with
one template branch emitting the complete recipe — `ssl_bump peek step1`
paired with `ssl_bump bump all`, never one without the other.

## Operational numbers

Measured 2026-08-28 on Docker. These are reported observations, not grades.

| | Pipelock | Smokescreen | Squid |
| --- | --- | --- | --- |
| `up` to a healthy probe | 1.5s | 0.6s | 1.0s |
| Image size | 13 MB | 9 MB | 9 MB |
| Survives crash under load | yes, nothing leaked | yes, nothing leaked | yes, nothing leaked |
| Survives `restart` under load | yes, recovered | yes, recovered | yes, recovered |

Two things are worth reading off that table rather than the numbers. All
three are small and start in about a second, so startup and size are not a
reason to prefer any of them. And Squid is the one engine whose *first*
request after a cold start can take seconds — it resolves the destination
before it can serve anything — which is invisible in steady state and was
initially misread here as a failure to serve at all.

Still uncollected: resource usage in steady state, and upgrade friction.

## Decision

**Pipelock is the default** (`DEFAULT_ENGINE` in `constants.py`). It passes every
graded check, and it is the only engine that enforces inside the CONNECT
tunnel (§1). The one thing measured against it is redirect-following (§6): it
is the only engine that answers a client from a URL the client did not ask
for. That looked like it might be a hole in the allowlist and is not — every
hop is re-authorized, measured with a control — so what is left is a
difference in who follows the chain, which does not outweigh being the only
engine that can see inside a tunnel.

**Squid is the alternative to reach for when the policy itself has to be
auditable.** It passes every graded check. Its tunnel exposure matches
Smokescreen's, narrowed by the CONNECT port restriction. In exchange, every
rule is visible in one file with a stated evaluation order rather than being
engine behavior you must trust and cannot inspect — which is also why `up`
validates that file harder than the other two (§4).

The case against it is the shape of its one serious defect. The PTR allowlist
bypass (§5) was a complete hole in the destination allowlist, it was found by
accident rather than by the suite, and it existed because Squid brings
behavior we did not ask for — a large general-purpose proxy has more of that
than a small purpose-built one. It is fixed and now guarded, but the class of
problem is not closed, and it is a fair argument for preferring an engine
with less surface. Squid is also the only engine that never re-resolves,
which cuts both ways (§3).

**Smokescreen is the one to choose deliberately or not at all.** It deviates
on mixed DNS answers (§2), which now fails the row like any other deny
check. Choosing it means accepting that deviation, plus unconstrained tunnel
contents to allowlisted hosts (§1).

## Matrix

<!-- BEGIN GENERATED matrix -->

Bracketed values are the **attributed cause**: what the engine said it was rejecting, not what the check is named after. A blank one means nothing was denied, so there is no reason to attribute.

| Check | Group | Expectation | Pipelock | Smokescreen | Squid |
| --- | --- | --- | --- | --- | --- |
| [allowed-http](#allowed-http) | quick | allow | PASS | PASS | PASS |
| [allowed-https](#allowed-https) | quick | allow | PASS | PASS | PASS |
| [blocked-host-connect](#blocked-host-connect) | quick | deny | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] |
| [blocked-host-http](#blocked-host-http) | quick | deny | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] |
| [direct-ip-connect](#direct-ip-connect) | quick | deny | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] | PASS [ip-literal-destination] |
| [loopback-ipv4](#loopback-ipv4) | quick | deny | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] | PASS [private-ip] |
| [rfc1918-ipv4](#rfc1918-ipv4) | quick | deny | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] | PASS [private-ip] |
| [link-local-ipv4](#link-local-ipv4) | quick | deny | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] | PASS [private-ip] |
| [metadata-endpoint](#metadata-endpoint) | quick | deny | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] | PASS [metadata] |
| [loopback-ipv6](#loopback-ipv6) | quick | deny | PASS [hostname-not-allowlisted] | PASS [unparseable-destination] | PASS [private-ip] |
| [private-ipv6](#private-ipv6) | quick | deny | PASS [hostname-not-allowlisted] | PASS [unparseable-destination] | PASS [private-ip] |
| [dns-private-ipv4](#dns-private-ipv4) | full | deny | PASS [metadata+private-ip] | PASS [private-ip] | PASS [metadata+private-ip] |
| [dns-private-ipv6](#dns-private-ipv6) | full | deny | PASS [private-ip] | PASS [private-ip] | PASS [private-ip] |
| [dns-rebinding](#dns-rebinding) | full | deny | PASS [private-ip] | PASS [private-ip] | PASS |
| [dns-mixed-answers](#dns-mixed-answers) | full | deny/record | PASS [private-ip] | RECORD (allowed) | PASS [private-ip] |
| [ptr-allowlist](#ptr-allowlist) | full | deny | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] | PASS [ip-literal-destination] |
| [connect-sni-mismatch](#connect-sni-mismatch) | full | deny/record | PASS [sni-mismatch] | RECORD (allowed) | RECORD (allowed) |
| [connect-raw-tunnel](#connect-raw-tunnel) | full | deny/record | PASS [non-tls-in-tunnel] | RECORD (allowed) | RECORD (allowed) |
| [concurrency-sanity](#concurrency-sanity) | full | record | RECORD | RECORD | RECORD |

Where the expectation column shows two values, the check was graded differently per engine in this run.

<!-- END GENERATED matrix -->

## Every check, and what each engine did

<!-- BEGIN GENERATED per-check -->

### allowed-http

A plain-HTTP GET to an allowlisted host reaches it.

* **Pipelock** — PASS (expectation: allow, 298ms)  
  reached pypi.org (HTTP/1.1 200 OK)
* **Smokescreen** — PASS (expectation: allow, 32ms)  
  reached pypi.org (HTTP/1.1 301 Moved Permanently)
* **Squid** — PASS (expectation: allow, 27ms)  
  reached pypi.org (HTTP/1.1 301 Moved Permanently)

### allowed-https

A CONNECT tunnel to an allowlisted host completes a real TLS handshake, so ordinary HTTPS works through the proxy.

* **Pipelock** — PASS (expectation: allow, 30ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Smokescreen** — PASS (expectation: allow, 31ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Squid** — PASS (expectation: allow, 25ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)

### blocked-host-connect

CONNECT to a host that is not on the allowlist is refused — the default-deny rule, on the tunnel path.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: example.com
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host 'example.com:443': default rule policy used.
* **Squid** — PASS [hostname-not-allowlisted] (expectation: deny, 9ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is not in the allowlist.

### blocked-host-http

A plain-HTTP GET to a host that is not on the allowlist is refused — the same rule on the request path.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — blocked: domain not in allowlist: example.com
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Proxy Authentication Required — Egress proxying is denied to host 'example.com': default rule policy used.
* **Squid** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is not in the allowlist.

### direct-ip-connect

A destination written as a bare address is refused. Under a hostname allowlist it can only ever be denied; which rule denies it is what the cause column shows.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 1.1.1.1
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '1.1.1.1:443': default rule policy used.
* **Squid** — PASS [ip-literal-destination] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is a bare IP address, and this proxy allowlists destinations by hostname only.

### loopback-ipv4

CONNECT to 127.0.0.1 is refused.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 127.0.0.1
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '127.0.0.1:80': default rule policy used.
* **Squid** — PASS [private-ip] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### rfc1918-ipv4

CONNECT to RFC1918 space (10/8, 172.16/12, 192.168/16) is refused.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 10.0.0.1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 192.168.1.1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 172.16.0.1
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '10.0.0.1:80': default rule policy used.; denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '192.168.1.1:80': default rule policy used.; denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '172.16.0.1:80': default rule policy used.
* **Squid** — PASS [private-ip] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### link-local-ipv4

CONNECT to 169.254.0.0/16 is refused.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 169.254.1.1
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '169.254.1.1:80': default rule policy used.
* **Squid** — PASS [private-ip] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### metadata-endpoint

The cloud metadata address is refused over both CONNECT and plain HTTP.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied for CONNECT and GET (CONNECT: denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 169.254.169.254; GET: denied: HTTP/1.1 403 Forbidden — blocked: domain not in allowlist: 169.254.169.254)
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied for CONNECT and GET (CONNECT: denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '169.254.169.254:80': default rule policy used.; GET: denied: HTTP/1.1 407 Proxy Authentication Required — Egress proxying is denied to host '169.254.169.254': default rule policy used.)
* **Squid** — PASS [metadata] (expectation: deny, 1ms)  
  denied for CONNECT and GET (CONNECT: denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a cloud metadata endpoint.; GET: denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a cloud metadata endpoint.)

### loopback-ipv6

CONNECT to [::1] is refused.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: ::1
* **Smokescreen** — PASS [unparseable-destination] (expectation: deny, 2ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '[::1]:80': Destination host cannot be determined.
* **Squid** — PASS [private-ip] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### private-ipv6

CONNECT to ULA and link-local IPv6 (fd00::1, fe80::1) is refused.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fd00::1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fe80::1
* **Smokescreen** — PASS [unparseable-destination] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '[fd00::1]:80': Destination host cannot be determined.; denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '[fe80::1]:80': Destination host cannot be determined.
* **Squid** — PASS [private-ip] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### dns-private-ipv4

An *allowlisted* name that resolves to a private IPv4 address is refused, so the denial can only have come from validating the resolved address (nip.io).

* **Pipelock** — PASS [metadata+private-ip] (expectation: deny, 147ms, 4 probes)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt
* **Smokescreen** — PASS [private-ip] (expectation: deny, 13ms, 4 probes)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt
* **Squid** — PASS [metadata+private-ip] (expectation: deny, 12ms, 4 probes)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt

### dns-private-ipv6

The same, for IPv6 (sslip.io).

* **Pipelock** — PASS [private-ip] (expectation: deny, 148ms, 3 probes)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt
* **Smokescreen** — PASS [private-ip] (expectation: deny, 9ms, 3 probes)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt
* **Squid** — PASS [private-ip] (expectation: deny, 8ms, 3 probes)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt

### dns-rebinding

A name whose answer changes between the first lookup and the next does not get the engine to a private address. Graded on whether the fixture's trap was reached, not on counts.

* **Pipelock** — PASS [private-ip] (expectation: deny, 1594ms, 6 probes)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (9 lookups total); of the 3 repeat probes, 3 were denied and 0 established
* **Smokescreen** — PASS [private-ip] (expectation: deny, 1601ms, 6 probes)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (6 lookups total); of the 3 repeat probes, 3 were denied and 0 established
* **Squid** — PASS (expectation: deny, 1623ms, 6 probes)  
  no connection reached the trap. 0/3 names were resolved more than once and so were handed the private address (3 lookups total); of the 3 repeat probes, 0 were denied and 3 established — but the engine resolved each name only once, so it was never offered the rebind and this run did not exercise one

### dns-mixed-answers

A name resolving to a public *and* a private address is refused, in both answer orderings — every address in the answer set is validated, not just the first or the routable one.

* **Pipelock** — PASS [private-ip] (expectation: deny, 53ms, 3 probes)  
  control public-only.fixture.test established, and both mixed-answer names (public-first and private-first) were denied — every address in the answer set is validated, not only the first one or the routable one
* **Smokescreen** — RECORD (allowed) (expectation: record, 34ms, 3 probes)  
  observed: allowed — mixed-public-first.fixture.test:443 established — the engine connected although a private address was in the answer set; mixed-private-first.fixture.test:443 established — the engine connected although a private address was in the answer set
* **Squid** — PASS [private-ip] (expectation: deny, 22ms, 3 probes)  
  control public-only.fixture.test established, and both mixed-answer names (public-first and private-first) were denied — every address in the answer set is validated, not only the first one or the routable one

### ptr-allowlist

An address whose PTR record claims an allowlisted hostname is still refused, so a reverse lookup cannot satisfy the allowlist.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 41ms, 1 probes)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 1.0.0.1; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 38ms, 1 probes)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '1.0.0.1:443': default rule policy used.; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Squid** — PASS [ip-literal-destination] (expectation: deny, 36ms, 1 probes)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is a bare IP address, and this proxy allowlists destinations by hostname only.; the engine performed no reverse lookup, so the allowlist was never offered the PTR name

### connect-sni-mismatch

A tunnel to one allowlisted host carrying a ClientHello for another is refused — enforcement inside the CONNECT tunnel.

* **Pipelock** — PASS [sni-mismatch] (expectation: deny, 17ms)  
  tunnel established but TLS handshake failed (SNI=files.pythonhosted.org): [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1032)
* **Smokescreen** — RECORD (allowed) (expectation: record, 26ms)  
  observed: allowed — mismatched SNI accepted: tunnel established, TLSv1.3 handshake OK (SNI=files.pythonhosted.org)
* **Squid** — RECORD (allowed) (expectation: record, 24ms)  
  observed: allowed — mismatched SNI accepted: tunnel established, TLSv1.3 handshake OK (SNI=files.pythonhosted.org)

### connect-raw-tunnel

A tunnel to an allowlisted host on 443 carrying plaintext rather than TLS is refused — enforcement inside the CONNECT tunnel.

* **Pipelock** — PASS [non-tls-in-tunnel] (expectation: deny, 16ms)  
  tunnel established; connection closed with no response to raw (non-TLS) bytes — consistent with a non-TLS-in-tunnel policy check
* **Smokescreen** — RECORD (allowed) (expectation: record, 26ms)  
  observed: allowed — raw bytes traversed the tunnel; response: type=alert(21) version=TLS1.2 length=2 -> alert level=fatal(2) description=decode_error(50); type=alert(21) version=TLS1.2 length=2 -> alert level=warning(1) description=close_notify(0)
* **Squid** — RECORD (allowed) (expectation: record, 20ms)  
  observed: allowed — raw bytes traversed the tunnel; response: type=alert(21) version=TLS1.2 length=2 -> alert level=fatal(2) description=decode_error(50); type=alert(21) version=TLS1.2 length=2 -> alert level=warning(1) description=close_notify(0)

### concurrency-sanity

Ten simultaneous CONNECTs to an allowed host all succeed — the proxy is not serializing or dropping under trivial load.

* **Pipelock** — RECORD (expectation: record, 23ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Smokescreen** — RECORD (expectation: record, 20ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Squid** — RECORD (expectation: record, 17ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed

<!-- END GENERATED per-check -->
