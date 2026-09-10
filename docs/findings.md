# Comparison of results using egress check suite

The tables are **generated** from `results/*.json` by `ipl-lab report`.

## Conditions

<!-- BEGIN GENERATED conditions -->

| | Pipelock | Smokescreen | Squid |
| --- | --- | --- | --- |
| Measured | 2026-09-10T06:59:16Z | 2026-09-10T06:59:20Z | 2026-09-10T06:59:25Z |
| Backend | docker | docker | docker |
| Host | Darwin 25.6.0 arm64 | Darwin 25.6.0 arm64 | Darwin 25.6.0 arm64 |
| Image | `internet-proxy-locally/pipelock:3.3.0` | `internet-proxy-locally/smokescreen:131fba29ce1e-build1` | `internet-proxy-locally/squid:6.12-r0-build1` |
| Policy | test (`ipl-lab up`) | test (`ipl-lab up`) | test (`ipl-lab up`) |
| TLS interception | on | off | on |
| Endpoint | `http://127.0.0.1:18080` | `http://127.0.0.1:18080` | `http://127.0.0.1:18080` |
| Result | 18 pass, 1 record | 15 pass, 3 fail, 1 record | 17 pass, 1 fail, 1 record |
| Exit code | 0 | 1 | 1 |

Source files: `results/pipelock.json`, `results/smokescreen.json`, `results/squid.json`.

<!-- END GENERATED conditions -->

## Summary

<!-- BEGIN GENERATED summary -->

18 of the 19 checks are graded `pass`/`fail` on every engine. In that common pool:

* **Pipelock** passes all of them.
* **Smokescreen** does not pass `dns-mixed-answers` (fail), `connect-sni-mismatch` (fail), `connect-raw-tunnel` (fail).
* **Squid** does not pass `connect-sni-mismatch` (fail).

**Passing that pool is not the same as behaving identically**, and the 1 check(s) it leaves out are where the engines differ: [`concurrency-sanity`](#concurrency-sanity). Each is graded `record` on at least one engine, which takes it out of any pass count — a `record` grade means no verdict is defined there, never that the behavior was the same. What each engine actually did is below.

**Different behavior** on 3 check(s) — one engine allowed what another refused:

* [`dns-mixed-answers`](#dns-mixed-answers) — Pipelock/Squid PASS [private-ip]; Smokescreen FAIL
* [`connect-sni-mismatch`](#connect-sni-mismatch) — Pipelock PASS [sni-mismatch]; Smokescreen/Squid FAIL [sni-mismatch]
* [`connect-raw-tunnel`](#connect-raw-tunnel) — Pipelock/Squid PASS [non-tls-in-tunnel]; Smokescreen FAIL [non-tls-in-tunnel]

**Same behavior, different stated reason** on 9 check(s). These are not behavioral differences — the request was refused either way — but they say which rule did the refusing, which is what decides whether a row is evidence of the thing it is named after:

* [`direct-ip-connect`](#direct-ip-connect) — Pipelock/Smokescreen PASS [hostname-not-allowlisted]; Squid PASS [ip-literal-destination]
* [`loopback-ipv4`](#loopback-ipv4) — Pipelock/Smokescreen PASS [hostname-not-allowlisted]; Squid PASS [private-ip]
* [`rfc1918-ipv4`](#rfc1918-ipv4) — Pipelock/Smokescreen PASS [hostname-not-allowlisted]; Squid PASS [private-ip]
* [`link-local-ipv4`](#link-local-ipv4) — Pipelock/Smokescreen PASS [hostname-not-allowlisted]; Squid PASS [private-ip]
* [`metadata-endpoint`](#metadata-endpoint) — Pipelock/Smokescreen PASS [hostname-not-allowlisted]; Squid PASS [metadata]
* [`loopback-ipv6`](#loopback-ipv6) — Pipelock PASS [hostname-not-allowlisted]; Smokescreen PASS [unparseable-destination]; Squid PASS [private-ip]
* [`private-ipv6`](#private-ipv6) — Pipelock PASS [hostname-not-allowlisted]; Smokescreen PASS [unparseable-destination]; Squid PASS [private-ip]
* [`dns-private-ipv4`](#dns-private-ipv4) — Pipelock/Squid PASS [metadata+private-ip]; Smokescreen PASS [private-ip]
* [`ptr-allowlist`](#ptr-allowlist) — Pipelock/Smokescreen PASS [hostname-not-allowlisted]; Squid PASS [ip-literal-destination]

<!-- END GENERATED summary -->

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
| [dns-rebinding](#dns-rebinding) | full | deny | PASS [private-ip] | PASS [private-ip] | PASS [private-ip] |
| [dns-mixed-answers](#dns-mixed-answers) | full | deny | PASS [private-ip] | FAIL | PASS [private-ip] |
| [ptr-allowlist](#ptr-allowlist) | full | deny | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] | PASS [ip-literal-destination] |
| [connect-sni-mismatch](#connect-sni-mismatch) | full | deny | PASS [sni-mismatch] | FAIL [sni-mismatch] | FAIL [sni-mismatch] |
| [connect-raw-tunnel](#connect-raw-tunnel) | full | deny | PASS [non-tls-in-tunnel] | FAIL [non-tls-in-tunnel] | PASS [non-tls-in-tunnel] |
| [concurrency-sanity](#concurrency-sanity) | full | record | RECORD | RECORD | RECORD |

<!-- END GENERATED matrix -->

## Every check, and what each engine did

<!-- BEGIN GENERATED per-check -->

### allowed-http

A plain-HTTP GET to an allowlisted host reaches it.

* **Pipelock** — PASS (expectation: allow, 283ms)  
  reached pypi.org (HTTP/1.1 200 OK)
* **Smokescreen** — PASS (expectation: allow, 25ms)  
  reached pypi.org (HTTP/1.1 301 Moved Permanently)
* **Squid** — PASS (expectation: allow, 31ms)  
  reached pypi.org (HTTP/1.1 301 Moved Permanently)

### allowed-https

A CONNECT tunnel to an allowlisted host completes a real TLS handshake, so ordinary HTTPS works through the proxy.

* **Pipelock** — PASS (expectation: allow, 20ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Smokescreen** — PASS (expectation: allow, 29ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Squid** — PASS (expectation: allow, 40ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)

### blocked-host-connect

CONNECT to a host that is not on the allowlist is refused — the default-deny rule, on the tunnel path.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: example.com
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host 'example.com:443': default rule policy used.
* **Squid** — PASS [hostname-not-allowlisted] (expectation: deny, 12ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is not in the allowlist.

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
* **Squid** — PASS [ip-literal-destination] (expectation: deny, 4ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is a bare IP address, and this proxy allowlists destinations by hostname only.

### loopback-ipv4

CONNECT to 127.0.0.1 is refused.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 127.0.0.1
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '127.0.0.1:80': default rule policy used.
* **Squid** — PASS [private-ip] (expectation: deny, 4ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### rfc1918-ipv4

CONNECT to RFC1918 space (10/8, 172.16/12, 192.168/16) is refused.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 10.0.0.1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 192.168.1.1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 172.16.0.1
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '10.0.0.1:80': default rule policy used.; denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '192.168.1.1:80': default rule policy used.; denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '172.16.0.1:80': default rule policy used.
* **Squid** — PASS [private-ip] (expectation: deny, 9ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### link-local-ipv4

CONNECT to 169.254.0.0/16 is refused.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 169.254.1.1
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '169.254.1.1:80': default rule policy used.
* **Squid** — PASS [private-ip] (expectation: deny, 4ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### metadata-endpoint

The cloud metadata address is refused over both CONNECT and plain HTTP.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied for CONNECT and GET (CONNECT: denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 169.254.169.254; GET: denied: HTTP/1.1 403 Forbidden — blocked: domain not in allowlist: 169.254.169.254)
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied for CONNECT and GET (CONNECT: denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '169.254.169.254:80': default rule policy used.; GET: denied: HTTP/1.1 407 Proxy Authentication Required — Egress proxying is denied to host '169.254.169.254': default rule policy used.)
* **Squid** — PASS [metadata] (expectation: deny, 4ms)  
  denied for CONNECT and GET (CONNECT: denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a cloud metadata endpoint.; GET: denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a cloud metadata endpoint.)

### loopback-ipv6

CONNECT to [::1] is refused.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: ::1
* **Smokescreen** — PASS [unparseable-destination] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '[::1]:80': Destination host cannot be determined.
* **Squid** — PASS [private-ip] (expectation: deny, 4ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### private-ipv6

CONNECT to ULA and link-local IPv6 (fd00::1, fe80::1) is refused.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fd00::1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fe80::1
* **Smokescreen** — PASS [unparseable-destination] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '[fd00::1]:80': Destination host cannot be determined.; denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '[fe80::1]:80': Destination host cannot be determined.
* **Squid** — PASS [private-ip] (expectation: deny, 6ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### dns-private-ipv4

An *allowlisted* name that resolves to a private IPv4 address is refused, so the denial can only have come from validating the resolved address (nip.io).

* **Pipelock** — PASS [metadata+private-ip] (expectation: deny, 171ms, 4 probes)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt
* **Smokescreen** — PASS [private-ip] (expectation: deny, 16ms, 4 probes)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt
* **Squid** — PASS [metadata+private-ip] (expectation: deny, 24ms, 4 probes)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt

### dns-private-ipv6

The same, for IPv6 (sslip.io).

* **Pipelock** — PASS [private-ip] (expectation: deny, 121ms, 3 probes)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt
* **Smokescreen** — PASS [private-ip] (expectation: deny, 11ms, 3 probes)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt
* **Squid** — PASS [private-ip] (expectation: deny, 17ms, 3 probes)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt

### dns-rebinding

A name whose answer changes between the first lookup and the next does not get the engine to a private address. Graded on whether the fixture's trap was reached, not on counts.

* **Pipelock** — PASS [private-ip] (expectation: deny, 1593ms, 6 probes)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (9 lookups total); of the 3 repeat probes, 3 were denied, 0 carried HTTP traffic, and 0 were inconclusive
* **Smokescreen** — PASS [private-ip] (expectation: deny, 1591ms, 6 probes)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (6 lookups total); of the 3 repeat probes, 3 were denied, 0 carried HTTP traffic, and 0 were inconclusive
* **Squid** — PASS [private-ip] (expectation: deny, 1612ms, 6 probes)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (6 lookups total); of the 3 repeat probes, 3 were denied, 0 carried HTTP traffic, and 0 were inconclusive

### dns-mixed-answers

A name resolving to a public *and* a private address is refused, in both answer orderings — every address in the answer set is validated, not just the first or the routable one.

* **Pipelock** — PASS [private-ip] (expectation: deny, 116ms, 3 probes)  
  control public-only.fixture.test established, and both mixed-answer names (public-first and private-first) were denied — every address in the answer set is validated, not only the first one or the routable one
* **Smokescreen** — FAIL (expectation: deny, 69ms, 3 probes)  
  mixed-public-first.fixture.test:443 established — the engine connected although a private address was in the answer set; mixed-private-first.fixture.test:443 established — the engine connected although a private address was in the answer set
* **Squid** — PASS [private-ip] (expectation: deny, 69ms, 3 probes)  
  control public-only.fixture.test established, and both mixed-answer names (public-first and private-first) were denied — every address in the answer set is validated, not only the first one or the routable one

### ptr-allowlist

An address whose PTR record claims an allowlisted hostname is still refused, so a reverse lookup cannot satisfy the allowlist.

* **Pipelock** — PASS [hostname-not-allowlisted] (expectation: deny, 38ms, 1 probes)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 1.0.0.1; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Smokescreen** — PASS [hostname-not-allowlisted] (expectation: deny, 38ms, 1 probes)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '1.0.0.1:443': default rule policy used.; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Squid** — PASS [ip-literal-destination] (expectation: deny, 40ms, 1 probes)  
  denied: HTTP/1.1 200 Connection established — denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is a bare IP address, and this proxy allowlists destinations by hostname only.; the engine performed no reverse lookup, so the allowlist was never offered the PTR name

### connect-sni-mismatch

A tunnel to one allowlisted host carrying a ClientHello for another is refused — enforcement inside the CONNECT tunnel.

* **Pipelock** — PASS [sni-mismatch] (expectation: deny, 33ms)  
  mismatched SNI refused: tunnel established but TLS handshake failed (SNI=files.pythonhosted.org): [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1032) — the matching-SNI control to the same host completed (tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)), so the refusal is the proxy's rather than the origin's
* **Smokescreen** — FAIL [sni-mismatch] (expectation: deny, 26ms)  
  mismatched SNI accepted: tunnel established, TLSv1.3 handshake OK (SNI=files.pythonhosted.org)
* **Squid** — FAIL [sni-mismatch] (expectation: deny, 40ms)  
  mismatched SNI accepted: tunnel established, TLSv1.3 handshake OK (SNI=files.pythonhosted.org)

### connect-raw-tunnel

A tunnel to an allowlisted host on 443 carrying plaintext rather than TLS is refused — enforcement inside the CONNECT tunnel.

* **Pipelock** — PASS [non-tls-in-tunnel] (expectation: deny, 15ms)  
  tunnel established; connection closed with no response to raw (non-TLS) bytes — consistent with a non-TLS-in-tunnel policy check
* **Smokescreen** — FAIL [non-tls-in-tunnel] (expectation: deny, 22ms)  
  raw bytes traversed the tunnel; response: type=alert(21) version=TLS1.2 length=2 -> alert level=fatal(2) description=decode_error(50); type=alert(21) version=TLS1.2 length=2 -> alert level=warning(1) description=close_notify(0)
* **Squid** — PASS [non-tls-in-tunnel] (expectation: deny, 2ms)  
  tunnel established; connection closed with no response to raw (non-TLS) bytes — consistent with a non-TLS-in-tunnel policy check

### concurrency-sanity

Ten simultaneous CONNECTs to an allowed host all succeed — the proxy is not serializing or dropping under trivial load.

* **Pipelock** — RECORD (expectation: record, 28ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Smokescreen** — RECORD (expectation: record, 19ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Squid** — RECORD (expectation: record, 5ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed

<!-- END GENERATED per-check -->
