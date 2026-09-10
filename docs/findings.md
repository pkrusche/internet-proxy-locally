# Comparison of results using egress check suite

The tables are **generated** from `results/*.json` by `ipl-lab report`.

## Conditions

<!-- BEGIN GENERATED conditions -->

| Condition | Pipelock | Smokescreen | Squid |
| --- | --- | --- | --- |
| TLS interception | off and on | off only (unsupported) | off and on |
| Measured | off: 2026-09-10T07:11:29Z<br>on: 2026-09-10T07:11:35Z | 2026-09-10T07:11:39Z (off only) | off: 2026-09-10T07:11:44Z<br>on: 2026-09-10T07:11:49Z |
| Backend | docker | docker (off only) | docker |
| Host | Darwin 25.6.0 arm64 | Darwin 25.6.0 arm64 (off only) | Darwin 25.6.0 arm64 |
| Image | internet-proxy-locally/pipelock:3.3.0 | internet-proxy-locally/smokescreen:131fba29ce1e-build1 (off only) | internet-proxy-locally/squid:6.12-r0-build1 |
| Endpoint | http://127.0.0.1:18080 | http://127.0.0.1:18080 (off only) | http://127.0.0.1:18080 |
| Exit code | 0 | 1 (off only) | 1 |

Source files: `results/benchmark.json`.

<!-- END GENERATED conditions -->

## Summary

<!-- BEGIN GENERATED summary -->

* **Pipelock**: 19 pass.
* **Smokescreen**: 16 pass, 3 fail (off only).
* **Squid**: off: 17 pass, 2 fail<br>on: 18 pass, 1 fail.

Concurrency sanity passes only when all ten simultaneous CONNECTs establish.

<!-- END GENERATED summary -->

## Matrix

<!-- BEGIN GENERATED matrix -->

Each proxy has one column. A single verdict applies to both TLS modes; differences are labeled **off** and **on**. Smokescreen supports off only. Bracketed values are attributed denial causes.

| Check | Pipelock | Smokescreen | Squid |
| --- | --- | --- | --- |
| [allowed-http](#allowed-http) | PASS | PASS (off only) | PASS |
| [allowed-https](#allowed-https) | PASS | PASS (off only) | PASS |
| [blocked-host-connect](#blocked-host-connect) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [hostname-not-allowlisted] |
| [blocked-host-http](#blocked-host-http) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [hostname-not-allowlisted] |
| [direct-ip-connect](#direct-ip-connect) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [ip-literal-destination] |
| [loopback-ipv4](#loopback-ipv4) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [private-ip] |
| [rfc1918-ipv4](#rfc1918-ipv4) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [private-ip] |
| [link-local-ipv4](#link-local-ipv4) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [private-ip] |
| [metadata-endpoint](#metadata-endpoint) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [metadata] |
| [loopback-ipv6](#loopback-ipv6) | PASS [hostname-not-allowlisted] | PASS [unparseable-destination] (off only) | PASS [private-ip] |
| [private-ipv6](#private-ipv6) | PASS [hostname-not-allowlisted] | PASS [unparseable-destination] (off only) | PASS [private-ip] |
| [dns-private-ipv4](#dns-private-ipv4) | PASS [metadata+private-ip] | PASS [private-ip] (off only) | PASS [metadata+private-ip] |
| [dns-private-ipv6](#dns-private-ipv6) | PASS [private-ip] | PASS [private-ip] (off only) | PASS [private-ip] |
| [dns-rebinding](#dns-rebinding) | PASS [private-ip] | PASS [private-ip] (off only) | PASS [private-ip] |
| [dns-mixed-answers](#dns-mixed-answers) | PASS [private-ip] | FAIL (off only) | PASS [private-ip] |
| [ptr-allowlist](#ptr-allowlist) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [ip-literal-destination] |
| [connect-sni-mismatch](#connect-sni-mismatch) | PASS [sni-mismatch] | FAIL [sni-mismatch] (off only) | FAIL [sni-mismatch] |
| [connect-raw-tunnel](#connect-raw-tunnel) | PASS [non-tls-in-tunnel] | FAIL [non-tls-in-tunnel] (off only) | off: FAIL [non-tls-in-tunnel]<br>on: PASS [non-tls-in-tunnel] |
| [concurrency-sanity](#concurrency-sanity) | PASS | PASS (off only) | PASS |

<!-- END GENERATED matrix -->

## Every check, and what each engine did

<!-- BEGIN GENERATED per-check -->

### allowed-http

A plain-HTTP GET to an allowlisted host reaches it.

* **Pipelock (TLS off)** — PASS (expectation: allow, 298ms)  
  reached pypi.org (HTTP/1.1 200 OK)
* **Pipelock (TLS on)** — PASS (expectation: allow, 278ms)  
  reached pypi.org (HTTP/1.1 200 OK)
* **Smokescreen (TLS off)** — PASS (expectation: allow, 24ms)  
  reached pypi.org (HTTP/1.1 301 Moved Permanently)
* **Squid (TLS off)** — PASS (expectation: allow, 24ms)  
  reached pypi.org (HTTP/1.1 301 Moved Permanently)
* **Squid (TLS on)** — PASS (expectation: allow, 26ms)  
  reached pypi.org (HTTP/1.1 301 Moved Permanently)

### allowed-https

A CONNECT tunnel to an allowlisted host completes a real TLS handshake, so ordinary HTTPS works through the proxy.

* **Pipelock (TLS off)** — PASS (expectation: allow, 30ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Pipelock (TLS on)** — PASS (expectation: allow, 17ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Smokescreen (TLS off)** — PASS (expectation: allow, 28ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Squid (TLS off)** — PASS (expectation: allow, 22ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Squid (TLS on)** — PASS (expectation: allow, 37ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)

### blocked-host-connect

CONNECT to a host that is not on the allowlist is refused — the default-deny rule, on the tunnel path.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: example.com
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: example.com
* **Smokescreen (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host 'example.com:443': default rule policy used.
* **Squid (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 8ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is not in the allowlist.
* **Squid (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 6ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is not in the allowlist.

### blocked-host-http

A plain-HTTP GET to a host that is not on the allowlist is refused — the same rule on the request path.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — blocked: domain not in allowlist: example.com
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — blocked: domain not in allowlist: example.com
* **Smokescreen (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Proxy Authentication Required — Egress proxying is denied to host 'example.com': default rule policy used.
* **Squid (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is not in the allowlist.
* **Squid (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is not in the allowlist.

### direct-ip-connect

A destination written as a bare address is refused. Under a hostname allowlist it can only ever be denied; which rule denies it is what the cause column shows.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 1.1.1.1
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 1.1.1.1
* **Smokescreen (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '1.1.1.1:443': default rule policy used.
* **Squid (TLS off)** — PASS [ip-literal-destination] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is a bare IP address, and this proxy allowlists destinations by hostname only.
* **Squid (TLS on)** — PASS [ip-literal-destination] (expectation: deny, 4ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is a bare IP address, and this proxy allowlists destinations by hostname only.

### loopback-ipv4

CONNECT to 127.0.0.1 is refused.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 127.0.0.1
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 127.0.0.1
* **Smokescreen (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '127.0.0.1:80': default rule policy used.
* **Squid (TLS off)** — PASS [private-ip] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 4ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### rfc1918-ipv4

CONNECT to RFC1918 space (10/8, 172.16/12, 192.168/16) is refused.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 10.0.0.1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 192.168.1.1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 172.16.0.1
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 10.0.0.1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 192.168.1.1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 172.16.0.1
* **Smokescreen (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 6ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '10.0.0.1:80': default rule policy used.; denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '192.168.1.1:80': default rule policy used.; denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '172.16.0.1:80': default rule policy used.
* **Squid (TLS off)** — PASS [private-ip] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 8ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### link-local-ipv4

CONNECT to 169.254.0.0/16 is refused.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 169.254.1.1
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 169.254.1.1
* **Smokescreen (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '169.254.1.1:80': default rule policy used.
* **Squid (TLS off)** — PASS [private-ip] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 4ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### metadata-endpoint

The cloud metadata address is refused over both CONNECT and plain HTTP.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied for CONNECT and GET (CONNECT: denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 169.254.169.254; GET: denied: HTTP/1.1 403 Forbidden — blocked: domain not in allowlist: 169.254.169.254)
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied for CONNECT and GET (CONNECT: denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 169.254.169.254; GET: denied: HTTP/1.1 403 Forbidden — blocked: domain not in allowlist: 169.254.169.254)
* **Smokescreen (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied for CONNECT and GET (CONNECT: denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '169.254.169.254:80': default rule policy used.; GET: denied: HTTP/1.1 407 Proxy Authentication Required — Egress proxying is denied to host '169.254.169.254': default rule policy used.)
* **Squid (TLS off)** — PASS [metadata] (expectation: deny, 1ms)  
  denied for CONNECT and GET (CONNECT: denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a cloud metadata endpoint.; GET: denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a cloud metadata endpoint.)
* **Squid (TLS on)** — PASS [metadata] (expectation: deny, 4ms)  
  denied for CONNECT and GET (CONNECT: denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a cloud metadata endpoint.; GET: denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a cloud metadata endpoint.)

### loopback-ipv6

CONNECT to [::1] is refused.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: ::1
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: ::1
* **Smokescreen (TLS off)** — PASS [unparseable-destination] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '[::1]:80': Destination host cannot be determined.
* **Squid (TLS off)** — PASS [private-ip] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 3ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### private-ipv6

CONNECT to ULA and link-local IPv6 (fd00::1, fe80::1) is refused.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fd00::1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fe80::1
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fd00::1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fe80::1
* **Smokescreen (TLS off)** — PASS [unparseable-destination] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '[fd00::1]:80': Destination host cannot be determined.; denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '[fe80::1]:80': Destination host cannot be determined.
* **Squid (TLS off)** — PASS [private-ip] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 7ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.

### dns-private-ipv4

An *allowlisted* name that resolves to a private IPv4 address is refused, so the denial can only have come from validating the resolved address (nip.io).

* **Pipelock (TLS off)** — PASS [metadata+private-ip] (expectation: deny, 144ms)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt
* **Pipelock (TLS on)** — PASS [metadata+private-ip] (expectation: deny, 14ms)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt
* **Smokescreen (TLS off)** — PASS [private-ip] (expectation: deny, 14ms)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt
* **Squid (TLS off)** — PASS [metadata+private-ip] (expectation: deny, 14ms)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt
* **Squid (TLS on)** — PASS [metadata+private-ip] (expectation: deny, 25ms)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt

### dns-private-ipv6

The same, for IPv6 (sslip.io).

* **Pipelock (TLS off)** — PASS [private-ip] (expectation: deny, 111ms)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt
* **Pipelock (TLS on)** — PASS [private-ip] (expectation: deny, 11ms)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt
* **Smokescreen (TLS off)** — PASS [private-ip] (expectation: deny, 10ms)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt
* **Squid (TLS off)** — PASS [private-ip] (expectation: deny, 9ms)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 18ms)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt

### dns-rebinding

A name whose answer changes between the first lookup and the next does not get the engine to a private address. Graded on whether the fixture's trap was reached, not on counts.

* **Pipelock (TLS off)** — PASS [private-ip] (expectation: deny, 1558ms)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (9 lookups total); of the 3 repeat probes, 3 were denied, 0 carried HTTP traffic, and 0 were inconclusive
* **Pipelock (TLS on)** — PASS [private-ip] (expectation: deny, 1585ms)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (9 lookups total); of the 3 repeat probes, 3 were denied, 0 carried HTTP traffic, and 0 were inconclusive
* **Smokescreen (TLS off)** — PASS [private-ip] (expectation: deny, 1590ms)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (6 lookups total); of the 3 repeat probes, 3 were denied, 0 carried HTTP traffic, and 0 were inconclusive
* **Squid (TLS off)** — PASS [private-ip] (expectation: deny, 1573ms)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (6 lookups total); of the 3 repeat probes, 3 were denied, 0 carried HTTP traffic, and 0 were inconclusive
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 1606ms)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (6 lookups total); of the 3 repeat probes, 3 were denied, 0 carried HTTP traffic, and 0 were inconclusive

### dns-mixed-answers

A name resolving to a public *and* a private address is refused, in both answer orderings — every address in the answer set is validated, not just the first or the routable one.

* **Pipelock (TLS off)** — PASS [private-ip] (expectation: deny, 84ms)  
  control public-only.fixture.test established, and both mixed-answer names (public-first and private-first) were denied — every address in the answer set is validated, not only the first one or the routable one
* **Pipelock (TLS on)** — PASS [private-ip] (expectation: deny, 74ms)  
  control public-only.fixture.test established, and both mixed-answer names (public-first and private-first) were denied — every address in the answer set is validated, not only the first one or the routable one
* **Smokescreen (TLS off)** — FAIL (expectation: deny, 68ms)  
  mixed-public-first.fixture.test:443 established — the engine connected although a private address was in the answer set; mixed-private-first.fixture.test:443 established — the engine connected although a private address was in the answer set
* **Squid (TLS off)** — PASS [private-ip] (expectation: deny, 56ms)  
  control public-only.fixture.test established, and both mixed-answer names (public-first and private-first) were denied — every address in the answer set is validated, not only the first one or the routable one
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 70ms)  
  control public-only.fixture.test established, and both mixed-answer names (public-first and private-first) were denied — every address in the answer set is validated, not only the first one or the routable one

### ptr-allowlist

An address whose PTR record claims an allowlisted hostname is still refused, so a reverse lookup cannot satisfy the allowlist.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 37ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 1.0.0.1; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 37ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 1.0.0.1; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Smokescreen (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 36ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '1.0.0.1:443': default rule policy used.; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Squid (TLS off)** — PASS [ip-literal-destination] (expectation: deny, 37ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is a bare IP address, and this proxy allowlists destinations by hostname only.; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Squid (TLS on)** — PASS [ip-literal-destination] (expectation: deny, 41ms)  
  denied: HTTP/1.1 200 Connection established — denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is a bare IP address, and this proxy allowlists destinations by hostname only.; the engine performed no reverse lookup, so the allowlist was never offered the PTR name

### connect-sni-mismatch

A tunnel to one allowlisted host carrying a ClientHello for another is refused — enforcement inside the CONNECT tunnel.

* **Pipelock (TLS off)** — PASS [sni-mismatch] (expectation: deny, 39ms)  
  mismatched SNI refused: tunnel established but TLS handshake failed (SNI=files.pythonhosted.org): [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1032) — the matching-SNI control to the same host completed (tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)), so the refusal is the proxy's rather than the origin's
* **Pipelock (TLS on)** — PASS [sni-mismatch] (expectation: deny, 31ms)  
  mismatched SNI refused: tunnel established but TLS handshake failed (SNI=files.pythonhosted.org): [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1032) — the matching-SNI control to the same host completed (tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)), so the refusal is the proxy's rather than the origin's
* **Smokescreen (TLS off)** — FAIL [sni-mismatch] (expectation: deny, 34ms)  
  mismatched SNI accepted: tunnel established, TLSv1.3 handshake OK (SNI=files.pythonhosted.org)
* **Squid (TLS off)** — FAIL [sni-mismatch] (expectation: deny, 34ms)  
  mismatched SNI accepted: tunnel established, TLSv1.3 handshake OK (SNI=files.pythonhosted.org)
* **Squid (TLS on)** — FAIL [sni-mismatch] (expectation: deny, 32ms)  
  mismatched SNI accepted: tunnel established, TLSv1.3 handshake OK (SNI=files.pythonhosted.org)

### connect-raw-tunnel

A tunnel to an allowlisted host on 443 carrying plaintext rather than TLS is refused — enforcement inside the CONNECT tunnel.

* **Pipelock (TLS off)** — PASS [non-tls-in-tunnel] (expectation: deny, 15ms)  
  tunnel established; connection closed with no response to raw (non-TLS) bytes — consistent with a non-TLS-in-tunnel policy check
* **Pipelock (TLS on)** — PASS [non-tls-in-tunnel] (expectation: deny, 16ms)  
  tunnel established; connection closed with no response to raw (non-TLS) bytes — consistent with a non-TLS-in-tunnel policy check
* **Smokescreen (TLS off)** — FAIL [non-tls-in-tunnel] (expectation: deny, 23ms)  
  raw bytes traversed the tunnel; response: type=alert(21) version=TLS1.2 length=2 -> alert level=fatal(2) description=decode_error(50); type=alert(21) version=TLS1.2 length=2 -> alert level=warning(1) description=close_notify(0)
* **Squid (TLS off)** — FAIL [non-tls-in-tunnel] (expectation: deny, 20ms)  
  raw bytes traversed the tunnel; response: type=alert(21) version=TLS1.2 length=2 -> alert level=fatal(2) description=decode_error(50); type=alert(21) version=TLS1.2 length=2 -> alert level=warning(1) description=close_notify(0)
* **Squid (TLS on)** — PASS [non-tls-in-tunnel] (expectation: deny, 2ms)  
  tunnel established; connection closed with no response to raw (non-TLS) bytes — consistent with a non-TLS-in-tunnel policy check

### concurrency-sanity

Ten simultaneous CONNECTs to an allowed host all succeed — the proxy is not serializing or dropping under trivial load.

* **Pipelock (TLS off)** — PASS (expectation: allow, 38ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Pipelock (TLS on)** — PASS (expectation: allow, 28ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Smokescreen (TLS off)** — PASS (expectation: allow, 21ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Squid (TLS off)** — PASS (expectation: allow, 27ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Squid (TLS on)** — PASS (expectation: allow, 7ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed

<!-- END GENERATED per-check -->
