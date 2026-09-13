# Comparison of results using egress check suite

The tables are **generated** from `results/*.json` by `ipl-lab report`.

## Conditions

<!-- BEGIN GENERATED conditions -->

| Condition | Pipelock | Smokescreen | Squid | Iron |
| --- | --- | --- | --- | --- |
| TLS interception | off and on | off only (unsupported) | off and on | off and on |
| Measured | off: 2026-09-13T19:09:09Z<br>on: 2026-09-13T19:09:14Z | 2026-09-13T19:09:19Z (off only) | off: 2026-09-13T19:09:24Z<br>on: 2026-09-13T19:09:29Z | off: 2026-09-13T19:09:41Z<br>on: 2026-09-13T19:09:45Z |
| Backend | docker | docker (off only) | docker | docker |
| Host | Darwin 25.6.0 arm64 | Darwin 25.6.0 arm64 (off only) | Darwin 25.6.0 arm64 | Darwin 25.6.0 arm64 |
| Image | internet-proxy-locally/pipelock:3.3.0 | internet-proxy-locally/smokescreen:131fba29ce1e-build1 (off only) | internet-proxy-locally/squid:6.12-r0-build4 | internet-proxy-locally/iron:0.49.0-build1 |
| Endpoint | http://127.0.0.1:18080 | http://127.0.0.1:18080 (off only) | http://127.0.0.1:18080 | http://127.0.0.1:18080 |
| Exit code | 0 | 0 (off only) | 0 | 0 |

Source files: `results/benchmark.json`.

<!-- END GENERATED conditions -->

## Summary

<!-- BEGIN GENERATED summary -->

* **Pipelock**: 19 pass.
* **Smokescreen**: 16 pass, 3 fail (off only).
* **Squid**: off: 17 pass, 2 fail<br>on: 18 pass, 1 fail.
* **Iron**: 16 pass, 3 fail.

Concurrency sanity passes only when all ten simultaneous CONNECTs establish.

<!-- END GENERATED summary -->

## Matrix

<!-- BEGIN GENERATED matrix -->

Each proxy has one column. A single verdict applies to both TLS modes; differences are labeled **off** and **on**. Smokescreen supports off only. Bracketed values are attributed denial causes.

| Check | Pipelock | Smokescreen | Squid | Iron |
| --- | --- | --- | --- | --- |
| [allowed-http](#allowed-http) | PASS | PASS (off only) | PASS | PASS |
| [allowed-https](#allowed-https) | PASS | PASS (off only) | PASS | PASS |
| [blocked-host-connect](#blocked-host-connect) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [hostname-not-allowlisted] | PASS [unknown] |
| [blocked-host-http](#blocked-host-http) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] |
| [direct-ip-connect](#direct-ip-connect) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [ip-literal-destination] | PASS [unknown] |
| [loopback-ipv4](#loopback-ipv4) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [private-ip] | PASS [unknown] |
| [rfc1918-ipv4](#rfc1918-ipv4) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [private-ip] | PASS [unknown] |
| [link-local-ipv4](#link-local-ipv4) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [private-ip] | PASS [unknown] |
| [metadata-endpoint](#metadata-endpoint) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [metadata] | PASS [hostname-not-allowlisted+unknown] |
| [loopback-ipv6](#loopback-ipv6) | PASS [hostname-not-allowlisted] | PASS [unparseable-destination] (off only) | PASS [private-ip] | PASS [unknown] |
| [private-ipv6](#private-ipv6) | PASS [hostname-not-allowlisted] | PASS [unparseable-destination] (off only) | PASS [private-ip] | PASS [unknown] |
| [dns-private-ipv4](#dns-private-ipv4) | PASS [metadata+private-ip] | PASS [private-ip] (off only) | PASS [metadata+private-ip] | PASS [metadata+private-ip] |
| [dns-private-ipv6](#dns-private-ipv6) | PASS [private-ip] | PASS [private-ip] (off only) | PASS [private-ip] | PASS [private-ip] |
| [dns-rebinding](#dns-rebinding) | PASS [private-ip] | PASS [private-ip] (off only) | PASS [private-ip] | PASS |
| [dns-mixed-answers](#dns-mixed-answers) | PASS [private-ip] | FAIL (off only) | PASS [private-ip] | FAIL |
| [ptr-allowlist](#ptr-allowlist) | PASS [hostname-not-allowlisted] | PASS [hostname-not-allowlisted] (off only) | PASS [ip-literal-destination] | PASS [unknown] |
| [connect-sni-mismatch](#connect-sni-mismatch) | PASS [sni-mismatch] | FAIL [sni-mismatch] (off only) | FAIL [sni-mismatch] | FAIL [sni-mismatch] |
| [connect-raw-tunnel](#connect-raw-tunnel) | PASS [non-tls-in-tunnel] | FAIL [non-tls-in-tunnel] (off only) | off: FAIL [non-tls-in-tunnel]<br>on: PASS [non-tls-in-tunnel] | FAIL [non-tls-in-tunnel] |
| [concurrency-sanity](#concurrency-sanity) | PASS | PASS (off only) | PASS | PASS |

<!-- END GENERATED matrix -->

## Every check, and what each engine did

<!-- BEGIN GENERATED per-check -->

### allowed-http

A plain-HTTP GET to an allowlisted host reaches it.

* **Pipelock (TLS off)** — PASS (expectation: allow, 336ms)  
  reached pypi.org (HTTP/1.1 200 OK)
* **Pipelock (TLS on)** — PASS (expectation: allow, 285ms)  
  reached pypi.org (HTTP/1.1 200 OK)
* **Smokescreen (TLS off)** — PASS (expectation: allow, 24ms)  
  reached pypi.org (HTTP/1.1 301 Moved Permanently)
* **Squid (TLS off)** — PASS (expectation: allow, 24ms)  
  reached pypi.org (HTTP/1.1 301 Moved Permanently)
* **Squid (TLS on)** — PASS (expectation: allow, 29ms)  
  reached pypi.org (HTTP/1.1 301 Moved Permanently)
* **Iron (TLS off)** — PASS (expectation: allow, 7541ms)  
  reached pypi.org (HTTP/1.1 301 Moved Permanently)
* **Iron (TLS on)** — PASS (expectation: allow, 41ms)  
  reached pypi.org (HTTP/1.1 301 Moved Permanently)

### allowed-https

A CONNECT tunnel to an allowlisted host completes a real TLS handshake, so ordinary HTTPS works through the proxy.

* **Pipelock (TLS off)** — PASS (expectation: allow, 33ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Pipelock (TLS on)** — PASS (expectation: allow, 19ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Smokescreen (TLS off)** — PASS (expectation: allow, 34ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Squid (TLS off)** — PASS (expectation: allow, 31ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Squid (TLS on)** — PASS (expectation: allow, 35ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Iron (TLS off)** — PASS (expectation: allow, 38ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)
* **Iron (TLS on)** — PASS (expectation: allow, 4ms)  
  tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)

### blocked-host-connect

CONNECT to a host that is not on the allowlist is refused — the default-deny rule, on the tunnel path.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: example.com
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: example.com
* **Smokescreen (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host 'example.com:443': default rule policy used.
* **Squid (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 9ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is not in the allowlist.
* **Squid (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 7ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is not in the allowlist.
* **Iron (TLS off)** — PASS [unknown] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden
* **Iron (TLS on)** — PASS [unknown] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden

### blocked-host-http

A plain-HTTP GET to a host that is not on the allowlist is refused — the same rule on the request path.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  http://example.com/: denied: HTTP/1.1 403 Forbidden — blocked: domain not in allowlist: example.com
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  http://example.com/: denied: HTTP/1.1 403 Forbidden — blocked: domain not in allowlist: example.com
* **Smokescreen (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  http://example.com/: denied: HTTP/1.1 407 Proxy Authentication Required — Egress proxying is denied to host 'example.com': default rule policy used.
* **Squid (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  http://example.com/: denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is not in the allowlist.
* **Squid (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  http://example.com/: denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is not in the allowlist.
* **Iron (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  http://example.com/: denied — Iron audit log (172.30.203.1:55006): rejected_by allowlist; client observation: inconclusive HTTP response: HTTP/1.1 403 Forbidden
* **Iron (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  http://example.com/: denied — Iron audit log (172.30.203.1:59192): rejected_by allowlist; client observation: inconclusive HTTP response: HTTP/1.1 403 Forbidden

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
* **Iron (TLS off)** — PASS [unknown] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden
* **Iron (TLS on)** — PASS [unknown] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden

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
* **Iron (TLS off)** — PASS [unknown] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden
* **Iron (TLS on)** — PASS [unknown] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden

### rfc1918-ipv4

CONNECT to RFC1918 space (10/8, 172.16/12, 192.168/16) is refused.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 10.0.0.1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 192.168.1.1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 172.16.0.1
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 10.0.0.1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 192.168.1.1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 172.16.0.1
* **Smokescreen (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '10.0.0.1:80': default rule policy used.; denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '192.168.1.1:80': default rule policy used.; denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '172.16.0.1:80': default rule policy used.
* **Squid (TLS off)** — PASS [private-ip] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 9ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.
* **Iron (TLS off)** — PASS [unknown] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden; denied: HTTP/1.1 403 Forbidden; denied: HTTP/1.1 403 Forbidden
* **Iron (TLS on)** — PASS [unknown] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden; denied: HTTP/1.1 403 Forbidden; denied: HTTP/1.1 403 Forbidden

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
* **Iron (TLS off)** — PASS [unknown] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden
* **Iron (TLS on)** — PASS [unknown] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden

### metadata-endpoint

The cloud metadata address is refused over both CONNECT and plain HTTP.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  169.254.169.254:80: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 169.254.169.254; http://169.254.169.254/latest/meta-data/: denied: HTTP/1.1 403 Forbidden — blocked: domain not in allowlist: 169.254.169.254
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  169.254.169.254:80: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 169.254.169.254; http://169.254.169.254/latest/meta-data/: denied: HTTP/1.1 403 Forbidden — blocked: domain not in allowlist: 169.254.169.254
* **Smokescreen (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  169.254.169.254:80: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '169.254.169.254:80': default rule policy used.; http://169.254.169.254/latest/meta-data/: denied: HTTP/1.1 407 Proxy Authentication Required — Egress proxying is denied to host '169.254.169.254': default rule policy used.
* **Squid (TLS off)** — PASS [metadata] (expectation: deny, 2ms)  
  169.254.169.254:80: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a cloud metadata endpoint.; http://169.254.169.254/latest/meta-data/: denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a cloud metadata endpoint.
* **Squid (TLS on)** — PASS [metadata] (expectation: deny, 4ms)  
  169.254.169.254:80: HTTP/1.1 200 Connection established — denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a cloud metadata endpoint.; http://169.254.169.254/latest/meta-data/: denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a cloud metadata endpoint.
* **Iron (TLS off)** — PASS [hostname-not-allowlisted+unknown] (expectation: deny, 2ms)  
  169.254.169.254:80: HTTP/1.1 403 Forbidden; http://169.254.169.254/latest/meta-data/: denied — Iron audit log (172.30.203.1:55094): rejected_by allowlist; client observation: inconclusive HTTP response: HTTP/1.1 403 Forbidden
* **Iron (TLS on)** — PASS [hostname-not-allowlisted+unknown] (expectation: deny, 2ms)  
  169.254.169.254:80: HTTP/1.1 403 Forbidden; http://169.254.169.254/latest/meta-data/: denied — Iron audit log (172.30.203.1:59282): rejected_by allowlist; client observation: inconclusive HTTP response: HTTP/1.1 403 Forbidden

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
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 4ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.
* **Iron (TLS off)** — PASS [unknown] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden
* **Iron (TLS on)** — PASS [unknown] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden

### private-ipv6

CONNECT to ULA and link-local IPv6 (fd00::1, fe80::1) is refused.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fd00::1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fe80::1
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fd00::1; denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: fe80::1
* **Smokescreen (TLS off)** — PASS [unparseable-destination] (expectation: deny, 2ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '[fd00::1]:80': Destination host cannot be determined.; denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '[fe80::1]:80': Destination host cannot be determined.
* **Squid (TLS off)** — PASS [private-ip] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 6ms)  
  denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.; denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: SSRF blocked, the destination resolves to a private, loopback, link-local or otherwise non-public address.
* **Iron (TLS off)** — PASS [unknown] (expectation: deny, 2ms)  
  denied: HTTP/1.1 403 Forbidden; denied: HTTP/1.1 403 Forbidden
* **Iron (TLS on)** — PASS [unknown] (expectation: deny, 1ms)  
  denied: HTTP/1.1 403 Forbidden; denied: HTTP/1.1 403 Forbidden

### dns-private-ipv4

An *allowlisted* name that resolves to a private IPv4 address is refused, so the denial can only have come from validating the resolved address (nip.io).

* **Pipelock (TLS off)** — PASS [metadata+private-ip] (expectation: deny, 175ms)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt
* **Pipelock (TLS on)** — PASS [metadata+private-ip] (expectation: deny, 14ms)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt
* **Smokescreen (TLS off)** — PASS [private-ip] (expectation: deny, 14ms)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt
* **Squid (TLS off)** — PASS [metadata+private-ip] (expectation: deny, 14ms)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt
* **Squid (TLS on)** — PASS [metadata+private-ip] (expectation: deny, 25ms)  
  allowlisted hostnames resolving to private/loopback/metadata IPv4 all denied; resolved IPs recorded per attempt
* **Iron (TLS off)** — PASS [metadata+private-ip] (expectation: deny, 23ms)  
  10.0.0.1.nip.io:80: denied — Iron audit log (172.30.203.1:55146): dial tcp 10.0.0.1:443: denied by upstream_deny_cidrs: 10.0.0.1 in 10.0.0.0/8; client observation: HTTP/1.1 200 Connection Established — inconclusive TLS/HTTP exchange after CONNECT: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1032); 192.168.1.1.nip.io:80: denied — Iron audit log (172.30.203.1:55148): dial tcp 192.168.1.1:443: denied by upstream_deny_cidrs: 192.168.1.1 in 192.168.0.0/16; client observation: HTTP/1.1 200 Connection Established — inconclusive TLS/HTTP exchange after CONNECT: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1032); 127.0.0.1.nip.io:80: denied — Iron audit log (172.30.203.1:55158): dial tcp 127.0.0.1:443: denied by upstream_deny_cidrs: 127.0.0.1 in 127.0.0.0/8; client observation: HTTP/1.1 200 Connection Established — inconclusive TLS/HTTP exchange after CONNECT: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1032); 169.254.169.254.nip.io:80: denied — Iron audit log (172.30.203.1:55170): dial tcp 169.254.169.254:443: denied by upstream_deny_cidrs: 169.254.169.254 in 169.254.169.254/32; client observation: HTTP/1.1 200 Connection Established — inconclusive TLS/HTTP exchange after CONNECT: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1032)
* **Iron (TLS on)** — PASS [metadata+private-ip] (expectation: deny, 21ms)  
  10.0.0.1.nip.io:80: denied — Iron audit log (172.30.203.1:59324): dial tcp 10.0.0.1:80: denied by upstream_deny_cidrs: 10.0.0.1 in 10.0.0.0/8; client observation: HTTP/1.1 200 Connection Established — inconclusive HTTP response after TLS: HTTP/1.1 502 Bad Gateway — bad gateway; 192.168.1.1.nip.io:80: denied — Iron audit log (172.30.203.1:59340): dial tcp 192.168.1.1:80: denied by upstream_deny_cidrs: 192.168.1.1 in 192.168.0.0/16; client observation: HTTP/1.1 200 Connection Established — inconclusive HTTP response after TLS: HTTP/1.1 502 Bad Gateway — bad gateway; 127.0.0.1.nip.io:80: denied — Iron audit log (172.30.203.1:59352): dial tcp 127.0.0.1:80: denied by upstream_deny_cidrs: 127.0.0.1 in 127.0.0.0/8; client observation: HTTP/1.1 200 Connection Established — inconclusive HTTP response after TLS: HTTP/1.1 502 Bad Gateway — bad gateway; 169.254.169.254.nip.io:80: denied — Iron audit log (172.30.203.1:59356): dial tcp 169.254.169.254:80: denied by upstream_deny_cidrs: 169.254.169.254 in 169.254.169.254/32; client observation: HTTP/1.1 200 Connection Established — inconclusive HTTP response after TLS: HTTP/1.1 502 Bad Gateway — bad gateway

### dns-private-ipv6

The same, for IPv6 (sslip.io).

* **Pipelock (TLS off)** — PASS [private-ip] (expectation: deny, 167ms)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt
* **Pipelock (TLS on)** — PASS [private-ip] (expectation: deny, 10ms)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt
* **Smokescreen (TLS off)** — PASS [private-ip] (expectation: deny, 10ms)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt
* **Squid (TLS off)** — PASS [private-ip] (expectation: deny, 10ms)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 19ms)  
  allowlisted hostnames resolving to private/loopback IPv6 all denied; resolved IPs recorded per attempt
* **Iron (TLS off)** — PASS [private-ip] (expectation: deny, 13ms)  
  0--1.sslip.io:80: denied — Iron audit log (172.30.203.1:55178): dial tcp [::1]:443: denied by upstream_deny_cidrs: ::1 in ::1/128; client observation: HTTP/1.1 200 Connection Established — inconclusive TLS/HTTP exchange after CONNECT: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1032); fe80--1.sslip.io:80: denied — Iron audit log (172.30.203.1:55192): dial tcp [fe80::1]:443: denied by upstream_deny_cidrs: fe80::1 in fe80::/10; client observation: HTTP/1.1 200 Connection Established — inconclusive TLS/HTTP exchange after CONNECT: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1032); fd00--1.sslip.io:80: denied — Iron audit log (172.30.203.1:55200): dial tcp [fd00::1]:443: denied by upstream_deny_cidrs: fd00::1 in fc00::/7; client observation: HTTP/1.1 200 Connection Established — inconclusive TLS/HTTP exchange after CONNECT: [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1032)
* **Iron (TLS on)** — PASS [private-ip] (expectation: deny, 15ms)  
  0--1.sslip.io:80: denied — Iron audit log (172.30.203.1:59364): dial tcp [::1]:80: denied by upstream_deny_cidrs: ::1 in ::1/128; client observation: HTTP/1.1 200 Connection Established — inconclusive HTTP response after TLS: HTTP/1.1 502 Bad Gateway — bad gateway; fe80--1.sslip.io:80: denied — Iron audit log (172.30.203.1:59376): dial tcp [fe80::1]:80: denied by upstream_deny_cidrs: fe80::1 in fe80::/10; client observation: HTTP/1.1 200 Connection Established — inconclusive HTTP response after TLS: HTTP/1.1 502 Bad Gateway — bad gateway; fd00--1.sslip.io:80: denied — Iron audit log (172.30.203.1:59378): dial tcp [fd00::1]:80: denied by upstream_deny_cidrs: fd00::1 in fc00::/7; client observation: HTTP/1.1 200 Connection Established — inconclusive HTTP response after TLS: HTTP/1.1 502 Bad Gateway — bad gateway

### dns-rebinding

A name whose answer changes between the first lookup and the next does not get the engine to a private address. Graded on whether the fixture's trap was reached, not on counts.

* **Pipelock (TLS off)** — PASS [private-ip] (expectation: deny, 1590ms)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (9 lookups total); of the 3 repeat probes, 3 were denied, 0 carried HTTP traffic, and 0 were inconclusive
* **Pipelock (TLS on)** — PASS [private-ip] (expectation: deny, 1587ms)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (9 lookups total); of the 3 repeat probes, 3 were denied, 0 carried HTTP traffic, and 0 were inconclusive
* **Smokescreen (TLS off)** — PASS [private-ip] (expectation: deny, 1590ms)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (6 lookups total); of the 3 repeat probes, 3 were denied, 0 carried HTTP traffic, and 0 were inconclusive
* **Squid (TLS off)** — PASS [private-ip] (expectation: deny, 1588ms)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (6 lookups total); of the 3 repeat probes, 3 were denied, 0 carried HTTP traffic, and 0 were inconclusive
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 1615ms)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (6 lookups total); of the 3 repeat probes, 3 were denied, 0 carried HTTP traffic, and 0 were inconclusive
* **Iron (TLS off)** — PASS (expectation: deny, 1595ms)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (6 lookups total); of the 3 repeat probes, 0 were denied, 0 carried HTTP traffic, and 3 were inconclusive
* **Iron (TLS on)** — PASS (expectation: deny, 1601ms)  
  no connection reached the trap. 3/3 names were resolved more than once and so were handed the private address (6 lookups total); of the 3 repeat probes, 0 were denied, 0 carried HTTP traffic, and 3 were inconclusive

### dns-mixed-answers

A name resolving to a public *and* a private address is refused, in both answer orderings — every address in the answer set is validated, not just the first or the routable one.

* **Pipelock (TLS off)** — PASS [private-ip] (expectation: deny, 77ms)  
  control public-only.fixture.test established, and both mixed-answer names (public-first and private-first) were denied — every address in the answer set is validated, not only the first one or the routable one
* **Pipelock (TLS on)** — PASS [private-ip] (expectation: deny, 72ms)  
  control public-only.fixture.test established, and both mixed-answer names (public-first and private-first) were denied — every address in the answer set is validated, not only the first one or the routable one
* **Smokescreen (TLS off)** — FAIL (expectation: deny, 66ms)  
  mixed-public-first.fixture.test:443 established — the engine connected although a private address was in the answer set; mixed-private-first.fixture.test:443 established — the engine connected although a private address was in the answer set
* **Squid (TLS off)** — PASS [private-ip] (expectation: deny, 56ms)  
  control public-only.fixture.test established, and both mixed-answer names (public-first and private-first) were denied — every address in the answer set is validated, not only the first one or the routable one
* **Squid (TLS on)** — PASS [private-ip] (expectation: deny, 66ms)  
  control public-only.fixture.test established, and both mixed-answer names (public-first and private-first) were denied — every address in the answer set is validated, not only the first one or the routable one
* **Iron (TLS off)** — FAIL (expectation: deny, 72ms)  
  mixed-public-first.fixture.test:443 established — the engine connected although a private address was in the answer set; mixed-private-first.fixture.test:443 established — the engine connected although a private address was in the answer set
* **Iron (TLS on)** — FAIL (expectation: deny, 67ms)  
  mixed-public-first.fixture.test:443 established — the engine connected although a private address was in the answer set; mixed-private-first.fixture.test:443 established — the engine connected although a private address was in the answer set

### ptr-allowlist

An address whose PTR record claims an allowlisted hostname is still refused, so a reverse lookup cannot satisfy the allowlist.

* **Pipelock (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 36ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 1.0.0.1; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Pipelock (TLS on)** — PASS [hostname-not-allowlisted] (expectation: deny, 36ms)  
  denied: HTTP/1.1 403 Forbidden — CONNECT blocked: domain not in allowlist: 1.0.0.1; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Smokescreen (TLS off)** — PASS [hostname-not-allowlisted] (expectation: deny, 38ms)  
  denied: HTTP/1.1 407 Request rejected by proxy — Egress proxying is denied to host '1.0.0.1:443': default rule policy used.; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Squid (TLS off)** — PASS [ip-literal-destination] (expectation: deny, 36ms)  
  denied: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is a bare IP address, and this proxy allowlists destinations by hostname only.; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Squid (TLS on)** — PASS [ip-literal-destination] (expectation: deny, 40ms)  
  denied: HTTP/1.1 200 Connection established — denied after CONNECT: HTTP/1.1 403 Forbidden — 403 Forbidden internet-proxy-locally denied this request: the destination is a bare IP address, and this proxy allowlists destinations by hostname only.; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Iron (TLS off)** — PASS [unknown] (expectation: deny, 42ms)  
  denied: HTTP/1.1 403 Forbidden; the engine performed no reverse lookup, so the allowlist was never offered the PTR name
* **Iron (TLS on)** — PASS [unknown] (expectation: deny, 35ms)  
  denied: HTTP/1.1 403 Forbidden; the engine performed no reverse lookup, so the allowlist was never offered the PTR name

### connect-sni-mismatch

A tunnel to one allowlisted host carrying a ClientHello for another is refused — enforcement inside the CONNECT tunnel.

* **Pipelock (TLS off)** — PASS [sni-mismatch] (expectation: deny, 57ms)  
  mismatched SNI refused: tunnel established but TLS handshake failed (SNI=files.pythonhosted.org): [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1032) — the matching-SNI control to the same host completed (tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)), so the refusal is the proxy's rather than the origin's
* **Pipelock (TLS on)** — PASS [sni-mismatch] (expectation: deny, 30ms)  
  mismatched SNI refused: tunnel established but TLS handshake failed (SNI=files.pythonhosted.org): [SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1032) — the matching-SNI control to the same host completed (tunnel established, TLSv1.3 handshake OK (SNI=pypi.org)), so the refusal is the proxy's rather than the origin's
* **Smokescreen (TLS off)** — FAIL [sni-mismatch] (expectation: deny, 72ms)  
  mismatched SNI accepted: tunnel established, TLSv1.3 handshake OK (SNI=files.pythonhosted.org)
* **Squid (TLS off)** — FAIL [sni-mismatch] (expectation: deny, 26ms)  
  mismatched SNI accepted: tunnel established, TLSv1.3 handshake OK (SNI=files.pythonhosted.org)
* **Squid (TLS on)** — FAIL [sni-mismatch] (expectation: deny, 27ms)  
  mismatched SNI accepted: tunnel established, TLSv1.3 handshake OK (SNI=files.pythonhosted.org)
* **Iron (TLS off)** — FAIL [sni-mismatch] (expectation: deny, 39ms)  
  mismatched SNI accepted: tunnel established, TLSv1.3 handshake OK (SNI=files.pythonhosted.org)
* **Iron (TLS on)** — FAIL [sni-mismatch] (expectation: deny, 2ms)  
  mismatched SNI accepted: tunnel established, TLSv1.3 handshake OK (SNI=files.pythonhosted.org)

### connect-raw-tunnel

A tunnel to an allowlisted host on 443 carrying plaintext rather than TLS is refused — enforcement inside the CONNECT tunnel.

* **Pipelock (TLS off)** — PASS [non-tls-in-tunnel] (expectation: deny, 16ms)  
  tunnel established; connection closed with no response to raw (non-TLS) bytes — consistent with a non-TLS-in-tunnel policy check
* **Pipelock (TLS on)** — PASS [non-tls-in-tunnel] (expectation: deny, 15ms)  
  tunnel established; connection closed with no response to raw (non-TLS) bytes — consistent with a non-TLS-in-tunnel policy check
* **Smokescreen (TLS off)** — FAIL [non-tls-in-tunnel] (expectation: deny, 21ms)  
  raw bytes traversed the tunnel; response: type=alert(21) version=TLS1.2 length=2 -> alert level=fatal(2) description=decode_error(50); type=alert(21) version=TLS1.2 length=2 -> alert level=warning(1) description=close_notify(0)
* **Squid (TLS off)** — FAIL [non-tls-in-tunnel] (expectation: deny, 19ms)  
  raw bytes traversed the tunnel; response: type=alert(21) version=TLS1.2 length=2 -> alert level=fatal(2) description=decode_error(50); type=alert(21) version=TLS1.2 length=2 -> alert level=warning(1) description=close_notify(0)
* **Squid (TLS on)** — PASS [non-tls-in-tunnel] (expectation: deny, 2ms)  
  tunnel established; connection closed with no response to raw (non-TLS) bytes — consistent with a non-TLS-in-tunnel policy check
* **Iron (TLS off)** — FAIL [non-tls-in-tunnel] (expectation: deny, 26ms)  
  raw bytes traversed the tunnel; response: not a recognized TLS record; first bytes: 485454502f312e3120333031204d6f766564205065726d616e656e746c790d0a (b'HTTP/1.1 301 Moved Permanently\r\n')
* **Iron (TLS on)** — FAIL [non-tls-in-tunnel] (expectation: deny, 32ms)  
  raw bytes traversed the tunnel; response: not a recognized TLS record; first bytes: 485454502f312e3120333031204d6f766564205065726d616e656e746c790d0a (b'HTTP/1.1 301 Moved Permanently\r\n')

### concurrency-sanity

Ten simultaneous CONNECTs to an allowed host all succeed — the proxy is not serializing or dropping under trivial load.

* **Pipelock (TLS off)** — PASS (expectation: allow, 29ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Pipelock (TLS on)** — PASS (expectation: allow, 62ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Smokescreen (TLS off)** — PASS (expectation: allow, 21ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Squid (TLS off)** — PASS (expectation: allow, 19ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Squid (TLS on)** — PASS (expectation: allow, 5ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Iron (TLS off)** — PASS (expectation: allow, 5ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed
* **Iron (TLS on)** — PASS (expectation: allow, 5ms)  
  10 concurrent CONNECTs to an allowed host: 10 established, 0 denied/failed

<!-- END GENERATED per-check -->
