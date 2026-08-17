# Pipelock vs Smokescreen — measured comparison

The default-backend decision is empirical: run the same suite against both
engines and record the results here. Feature tables alone do not decide it.

> **Tooling note:** the run recorded below predates the richer
> `checks/egress.py` collection added for TODO.md §1 (per-attempt
> DNS-rebinding evidence, denial-cause classification, response headers,
> decoded TLS records, engine log capture, `--diff`). The findings and
> data below are unchanged from the original run; re-running `check
> --full` against both engines with the current tooling is the way to
> confirm them and resolve the "inconclusive"/"unattributed" notes.

## Measurement conditions

| | |
| --- | --- |
| Date | 2026-08-17 |
| Host | macOS 26.6.1, arm64 (Apple Silicon) |
| Backend | Apple `container` |
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

| Check | Pipelock | Smokescreen | Notes |
| --- | --- | --- | --- |
| allowed-http | PASS (200) | PASS (301) | any status < 400 passes; see "unattributed" below |
| allowed-https | PASS | PASS | TLSv1.3, SNI = CONNECT target |
| blocked-host-connect | PASS (403) | PASS (407) | |
| blocked-host-http | PASS (403) | PASS (407) | |
| direct-ip-connect | PASS (403) | PASS (407) | |
| loopback-ipv4 | PASS | PASS | |
| rfc1918-ipv4 | PASS | PASS | 10/192.168/172.16 all denied |
| link-local-ipv4 | PASS | PASS | |
| metadata-endpoint | PASS | PASS | denied for both CONNECT and GET |
| loopback-ipv6 | PASS | PASS | |
| private-ipv6 | PASS | PASS | `fd00::1`, `fe80::1` |
| dns-private-ipv4 (nip.io) | PASS | PASS | **allowlisted** hostname → private IP, denied |
| dns-private-ipv6 (sslip.io) | PASS | PASS | **allowlisted** hostname → private IP, denied |
| dns-rebinding (rbndr.us) | RECORD 0 denied / 6 established | RECORD 6 denied / 0 established | inconclusive — see below |
| dns-mixed-answers | SKIP | SKIP | needs the local dnsmasq fixture |
| connect-sni-mismatch | PASS (denied) | RECORD **allowed** | **discriminator** |
| connect-raw-tunnel | PASS (denied) | RECORD **allowed** | **discriminator** |
| concurrency-sanity | RECORD 10/10 | RECORD 10/10 | |

## Findings

### 1. Hostname and IP-layer enforcement is equivalent

Every deny floor holds on both engines: unknown hostname, bare IP,
loopback, RFC1918, link-local, cloud metadata, IPv6 loopback/private.

The two DNS-fixture checks are the strongest results in the run. The
fixture hostnames are *deliberately allowlisted* under the test policy, so
the denial could only have come from re-validating the resolved IP after
DNS. Both engines validate post-resolution, as required by docs/policy.md.

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

### 5. Unattributed: `allowed-http` returned 200 vs 301

Plain-HTTP `pypi.org` normally answers `301` → HTTPS, which is what
Smokescreen returned. Pipelock returned `200`. Nothing in
`config/pipelock.yaml` requests redirect-following, so the most likely
explanation is upstream/CDN variation rather than a proxy feature — but
this was **not** confirmed. Both pass (`< 400`), and it does not affect
the decision. Worth re-checking if it persists.

## Not yet measured

* Docker backend (installed on the measurement host but not exercised).
* `dns-mixed-answers` — needs the dnsmasq fixture in docs/security.md.
* Crash → fail-closed (kill the container, confirm the sandbox loses
  Internet rather than gaining unfiltered access).
* `./run.py restart` behavior.
* Startup time, image size, resource usage, upgrade friction.

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
