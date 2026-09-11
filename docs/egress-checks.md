# Egress checks

The egress suite checks destination policy through the proxy. This page
describes all 19 checks in execution order, as registered in
[`catalogue.py`](../src/internet_proxy_locally/checks/egress/catalogue.py).
The implementations live in
[`checks/egress/`](../src/internet_proxy_locally/checks/egress/).
For measured engine behavior see [findings.md](findings.md); for fixture
setup see [lab.md](lab.md).

## Interpreting results

`pass` means the check's implemented expectation was met; `fail` means it
was violated. `skip` means a prerequisite was missing, and `error` means
execution or evidence was inconclusive. 

The checker exits 1 for errors, **not for policy failures**; `--strict` 
additionally treats skips as execution errors.

Most CONNECT denial probes require an explicit 4xx refusal, or attempt TLS
and an HTTP request after CONNECT succeeds. CONNECT 200 alone does not prove
access. A complete 2xx/3xx HTTP response after TLS proves traffic was carried;
recognized Squid denial responses inside TLS count as refusals. Other HTTP
errors, timeouts, resets and TLS failures are inconclusive. Iron can also
use a correlated explicit IP-denial audit record for supported DNS/private
probes; see [the evidence rules](tls-interception.md#late-denials-and-how-the-suite-grades-them).
The SNI, raw-tunnel and concurrency checks use different criteria, described
below.

A denial does not necessarily establish which rule stopped the request.
Read the best-effort `cause`, attempt details and engine logs. In particular,
literal-address probes can pass through hostname or port restrictions without
exercising the intended private-address rule. The plain-HTTP denial helper
counts **any HTTP status of 400 or above** as a denial, so an origin error or
proxy DNS/upstream failure can produce a misleading pass.

The checker disables certificate and hostname verification for its TLS
handshake and tunnel-traffic probes. These test transport behavior, not client
trust configuration or origin identity. Proxy-side certificate verification
is separate. Internet-dependent probes can fail because of DNS, routing or
origin availability. Fixture-dependent checks require the lab allowlist;
the runner checks it using `1.1.1.1.nip.io:443` and skips those checks if that
control is denied.

All checks exercise traffic sent through the proxy. When using the proxy with 
a sandbox, the sandbox must enforce that traffic cannot bypass it.
See [security.md](security.md) for the threat model.

## Quick checks

### `allowed-http`

- **What it does:** Sends a plain-HTTP GET to `http://pypi.org/`. A status
  below 400 passes; response headers are retained.
- **Risk tested:** Detects a broken allow path or an over-restrictive policy
  that prevents legitimate package-service access. It is an availability control.
- **Caveats:** `pypi.org` must be allowlisted and reachable. Redirects count
  as success and are not followed; the check does not validate response content
  or prove a package download works.

### `allowed-https`

- **What it does:** CONNECTs to `pypi.org:443` and completes a TLS handshake
  with SNI `pypi.org`.
- **Risk tested:** Detects broken HTTPS tunneling or TLS handling that would
  stop normal clients from reaching an allowed destination.
- **Caveats:** No HTTP request follows the handshake, and certificate trust
  is not checked. With interception, the handshake can terminate at the proxy;
  success alone does not prove an origin request succeeds.

### `blocked-host-connect`

- **What it does:** Attempts CONNECT to `example.com:443`, expecting denial;
  if CONNECT succeeds, actively tests TLS/HTTP traffic.
- **Risk tested:** A hostile client contacting an arbitrary, unapproved
  HTTPS endpoint for exfiltration, downloads or command-and-control.
- **Caveats:** `example.com` must remain outside the allowlist. This checks
  one hostname and port, not hostname normalization or wildcard edge cases.
  Ambiguous post-CONNECT failures remain errors.

### `blocked-host-http`

- **What it does:** GETs `http://example.com/`, expecting an HTTP error status.
- **Risk tested:** Default-deny bypass on the plain-HTTP request path when
  CONNECT filtering is configured correctly but HTTP forwarding is not.
- **Caveats:** The hostname must be unlisted. Any status at least 400 passes,
  including upstream failures; inspect the response and denial cause.

### `direct-ip-connect`

- **What it does:** Attempts CONNECT to the public literal `1.1.1.1:443`.
- **Risk tested:** Bypassing a hostname allowlist by addressing a server
  directly, without presenting an approved hostname.
- **Caveats:** A pass establishes refusal of this literal, not why it was
  refused. It does not cover IPv6 public literals, alternative IP spellings
  or literal destinations on the plain-HTTP path.

### `loopback-ipv4`

- **What it does:** Attempts CONNECT to `127.0.0.1:80`.
- **Risk tested:** Using the proxy for server-side request forgery (SSRF)
  against services on the proxy's own loopback interface.
- **Caveats:** Loopback is relative to the proxy's network namespace, which
  may be a container rather than the host. Only one address is sampled;
  hostname or port rejection can mask missing loopback filtering.

### `rfc1918-ipv4`

- **What it does:** Attempts CONNECT to `10.0.0.1:80`, `192.168.1.1:80`
  and `172.16.0.1:80`; all must be refused.
- **Risk tested:** SSRF into private networks to reach internal applications,
  routers or administrative services accessible from the proxy.
- **Caveats:** These are representatives of the three RFC1918 ranges, not
  exhaustive coverage. Other private/special ranges are not tested here.
  A hostname or port denial does not prove resolved-IP filtering works.

### `link-local-ipv4`

- **What it does:** Attempts CONNECT to `169.254.1.1:80`.
- **Risk tested:** Reaching services on the proxy's local link that should
  not be exposed to an untrusted client.
- **Caveats:** One address represents `169.254.0.0/16`. This does not test
  every link-local service, and a literal/port rule can deny it first.

### `metadata-endpoint`

- **What it does:** Probes `169.254.169.254:80` with CONNECT and GETs
  `http://169.254.169.254/latest/meta-data/`; both paths must be refused.
- **Risk tested:** SSRF to a cloud metadata service that could expose
  instance information or credentials to the sandboxed client.
- **Caveats:** It does not perform a credential retrieval or token exchange,
  or cover provider-specific alternative endpoints. An HTTP authentication
  error can count as a pass even if metadata was reached. CONNECT also uses
  the generic TLS/HTTP follow-up, which cannot establish reachability of a
  plaintext-only service; literal or port denial can mask the metadata rule.

### `loopback-ipv6`

- **What it does:** Attempts CONNECT to `[::1]:80`.
- **Risk tested:** An IPv6 route to local services left open by IPv4-only
  SSRF protections.
- **Caveats:** Tests bracketed IPv6 loopback only, not IPv4-mapped IPv6 or
  alternative encodings. Parsing, hostname or port rejection can occur before
  address validation; missing IPv6 connectivity does not prove enforcement.

### `private-ipv6`

- **What it does:** Attempts CONNECT to `[fd00::1]:80` and `[fe80::1]:80`;
  both must be refused.
- **Risk tested:** SSRF to IPv6 unique-local or link-local services despite
  restrictions on private IPv4 destinations.
- **Caveats:** Samples one address of each kind, not the full ranges.
  The link-local target has no interface scope identifier. Parsing, port
  policy and IPv6 routing can prevent the intended address check from running.

## Full-suite additions

### `dns-private-ipv4`

- **What it does:** CONNECTs on port 80 to `10.0.0.1.nip.io`,
  `192.168.1.1.nip.io`, `127.0.0.1.nip.io` and
  `169.254.169.254.nip.io`. All must be refused; attempts retain the
  checker's own DNS answers.
- **Risk tested:** An approved hostname resolving to a private, loopback or
  metadata address, bypassing a policy that checks only the requested name.
- **Caveats:** Requires the lab's `*.nip.io` allowance and external DNS.
  The checker's answers need not match the proxy's. Port restrictions or DNS
  filtering can stop the request before resolved-address validation; inspect
  causes rather than assuming every pass proves SSRF filtering.

### `dns-private-ipv6`

- **What it does:** CONNECTs on port 80 to `0--1.sslip.io`,
  `fe80--1.sslip.io` and `fd00--1.sslip.io`, representing loopback,
  link-local and unique-local IPv6. All must be refused.
- **Risk tested:** The same approved-name SSRF bypass through AAAA answers,
  exposing gaps in IPv6 address validation.
- **Caveats:** Requires the lab's `*.sslip.io` allowance and working external
  DNS. Local resolution is diagnostic, not proof of the proxy's answer.
  Port, DNS or parser rejection can mask the intended rule. `0--1` is
  deliberately used because the equivalent `--1` label is invalid IDNA.

### `dns-rebinding`

- **What it does:** Creates three fresh names under `rebind.fixture.test`,
  probes each on port 443, waits 1.5 seconds, then probes each again. The
  fixture returns its controlled public-address origin first and a private
  trap on subsequent lookups. Any new trap connection fails the check.
- **Risk tested:** An attacker changing DNS after initial validation so a
  later lookup or connection reaches an internal address.
- **Caveats:** Requires observable fixture DNS/trap logs. No observed lookup
  skips; no repeat lookup yields an error. A pass requires at least one name
  to be looked up again and no trap hits, not all three names rebinding or all
  repeat probes completing conclusively. Reusing a previously validated public
  address is acceptable. Cache timing, connection reuse and other races are
  not exhaustively explored; lab Squid uses a shorter caching time. Shared trap
  traffic during the check can confound attribution.

### `dns-mixed-answers`

- **What it does:** First requires TLS/HTTP success through
  `public-only.fixture.test:443`. It then probes
  `mixed-public-first.fixture.test:443` and
  `mixed-private-first.fixture.test:443`, whose answers mix public and private
  addresses in opposite orders. Either tunnel carrying HTTP traffic, or any
  new private-trap connection, fails the check.
- **Risk tested:** Validating only the first or selected DNS answer and
  overlooking a private address that could be used during selection or fallback.
- **Caveats:** This tests the strict policy of rejecting the entire mixed
  answer set: connecting only to its public address still fails. An unsuccessful
  public control skips the check; ambiguous mixed-probe failures are errors.
  The fixture samples two IPv4 orderings, not every resolver behavior or
  A/AAAA combination. Trap evidence assumes no unrelated concurrent probes.

### `ptr-allowlist`

- **What it does:** CONNECTs to `1.0.0.1:443` while the lab DNS fixture claims
  its PTR name is `pypi.org`. Requires observable fixture logs and records
  whether the proxy performed a reverse lookup.
- **Risk tested:** An attacker-controlled reverse-DNS record satisfying a
  hostname allowlist even though the client requested an unapproved IP literal.
- **Caveats:** Rejecting literals before reverse lookup is a valid pass.
  Successful traffic fails, but does not by itself prove PTR-based authorization.
  The destination is external; transport failure is inconclusive. This tests
  one forged PTR claim, not all reverse/forward DNS consistency scenarios.

### `connect-sni-mismatch`

- **What it does:** CONNECTs to `pypi.org:443` but sends TLS SNI
  `files.pythonhosted.org`; both names are allowlisted. A successful handshake
  fails. If TLS fails after CONNECT, it tries matching SNI as a control and
  grades denial when that control succeeds; if both fail, it reports an error.
- **Risk tested:** Using an approved CONNECT destination while asking a
  shared TLS endpoint for another virtual host, separating the declared tunnel
  target from the service selected inside it.
- **Caveats:** This tests equality of two allowed names, not successful access
  to a forbidden service or HTTP Host-based fronting. A matching-SNI control
  reduces ambiguity but cannot rule out origin-specific rejection of the
  mismatched SNI. Pre-handshake CONNECT failures also grade as denial without
  proving SNI inspection. Certificate validation is disabled; no application
  request is made. Engine logs help attribute the result.

### `connect-raw-tunnel`

- **What it does:** CONNECTs to `pypi.org:443` and sends a plaintext HTTP GET
  inside the tunnel. Any returned bytes grade as allowed/fail, including a TLS
  alert; no returned bytes grade as denied/pass.
- **Risk tested:** Using an HTTPS CONNECT allowance to carry non-TLS traffic,
  potentially reaching another protocol on an approved destination and port.
- **Caveats:** This is a response-based heuristic. Silence, reset or a CONNECT
  failure can pass without proving deliberate proxy enforcement; a returned
  alert/error can come from the proxy rather than the origin. Inspect engine
  logs. One plaintext HTTP payload does not cover arbitrary protocols, and
  a returned alert does not prove a useful application session was established.

### `concurrency-sanity`

- **What it does:** Starts ten concurrent CONNECT attempts to `pypi.org:443`
  and immediately closes accepted tunnels. Passes only if all ten succeed.
- **Risk tested:** Basic availability regressions such as connection drops
  under the modest parallelism of normal package/tool traffic.
- **Caveats:** Counts CONNECT acceptance only, without TLS or HTTP. It has no
  throughput or latency threshold, so cannot prove the proxy avoids serialization.
  It is not a load, resource-exhaustion or denial-of-service resistance test;
  external network failures can also cause failure.
