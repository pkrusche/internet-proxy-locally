# Security model

## What this service defends against

The client is assumed hostile: a coding agent (or code it wrote) running
inside `project-sandbox` with `HTTP_PROXY`/`HTTPS_PROXY` pointed here and
all other egress dropped by iptables. The proxy's job is to limit **where**
that client can connect:

* only allowlisted Internet hostnames;
* never private, loopback, link-local, or metadata addresses — including
  via DNS tricks (public hostname → private A/AAAA record, rebinding,
  mixed answers);
* no CONNECT tunnel abuse where the engine supports detecting it
  (SNI ↔ CONNECT target mismatch / domain fronting, non-TLS bytes inside
  a tunnel).

## What it does not defend against

* **Exfiltration to an allowed HTTPS destination.** Without TLS
  interception (explicitly out of scope for v1, see docs/pipelock.md) the
  proxy cannot see encrypted request bodies. If `github.com` is allowed,
  data can be pushed to any reachable GitHub repository.
* Anything reachable without traversing the proxy. Preventing direct
  egress is `project-sandbox`'s iptables responsibility.
* Malicious content in allowed responses.

## Fail-closed properties

* `up` refuses to start with an invalid or non-strict policy file.
* `up` refuses unpinned images (no digest / no source SHA) and `latest` tags.
* `up` refuses the endpoint when an unknown process occupies it.
* The post-start health check requires the proxy to *deny* a
  non-allowlisted probe host; a proxy that answers 2xx/3xx for it is
  treated as broken, not healthy.
* If the proxy container dies, nothing listens on `127.0.0.1:18080` — the
  sandbox loses Internet rather than gaining unfiltered access. There is
  no automatic restart policy; restarts are explicit (`./run.py restart`).
* Open modes are rejected by validation (`action: open`,
  `--unsafe-allow-private-ranges`, `tls_interception.enabled: true`,
  non-`strict` Pipelock modes).

## The adversarial suite

```bash
./run.py check --quick   # ordinary allow/deny behavior
./run.py up --test-policy && ./run.py check --full
```

`checks/egress.py` runs identically against both engines and emits
comparable text or `--json` results; see docs/comparison.md for where the
measured results go. The full suite covers private IPv4/IPv6, metadata,
DNS-resolved private targets (nip.io / sslip.io fixtures), DNS rebinding
(rbndr.us, recorded — timing dependent), SNI mismatch, raw bytes inside a
CONNECT tunnel, IP-form CONNECT, and a concurrency sanity check.

### Local DNS fixture for mixed answers

Public wildcard-DNS services cannot serve mixed public+private answer
sets reliably. To run the `dns-mixed-answers` test, point the proxy
container at a local dnsmasq with a crafted record, e.g.:

```bash
dnsmasq --no-daemon --port 5353 \
  --host-record=mixed.fixture.test,93.184.216.34,10.0.0.1
```

then add `mixed.fixture.test` to the *test* policy, run the engine with
its DNS pointed at that resolver, and verify the proxy refuses the
connection (an engine picking "just the public answer" silently is a
finding worth recording in docs/comparison.md).

## Endpoint exposure

The container publishes `127.0.0.1:18080` only. That is a convenience
boundary, not the security boundary: the policy remains enforced even for
traffic that reaches the engine's internal address from another local
container. No unauthenticated open-proxy mode exists in the shipped
configuration; client authentication is deferred until multiple caller
identities need different policies (see README §3).
