# internet-proxy-locally

## Goal

Provide a small, local, containerized Internet filtering proxy for coding-agent sandboxes.

The service is intended to work with `project-sandbox`, but is independently useful and independently managed.

Primary requirements:

* simple local setup;
* Docker support;
* Apple `container` support;
* no Docker Compose;
* one stable host-loopback HTTP proxy endpoint;
* strict destination policy;
* protection against SSRF/private-network access;
* usable by standard `HTTP_PROXY` / `HTTPS_PROXY` clients;
* fail closed;
* independently testable;
* no AI-provider credential handling;
* no MCP routing;
* no dependency on Agentgateway.

Agentgateway remains a separate local service for AI APIs and MCP.

---

## Architecture

```text
                         host
┌─────────────────────────────────────────────────────┐
│                                                     │
│  Agentgateway                 Internet proxy        │
│  127.0.0.1:4000              127.0.0.1:18080        │
│       │                              │              │
│       │                              │              │
│       ▼                              ▼              │
│  OpenAI / Anthropic           Pipelock or           │
│  and MCP services             Smokescreen           │
│                                      │              │
│                                      ▼              │
│                                public Internet      │
└─────────────────────────────────────────────────────┘
             ▲                       ▲
             │                       │
             └──── project-sandbox ──┘
                       iptables
                     default DROP
```

The proxy SHALL expose the same host-side endpoint regardless of implementation:

```text
http://127.0.0.1:18080
```

Internal container ports may differ.

`project-sandbox` therefore does not need to know whether Pipelock or Smokescreen is running.

---

## Responsibilities

### This repository owns

* proxy implementation selection;
* container image selection/building;
* image pinning;
* Pipelock configuration;
* Smokescreen configuration;
* Internet allowlist;
* SSRF/private-address policy;
* proxy lifecycle;
* logs;
* health/status;
* upgrade procedure;
* security tests;
* Pipelock-vs-Smokescreen comparison.

### project-sandbox owns

* forwarding the host-loopback endpoint into the sandbox;
* injecting `HTTP_PROXY` / `HTTPS_PROXY`;
* preventing direct egress with iptables;
* keeping Agentgateway and other local services in `NO_PROXY`.

### agentgateway-locally owns

* AI API routing;
* MCP;
* provider API keys;
* gateway authentication;
* AI request logging.

---

# 1. Repository shape

Follow the operational pattern established by `agentgateway-locally`.

Proposed layout:

```text
internet-proxy-locally/
├── README.md
├── PLAN.md
├── run.py
├── services/
│   ├── pipelock.toml
│   └── smokescreen.toml
├── config/
│   ├── pipelock.yaml
│   └── smokescreen.yaml
├── images/
│   └── smokescreen/
│       └── Dockerfile
├── checks/
│   └── egress.py
├── tests/
│   └── ...
└── docs/
    ├── backends.md
    ├── policy.md
    ├── security.md
    ├── pipelock.md
    └── smokescreen.md
```

`run.py` should be Python 3.11+ and preferably stdlib-only.

No `docker-compose.yml`.

---

# 2. Runtime interface

Use one CLI for both Docker and Apple `container`.

Examples:

```bash
./run.py setup

./run.py --engine pipelock up
./run.py --engine smokescreen up

./run.py status
./run.py logs
./run.py check
./run.py down
```

Backend override:

```bash
./run.py --backend docker --engine pipelock up
./run.py --backend container --engine pipelock up
```

Defaults:

* on macOS, prefer Apple `container` when installed and supported;
* otherwise use Docker;
* allow an explicit backend override;
* default proxy engine initially: **Pipelock**, subject to parity testing below.

### Lifecycle semantics

Match `agentgateway-locally` where useful:

* explicit `up`;
* explicit `down`;
* no Compose;
* no hidden background supervisor;
* no platform-specific automatic restart policy;
* `up` may recreate the container rather than mutating a stopped one;
* `restart` means explicit teardown/recreation;
* `status` reports the selected implementation and runtime.

---

# 3. Stable external contract

Both engines SHALL expose:

```text
127.0.0.1:18080
```

as a standard HTTP forward proxy.

Clients use:

```bash
export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080
```

The service SHALL NOT require clients to know:

* internal container ports;
* engine-specific hostnames;
* engine-specific CLI arguments.

### Host binding

Publish only the intended host-loopback port where the runtime supports host publication controls.

Do not treat host-loopback publication as the entire security boundary. The proxy itself must remain allowlist/enforcement configured even if another local container can reach its internal address.

No unauthenticated **open** proxy mode is allowed in the shipped configuration.

Client authentication is not required for v1 because:

* the service carries no provider credentials;
* it exposes only an allowlisted Internet capability;
* `project-sandbox` independently restricts sandbox egress.

This can be revisited if multiple caller identities require different policies.

---

# 4. Shared Internet policy

Maintain one documented logical policy and express it in both engines.

Initial policy mode:

```text
default: deny
```

Start with a deliberately small developer allowlist, for example:

```text
github.com
*.github.com
*.githubusercontent.com

pypi.org
files.pythonhosted.org

registry.npmjs.org
```

Expand only from demonstrated requirements.

Do not include OpenAI or Anthropic API domains merely because coding agents use them. AI APIs are expected to go through Agentgateway.

### Policy rules

* allowlist rather than denylist;
* reject private IPv4;
* reject loopback;
* reject link-local;
* reject cloud metadata addresses;
* reject private/link-local IPv6;
* validate destinations after DNS resolution;
* protect against DNS rebinding;
* preserve explicit logs for rejected destinations.

### Policy ownership

`config/` is the source of truth.

`project-sandbox --extra-domain` does not mutate these files.

Changes to the allowlist require a normal reviewable repository change.

---

# 5. Pipelock implementation

## Initial operating mode

Use Pipelock as a **strict standard forward proxy**, not as an MCP or AI gateway.

Do not use its MCP/A2A features here.

Initial intent:

```yaml
version: 1
mode: strict
enforce: true

api_allowlist:
  - github.com
  - "*.github.com"
  - "*.githubusercontent.com"
  - pypi.org
  - files.pythonhosted.org
  - registry.npmjs.org

forward_proxy:
  enabled: true
  sni_verification: true
  sni_require_tls: true

tls_interception:
  enabled: false
```

Exact configuration must be validated against the pinned Pipelock release.

## Why Pipelock is the initial preferred backend

Relevant advantages for a hostile coding-agent client:

* destination allowlisting;
* SSRF/private-network protection;
* DNS-rebinding protections;
* CONNECT destination ↔ TLS SNI verification;
* ability to require TLS inside CONNECT tunnels;
* agent-oriented egress security controls;
* official OCI image;
* signed/SBOM-backed releases;
* richer audit/evidence capabilities;
* optional future TLS content inspection.

The important features for v1 are destination and tunnel controls, not MCP support.

## Image

Use the upstream OCI image.

* pin both release version and immutable digest;
* document the update procedure;
* do not use `latest` in the stable configuration;
* verify architecture support for both expected Docker and Apple Silicon environments.

## TLS interception

Explicitly disabled for v1.

Reasons:

* no local CA lifecycle;
* no CA private-key custody;
* no agent image trust-store changes;
* no certificate-pinning breakage;
* simpler debugging;
* smaller operational surface.

Consequently Pipelock does **not** provide full HTTPS request-body DLP in the initial configuration.

That limitation is accepted.

A later experiment MAY evaluate TLS interception specifically for preventing exfiltration to otherwise permitted domains.

---

# 6. Smokescreen implementation

Smokescreen is the conservative/minimal comparison implementation.

Configure:

```text
default service:
    action = enforce
```

with the same logical hostname allowlist as Pipelock.

Enable/retain:

* public-IP validation;
* private-range blocking;
* explicit DNS handling;
* connection timeout;
* reasonable request/concurrency limits;
* structured access logs where practical.

Do not use `open` mode.

## Image

Upstream Smokescreen does not currently provide the same turnkey OCI packaging as Pipelock.

Carry a minimal multi-stage Dockerfile in:

```text
images/smokescreen/Dockerfile
```

Requirements:

* pin the upstream source revision/release;
* pin builder/runtime base images where practical;
* produce a small final image;
* run unprivileged if supported;
* include required license notices;
* build successfully through both Docker and Apple `container` build workflows used by this repository.

The built image is local by default. Publishing it is out of scope until third-party distribution requirements are reviewed.

## mTLS

Do not enable Smokescreen client mTLS initially.

mTLS becomes useful if a future shared proxy serves different caller identities with different policies.

---

# 7. Pipelock vs Smokescreen decision criteria

The purpose of supporting both initially is to make the decision empirical.

| Property                            | Pipelock                | Smokescreen                      |
| ----------------------------------- | ----------------------- | -------------------------------- |
| Default-deny hostname policy        | Yes                     | Yes                              |
| Public-IP / SSRF protection         | Yes                     | Yes                              |
| DNS rebinding protection            | Yes                     | Yes                              |
| Standard CONNECT                    | Yes                     | Yes                              |
| CONNECT ↔ SNI verification          | Strong explicit support | Verify experimentally            |
| Require TLS inside CONNECT          | Yes                     | Verify experimentally            |
| HTTPS body inspection without MITM  | No                      | No                               |
| Optional TLS MITM later             | Yes                     | No                               |
| Rate / concurrency control          | Yes                     | Yes                              |
| Official OCI image                  | Yes                     | No equivalent upstream packaging |
| Operational history                 | Newer                   | Much longer                      |
| Config surface                      | Larger                  | Smaller                          |
| Agent-specific security features    | Extensive               | Minimal                          |
| Fit for minimal allowlist proxy     | Good                    | Excellent                        |
| Fit for hostile coding-agent egress | Excellent               | Good                             |

### Current working hypothesis

Use **Pipelock as the default** if its strict forward-proxy behavior proves stable.

Keep **Smokescreen as the fallback** if operational simplicity and maturity outweigh Pipelock's stronger CONNECT tunnel controls.

Do not make the final decision based on feature tables alone.

---

# 8. Common adversarial test suite

`checks/egress.py` SHALL run against either engine.

The test runner should accept something like:

```bash
./run.py --engine pipelock check
./run.py --engine smokescreen check
```

and produce comparable results.

## Basic policy

* [ ] Allowed HTTP destination succeeds.
* [ ] Allowed HTTPS destination succeeds.
* [ ] Blocked hostname fails.
* [ ] Direct destination-IP access fails unless explicitly allowed.
* [ ] `127.0.0.1` fails.
* [ ] RFC1918 IPv4 fails.
* [ ] IPv4 link-local fails.
* [ ] `169.254.169.254` fails.
* [ ] IPv6 loopback fails.
* [ ] IPv6 private/link-local destination fails.

## DNS / SSRF

* [ ] Public hostname resolving to private IPv4 is rejected.
* [ ] Public hostname resolving to private IPv6 is rejected.
* [ ] Mixed public/private DNS answers fail safely.
* [ ] DNS rebinding test does not permit switching to a forbidden address.
* [ ] Destination validation occurs on the resolved target rather than hostname text alone.

## CONNECT abuse

Test with a controlled local fixture where necessary.

### Valid tunnel

```text
CONNECT allowed.example:443
TLS SNI = allowed.example
```

* [ ] succeeds.

### SNI mismatch

```text
CONNECT allowed.example:443
TLS SNI = different.example
```

Expected:

* [ ] Pipelock rejects it with SNI verification enabled.
* [ ] Record Smokescreen behavior.

### Raw protocol smuggling

```text
CONNECT allowed.example:443
<non-TLS arbitrary bytes>
```

Expected:

* [ ] Pipelock rejects it with `sni_require_tls`.
* [ ] Record Smokescreen behavior.

### IP-form CONNECT

* [ ] Measure and document both engines' handling of direct-IP CONNECT targets.
* [ ] Ensure private/routability checks still apply.

These CONNECT tests are a major part of the final backend decision.

---

# 9. project-sandbox integration tests

In addition to standalone proxy tests, document a manual or automated integration matrix with `project-sandbox`.

## Proxy routing

Inside the sandbox:

```bash
curl https://github.com
```

* [ ] succeeds through the proxy when GitHub is allowlisted.

```bash
curl https://<blocked-domain>
```

* [ ] fails at the proxy policy.

## Bypass

```bash
curl --noproxy '*' https://github.com
```

* [ ] fails at the sandbox iptables layer.

* [ ] Unset `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`: Internet fails.

* [ ] Raw TCP to public port 443 fails.

* [ ] Raw UDP Internet access fails.

* [ ] Direct DNS fails.

## Agentgateway separation

Run both `agentgateway-locally` and this repository.

* [ ] AI request succeeds through Agentgateway.
* [ ] General Internet succeeds through the Internet proxy.
* [ ] Agentgateway does not accidentally traverse the Internet proxy.
* [ ] Internet traffic does not accidentally traverse Agentgateway.
* [ ] Stop Internet proxy: AI still works.
* [ ] Stop Agentgateway: allowed ordinary Internet still works.

---

# 10. Health and operational commands

## `setup`

* validate Python version;
* detect available container backends;
* verify selected engine prerequisites;
* build Smokescreen image when needed;
* pull/verify pinned Pipelock image when needed;
* validate configuration files;
* do not silently modify system networking.

## `up`

* validate configuration;
* recreate selected proxy container;
* publish stable host endpoint;
* fail if the endpoint is already unexpectedly occupied;
* perform post-start health/proxy test.

## `status`

Show:

* selected engine;
* selected backend;
* container state;
* configured/pinned image;
* host proxy endpoint;
* whether a basic local proxy check succeeds.

## `logs`

Expose engine logs through the selected container runtime.

## `check`

Run the common security test suite.

Offer at least:

```text
--quick
--full
```

where quick checks ordinary allow/deny behavior and full includes SSRF and CONNECT-abuse fixtures.

## `down`

Remove only resources owned by this repository.

Do not affect Agentgateway or project-sandbox containers.

---

# 11. Logging and privacy

Internet-proxy logs can reveal:

* requested hostnames;
* URLs for plaintext HTTP;
* timestamps;
* traffic volume;
* potentially request content depending on engine/features.

Document this clearly.

For Pipelock:

* configure only the logging/evidence features intentionally required;
* understand what signed receipts persist before enabling them broadly;
* do not enable unrelated telemetry implicitly.

For Smokescreen:

* document access-log fields and retention.

No provider API keys should be present in this service by design.

Do not add OpenAI/Anthropic secrets to this repository.

---

# 12. Backend parity

Docker and Apple `container` are first-class.

Every runtime-affecting feature must be tested or explicitly documented as backend-specific.

Required parity:

* [ ] `setup`
* [ ] image pull/build
* [ ] `up`
* [ ] loopback port publication
* [ ] `status`
* [ ] `logs`
* [ ] `check`
* [ ] `down`

Do not add features implemented only through Docker Compose.

If Apple `container` lacks an exact Docker feature, prefer a common lower-level behavior rather than creating divergent security semantics.

---

# 13. Implementation phases

## Phase 1 — Pipelock minimum viable service

* [ ] Create repository skeleton.
* [ ] Implement backend detection.
* [ ] Implement Pipelock service definition.
* [ ] Pin Pipelock image.
* [ ] Add strict allowlist config.
* [ ] Expose `127.0.0.1:18080`.
* [ ] Implement `up/status/logs/down`.
* [ ] Implement quick allow/deny check.
* [ ] Verify Docker.
* [ ] Verify Apple `container`.

Deliverable:

```text
HTTPS_PROXY=http://127.0.0.1:18080 curl https://github.com
```

works, while a non-allowlisted host fails.

## Phase 2 — Smokescreen comparison backend

* [ ] Add pinned Smokescreen source/version.
* [ ] Add local multi-stage image.
* [ ] Add equivalent allowlist.
* [ ] Expose the same host endpoint.
* [ ] Implement the same lifecycle interface.
* [ ] Verify Docker.
* [ ] Verify Apple `container`.

## Phase 3 — Adversarial parity suite

* [ ] Private IPv4.
* [ ] Private IPv6.
* [ ] Metadata endpoint.
* [ ] DNS-rebinding fixture.
* [ ] Mixed DNS result fixture.
* [ ] SNI mismatch.
* [ ] Raw CONNECT tunnel.
* [ ] Rate/concurrency sanity.
* [ ] Crash/restart/fail-closed behavior.

Record results in a checked-in comparison document.

## Phase 4 — project-sandbox integration

* [ ] Verify `--internet-proxy`.
* [ ] Verify iptables bypass prevention.
* [ ] Verify `NO_PROXY` for Agentgateway.
* [ ] Verify independent failure of Agentgateway and Internet proxy.
* [ ] Add README instructions linking both repositories.

## Phase 5 — choose default

Based on measured behavior:

* [ ] Confirm Pipelock as default; or
* [ ] Switch default to Smokescreen.

Both may remain supported if maintenance cost stays low.

---

# 14. Definition of done

The initial project is complete when:

1. one command starts an Internet filtering proxy under Docker or Apple `container`;
2. no Compose is required;
3. the stable endpoint is `http://127.0.0.1:18080`;
4. allowed Internet destinations work;
5. unapproved destinations fail;
6. private/internal destinations fail;
7. `project-sandbox` can use the endpoint while blocking direct bypass;
8. Agentgateway remains completely separate;
9. Pipelock and Smokescreen have been run through the same adversarial suite;
10. the default backend choice is documented with measured reasons.

---

# 15. Explicit non-goals

Initial versions do not aim to:

* replace Agentgateway;
* proxy MCP;
* proxy AI-provider credentials;
* implement transparent networking;
* redirect arbitrary TCP automatically;
* use Docker Compose;
* run one filtering proxy container per sandbox;
* create per-project shared container networks;
* perform TLS interception;
* manage a private CA;
* inspect all HTTPS bodies;
* provide enterprise fleet management;
* expose the proxy to the LAN;
* dynamically accept domain changes from `project-sandbox`;
* guarantee that data cannot be exfiltrated to an already-allowlisted HTTPS service.

The last item is important: without TLS interception, destination filtering limits **where** the agent can connect, but generally cannot inspect encrypted request bodies sent to an allowed HTTPS destination.
