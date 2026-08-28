# Architecture

A small, local, containerized Internet filtering proxy for coding-agent
sandboxes. It is built to work with [project-sandbox](https://github.com/pkrusche/project-sandbox)
but can be used independently.

```text
                         host
┌─────────────────────────────────────────────────────┐
│                                                     │
│  Agentgateway                 Internet proxy        │
│  127.0.0.1:4000              127.0.0.1:18080        │
│       │                              │              │
│       │                              │              │
│       ▼                              ▼              │
│  OpenAI / Anthropic           Pipelock,             │
│  and MCP services             Smokescreen or Squid  │
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

Agentgateway is a separate local service for AI APIs and MCP. This
repository has no dependency on it and carries no provider credentials.

**The bottom half of that diagram is an intended integration, not a
description of any particular machine.** The endpoint is this
repository's to provide and is verified here; *routing* a sandbox through
it is `project-sandbox`'s to do, and the currently installed release does
not: it sets no `HTTP_PROXY`/`HTTPS_PROXY`, never names the endpoint, and
filters egress with its own iptables/ipset domain allowlist instead
(measured 2026-08-28 by `scripts/verify_sandbox.py`, which reads it off
the installation rather than assuming). Wiring it means setting the proxy
variables in `project-sandbox` and allowing the endpoint through its
firewall — work in that repository, not this one. Until then, exporting
`HTTP_PROXY` by hand is what puts a client behind this proxy.

See also <https://github.com/pkrusche/agentgateway-locally>.

## Stable external interface

Supported proxy engines expose the same host-side endpoint as a standard HTTP forward
proxy, regardless of implementation:

```text
http://127.0.0.1:18080
```

Internal container ports differ (Pipelock 8888, Smokescreen 4750, Squid
3128) and are not part of the contract. `project-sandbox` does not need to
know which engine is running.

Clients use the standard environment variables:

```bash
export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080
```

## Responsibilities

**This repository owns** engine selection; image selection, building and
pinning; every engine configuration; the Internet allowlist; SSRF/private
-address policy; proxy lifecycle; logs; health and status; the upgrade
procedure; the security tests; and the cross-engine comparison —
generated into docs/comparison.md from committed result files, so the
comparison is a rendering of measurements rather than a transcription of
them (docs/engines.md holds the reading of those measurements).

## Where the policy comes from

```text
config.toml            the allowlist, written once
   +  templates/*.j2   everything else each engine needs, as literal text
   |
   |  ./run.py policy  (also run by setup / up / restart)
   v
config/pipelock.yaml   config/smokescreen.yaml   config/squid.conf
config/*.test.*        the same, plus [policy.test]
config/dns-fixture.hosts   the test fixture's records, from [fixture]
   |
   |  --volume ...:ro
   v
the running container
```

The generated files are committed, because they are what a reviewer reads
and what the container mounts. Only domains are generated: the deny
floors, rule order and every enforcement switch are literal text in the
templates. `validate_policy_file()` — a regex reader that knows nothing
about the generator — checks the rendered output before it is written, so
a generator bug fails closed instead of shipping (docs/policy.md).

## Non-goals

This service does not aim to replace Agentgateway, proxy MCP, proxy
AI-provider credentials, implement transparent networking, redirect
arbitrary TCP, use Docker Compose, run one proxy container per sandbox,
create per-project shared container networks, perform TLS interception,
manage a private CA, inspect HTTPS bodies, provide fleet management,
expose the proxy to the LAN, or accept dynamic domain changes from
`project-sandbox`.

It also does not guarantee that data cannot be exfiltrated to an
already-allowlisted HTTPS service. Without TLS interception, destination
filtering limits **where** the agent can connect but generally cannot
inspect encrypted request bodies sent to an allowed destination. See
docs/security.md.
