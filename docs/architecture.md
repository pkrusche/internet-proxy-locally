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
procedure; the security tests; and the cross-engine comparison.

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
