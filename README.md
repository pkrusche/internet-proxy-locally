# internet-proxy-locally

A small, local, containerized Internet filtering proxy for coding-agent
sandboxes. Default deny, hostname allowlist, SSRF protection, fail closed.

One stable endpoint — `http://127.0.0.1:18080` — backed by
[Pipelock](https://github.com/luckyPipewrench/pipelock) (default),
[Smokescreen](https://github.com/stripe/smokescreen) or
[Squid](https://www.squid-cache.org/).
Docker and Apple `container` are both first-class. No Docker Compose.

## Quick start

```bash
./run.py setup          # validate prerequisites, pull/build pinned images
./run.py up             # start the proxy and health-check it
./run.py check --quick  # confirm allow/deny behavior

export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080
curl https://github.com          # allowlisted → works
curl https://example.com         # not allowlisted → denied by the proxy
```

Requires Python 3.11+ (stdlib only) and Docker or Apple `container`.

## Commands

| | |
| --- | --- |
| `./run.py setup` | validate prerequisites, pull/build pinned images |
| `./run.py up` | (re)create the container and health-check it |
| `./run.py status` | engine, backend, container state, pins, live health |
| `./run.py logs` | engine logs |
| `./run.py check` | egress security suite (`--quick` / `--full`, `--json`) |
| `./run.py restart` | explicit teardown then up |
| `./run.py down` | remove containers owned by this repository |
| `./run.py pin` | record immutable image/source pins |

`--engine pipelock|smokescreen|squid` and `--backend docker|container`
override the defaults. Full reference: [docs/usage.md](docs/usage.md).

## Documentation

| | |
| --- | --- |
| [architecture.md](docs/architecture.md) | how it fits together, stable contract, responsibilities, non-goals |
| [usage.md](docs/usage.md) | command reference, lifecycle, health check, local tests |
| [policy.md](docs/policy.md) | the allowlist, the rules, how to change them |
| [security.md](docs/security.md) | threat model, fail-closed properties, what it does *not* defend against |
| [comparison.md](docs/comparison.md) | **measured** Pipelock vs Smokescreen vs Squid results and the default-engine decision |
| [backends.md](docs/backends.md) | Docker vs Apple `container`, parity status, upgrades |

Open work is tracked in [TODO.md](TODO.md).

## Status

The service is implemented and all three engines have been measured
against the common adversarial suite
([docs/comparison.md](docs/comparison.md)). Of 14 graded checks, all three
pass the same 13. The fourteenth, `dns-mixed-answers`, is new and is the
first to separate them on enforcement rather than grading: given a
hostname resolving to both a public and a private address, Pipelock and
Squid refuse the name and **Smokescreen connects to the public address**,
so `check --full` exits 1 on Smokescreen. It does not reach the private
address; the finding and the decision it forces are findings 9 and 11.

Pipelock stays the default because it enforces inside CONNECT tunnels
(SNI verification, TLS-required) where Smokescreen and Squid do not.

Squid differs from the other two in where its policy lives: Pipelock and
Smokescreen block private destinations in engine code, while Squid's SSRF
floors are ordinary `dst` ACLs in `config/squid.conf`, ordered ahead of
the allowlist. That makes them reviewable — and `./run.py setup` checks
the required ranges and the rule order rather than trusting them.

Not yet verified: the `project-sandbox` integration matrix, and Squid plus
the DNS fixture on the Docker backend (both were measured on Apple
`container`). See TODO.md.

## Important limitation

Without TLS interception (deliberately out of scope — see
[docs/security.md](docs/security.md)), destination filtering limits **where**
an agent can connect but cannot inspect encrypted request bodies. Data can
still be pushed to an already-allowlisted HTTPS service.
