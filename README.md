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
uv sync                 # once: create .venv (Python 3.11+, Jinja2)
./run.py setup          # validate prerequisites, pull/build pinned images
./run.py up             # start the proxy and health-check it
./run.py check --quick  # confirm allow/deny behavior

export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080
curl https://github.com          # allowlisted → works
curl https://example.com         # not allowlisted → denied by the proxy
```

Requires Python 3.11+, [uv](https://docs.astral.sh/uv/), and Docker or
Apple `container`. The only dependency is Jinja2, used by one code path —
rendering the engine configs from `config.toml`. It is imported lazily, so
`down`, `status` and `logs` still work on a bare interpreter.

## The allowlist

`config.toml` at the repository root holds the allowlist, once:

```toml
[policy]
allow = ["github.com", "*.github.com", "pypi.org", ...]
```

`./run.py` renders it into all six engine configs (`config/*.yaml`,
`config/squid.conf` and the `.test` variants) through `templates/`, and
`setup` / `up` / `restart` do that before starting anything — so the three
engines cannot express different policies. Edit `config.toml`, run
`./run.py up`, commit both. `./run.py policy --check` reports drift
without writing. See [docs/policy.md](docs/policy.md).

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
| `./run.py policy` | render `config/*` from `config.toml` (`--check` to report drift) |

`--engine pipelock|smokescreen|squid` and `--backend docker|container`
override the defaults. Full reference: [docs/usage.md](docs/usage.md).

## Documentation

| | |
| --- | --- |
| [architecture.md](docs/architecture.md) | how it fits together, stable contract, responsibilities, non-goals |
| [usage.md](docs/usage.md) | command reference, lifecycle, health check, local tests |
| [policy.md](docs/policy.md) | the allowlist, the rules, how to change them |
| [security.md](docs/security.md) | threat model, fail-closed properties, what it does *not* defend against |
| [comparison.md](docs/comparison.md) | **generated** Pipelock vs Smokescreen vs Squid results — every row measured, nothing written by hand |
| [engines.md](docs/engines.md) | what those results mean: the differences that matter, the corrections, the default-engine decision |
| [backends.md](docs/backends.md) | Docker vs Apple `container`, parity status, upgrades |

Open work is tracked in [TODO.md](TODO.md).

## Status

The service is implemented and all three engines are measured against the
common adversarial suite on every run of `scripts/report.py --run`, which
regenerates [docs/comparison.md](docs/comparison.md) from the result files
in `results/`. Of the 15 checks graded on every engine, all three pass all
15.

The differences are in the four checks that are *not* graded identically
everywhere, and they are the interesting part —
[docs/engines.md](docs/engines.md) is the file to read:

* `dns-mixed-answers` — given a hostname resolving to both a public and a
  private address, Pipelock and Squid refuse the name and **Smokescreen
  connects to the public address**, which docs/policy.md says it should
  not. The row is graded `record` on Smokescreen, so the exit code stays
  meaningful; the deviation is still measured and still printed.
* `connect-sni-mismatch` / `connect-raw-tunnel` — Pipelock refuses both;
  Smokescreen and Squid relay whatever the tunnel carries.
* `allowed-http` — Pipelock answers 200 where the others answer 301,
  because it **follows the destination's redirect** and hands back the
  target's response. Each hop is re-authorized against the allowlist:
  measured by narrowing the policy around a real cross-host redirect, with
  a control run that proves the redirect is followed at all.

Pipelock stays the default because it enforces inside CONNECT tunnels
(SNI verification, TLS-required) where Smokescreen and Squid do not.

Squid differs from the other two in where its policy lives: Pipelock and
Smokescreen block private destinations in engine code, while Squid's SSRF
floors are ordinary `dst` ACLs in `config/squid.conf`, ordered ahead of
the allowlist. That makes them reviewable — and `./run.py setup` checks
the required ranges and the rule order rather than trusting them.

Both backends are verified end to end, the DNS fixture included, by the
scripts in `scripts/` (docs/backends.md records which release each result
came from). The service is also measured to fail *closed*: killed
mid-load and restarted, no request for a denied host ever succeeded on
any engine.

One thing the architecture diagram implies is **not** true on any machine
yet: `project-sandbox` does not route sandboxes through this proxy. It
sets no `HTTP_PROXY` and filters egress with its own allowlist, so
exporting the variables by hand is currently what puts a client behind
this proxy. `scripts/verify_sandbox.py` checks that claim against the
installed tool rather than assuming it. See TODO.md.

## Important limitation

Without TLS interception (deliberately out of scope — see
[docs/security.md](docs/security.md)), destination filtering limits **where**
an agent can connect but cannot inspect encrypted request bodies. Data can
still be pushed to an already-allowlisted HTTPS service.
