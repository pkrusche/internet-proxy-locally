# internet-proxy-locally

A small, local, containerized Internet filtering proxy for coding-agent
sandboxes. Default deny, hostname allowlist, SSRF protection, fail closed.

One stable endpoint — `http://127.0.0.1:18080` — backed by
[Pipelock](https://github.com/luckyPipewrench/pipelock) (default),
[Smokescreen](https://github.com/stripe/smokescreen) or
[Squid](https://www.squid-cache.org/). Docker and Apple `container` are
both first-class. No Docker Compose.

## Quick start

```bash
uv sync                 # once: create the environment uv run uses
./run.py setup          # validate prerequisites, pull/build pinned images
./run.py up             # start the proxy and health-check it
./run.py check          # confirm allow/deny behavior

export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080
curl https://github.com          # allowlisted → works
curl https://example.com         # not allowlisted → denied by the proxy
```

Requires [uv](https://docs.astral.sh/uv/) and Docker or Apple `container`.
Every entry point is run through uv — that is what the shebangs do, so
`./run.py ...` works directly and picks up the interpreter from
`.python-version` and the dependencies (Jinja2, PyYAML) from
`pyproject.toml`. There is no bare-interpreter path to keep working, so
nothing is imported lazily to preserve one.

## The allowlist

`config.toml` at the repository root holds the allowlist, once:

```toml
[policy]
allow = ["github.com", "*.github.com", "pypi.org", ...]
```

`./run.py` renders it into all three engine configs (`config/*.yaml`,
`config/squid.conf`) through `templates/`, and `setup` / `up` / `restart`
do that before starting anything — so the three engines cannot express
different policies. Edit `config.toml`, run `./run.py up`, commit both.
`./run.py policy --check` reports drift without writing. See
[docs/policy.md](docs/policy.md).

## Commands

| | |
| --- | --- |
| `./run.py setup` | validate prerequisites, pull/build pinned images |
| `./run.py up` | (re)create the container and health-check it |
| `./run.py status` | engine, backend, container state, pins, live health |
| `./run.py logs` | engine logs |
| `./run.py check` | allow/deny behavior against the live proxy |
| `./run.py restart` | explicit teardown then up |
| `./run.py down` | remove containers owned by this repository |
| `./run.py policy` | render `config/*` from `config.toml` (`--check` for drift) |
| `./run.py pin` | record immutable image/source pins |

`--engine pipelock|smokescreen|squid` and `--backend docker|container`
override the defaults; `./run.py --help` is the full reference.

To upgrade an engine: `./run.py pin <engine>` (needs network), review the
change to `services/<engine>.toml`, commit it, then `./run.py setup`.

## Stable interface

The contract other tools may rely on: an HTTP proxy on
`http://127.0.0.1:18080`, loopback only, speaking `CONNECT` and plain HTTP,
answering a denied request with a 4xx and a stated reason. Which engine is
behind it is not part of the contract.

## Which engine, and why

**Pipelock is the default: it is the only engine that enforces inside the
CONNECT tunnel.** Squid is the alternative when the policy itself has to be
auditable — its SSRF floors are ordinary `dst` ACLs in a file you can read,
which `./run.py setup` then checks rather than trusts.

Every engine, every check and every number behind that is in
[docs/findings.md](docs/findings.md), where the tables are generated from
the result files by `./lab.py report` rather than written by hand. This
section deliberately does not restate them: a summary kept in step by
memory is how a README ends up describing a measurement nobody has taken
in a year.

## Documentation

| | |
| --- | --- |
| [findings.md](docs/findings.md) | Pipelock vs Smokescreen vs Squid: what was measured, what it means, why Pipelock |
| [policy.md](docs/policy.md) | the allowlist, the rules, how to change them |
| [security.md](docs/security.md) | threat model, fail-closed properties, non-goals, what it does *not* defend against |
| [lab.md](docs/lab.md) | the test policy, the DNS fixture, and how to reproduce the comparison |

Open work is tracked in [TODO.md](TODO.md).

## Important limitation

Without TLS interception (deliberately out of scope — see
[docs/security.md](docs/security.md)), destination filtering limits **where**
an agent can connect but cannot inspect encrypted request bodies. Data can
still be pushed to an already-allowlisted HTTPS service.

Separately: `project-sandbox` does **not** currently route sandboxes through
this proxy. It sets no `HTTP_PROXY` and filters egress with its own
allowlist, so exporting the variables by hand is what puts a client behind
this proxy today. `scripts/verify_sandbox.py` checks that against the
installed tool rather than assuming it.
