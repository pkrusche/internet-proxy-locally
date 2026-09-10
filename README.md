# internet-proxy-locally

A small, local, containerized Internet filtering proxy for coding-agent
sandboxes. Default deny, hostname allowlist, SSRF protection, fail closed.

One stable endpoint — `http://127.0.0.1:18080` — backed by
[Pipelock](https://github.com/luckyPipewrench/pipelock) (default),
[Smokescreen](https://github.com/stripe/smokescreen),
[Squid](https://www.squid-cache.org/) or
[Iron](https://docs.iron.sh/). Docker and Apple `container` are
both supported for operational setups. The lab uses Docker for all fixtures
and measured proxies. No Docker Compose.

## Quick start

```bash
uv sync                 # once: create the environment uv run uses
uv run ipl setup        # validate prerequisites, build the pinned images
uv run ipl up           # start the proxy and health-check it
uv run ipl check        # confirm allow/deny behavior

export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080
curl https://github.com          # allowlisted → works
curl https://example.com         # not allowlisted → denied by the proxy
```

Requires Python 3.11+, [uv](https://docs.astral.sh/uv/), and Docker or Apple
`container`. Run from a workspace containing `config.toml`. Teardown is
`ipl down`.
`uv sync` installs this repository as a package and puts `ipl`, `ipl-lab`,
and `ipl-check` in the environment; `uv run ipl ...` picks up
the interpreter from `.python-version` and the dependencies from
`pyproject.toml`. There is no bare-interpreter path to keep
working, so nothing is imported lazily to preserve one.

The Python lives in `src/internet_proxy_locally/`, and the templates and
image build contexts ship inside it under `data/` — so the package can
render a policy and build an image without a checkout.
What stays at the repository root is what a person edits or the tool
generates: `config.toml`, `config/`, `lab/config/`, `results/`.

## The allowlist

`config.toml` at the repository root holds the allowlist, once:

```toml
[policy]
allow = ["github.com", "*.github.com", "pypi.org", ...]
```

`ipl` renders it into all four engine configs (`config/*.yaml`,
`config/squid.conf`) through `data/templates/`, and `setup` / `up` / `restart`
do that before starting anything — so the engines cannot express
different policies. Edit `config.toml`, run `ipl up`, commit both.
See
[docs/policy.md](docs/policy.md).

## Commands

| | |
| --- | --- |
| `ipl setup` | validate prerequisites, build the pinned images |
| `ipl up` | (re)create the container and health-check it |
| `ipl status` | engine, backend, container state, image, live health |
| `ipl logs` | engine logs |
| `ipl check` | allow/deny behavior against the live proxy |
| `ipl restart` | render, then recreate the proxy |
| `ipl down` | remove containers owned by this repository |
| `ipl ca init/status/export/rotate` | manage the opt-in TLS-interception CA ([docs/tls-interception.md](docs/tls-interception.md)) |

`--engine pipelock|smokescreen|squid|iron` and `--backend docker|container`
override the defaults; `ipl --help` is the full reference.

For Iron, run `uv run ipl --engine iron setup`, then
`uv run ipl --engine iron up`. It uses the same endpoint and allowlist.
TLS passes through by default; add `--tls-interception` to setup and up
to use the existing CA workflow. Iron's live measurements are pending;
see [docs/lab.md](docs/lab.md#reproducing-the-comparison).

## Pins

Every image is built from a Dockerfile in
`src/internet_proxy_locally/data/images/<name>/`, and every pin it depends
on — the base image, an apk version, an upstream commit SHA, Pipelock's
upstream manifest digest — is a literal in that file. Nothing resolves a
pin at run time and nothing writes one back, so what an image is made of
is whatever the last reviewed diff said.

`images.py` holds one constant tag per image, which is what `up` runs and
what `setup` checks before deciding to build. To upgrade an engine: edit
its Dockerfile, bump the matching tag constant, commit, then `ipl setup`.
The unit suite asserts every `FROM` and every `apk add` is pinned and that
each tag still matches the pin its Dockerfile names, so a bump that gets
only half done is a failing test rather than a stale image.

## Stable interface

The contract other tools may rely on: an HTTP proxy on
`http://127.0.0.1:18080`, loopback only, speaking `CONNECT` and plain HTTP,
answering a denied request with a 4xx and a stated reason. Which engine is
behind it is not part of the contract.

## Which engine, and why

**Pipelock remains the default**, with TLS and SNI checks inside CONNECT
tunnels enabled. Iron also checks TLS SNI in its passthrough mode; its
behavior in this integration still needs lab measurement. Squid is the
alternative when the policy itself has to be auditable — its SSRF floors
are ordinary `dst` ACLs in a file you can read, which `ipl setup` then
checks rather than trusts.

The measured engines, checks and evidence are in
[docs/findings.md](docs/findings.md), where the tables are generated from
the result files by `ipl-lab report` rather than written by hand. This
section deliberately does not restate them: a summary kept in step by
memory is how a README ends up describing a measurement nobody has taken
in a year.

## Documentation

| | |
| --- | --- |
| [findings.md](docs/findings.md) | measured engine comparison; Iron measurements pending |
| [policy.md](docs/policy.md) | the allowlist, the rules, how to change them |
| [security.md](docs/security.md) | threat model, fail-closed properties, non-goals, what it does *not* defend against |
| [lab.md](docs/lab.md) | the test policy, the DNS fixture, and how to reproduce the comparison |
| [tls-interception.md](docs/tls-interception.md) | opt-in TLS interception: the `ipl ca` lifecycle, per-engine notes, why Smokescreen is excluded |

Open work is tracked in [TODO.md](TODO.md).

## Important limitation

By default, destination filtering limits **where** an agent can connect
but cannot inspect encrypted request bodies: data can still be pushed to
an already-allowlisted HTTPS service. Pipelock, Squid and Iron support
opt-in TLS interception, which enables inspection but does not itself prohibit
uploads. It is off by default, and a real
change to the threat model when turned on (private-key custody, trust
distribution to every consuming sandbox) — see
[docs/tls-interception.md](docs/tls-interception.md) before enabling it.
Smokescreen cannot do this at all; see
[docs/security.md](docs/security.md).

Separately: `project-sandbox` does **not** currently route sandboxes through
this proxy. It sets no `HTTP_PROXY` and filters egress with its own
allowlist, so exporting the variables by hand is what puts a client behind
this proxy today.

Enable TLS interception per run with `ipl up --tls-interception` or
`ipl-lab up --tls-interception`; repeat the switch on `ipl restart`.
