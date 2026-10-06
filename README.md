# internet-proxy-locally

Scripts to run a local, containerized Internet filtering proxy for coding/agent
sandboxes. Default deny, hostname allowlist, SSRF protection, local
endpoint at `http://127.0.0.1:18080`.

> 🤖 Made with the help of AI.

As it wasn't clear to me which proxy is best for this, the scripts include
Dockerfiles to run and test + compare
[Pipelock](https://github.com/luckyPipewrench/pipelock) (default),
[Smokescreen](https://github.com/stripe/smokescreen),
[Squid](https://www.squid-cache.org/) or
[Iron](https://docs.iron.sh/).

Docker and Apple `container` are both supported for running the proxy.
Measurements & tests in the lab only run on Docker to simplify network
setup.

## Quick start

Clone, and run inside your local copy:

```bash
uv sync                 # once: create the environment uv run uses
uv run ipl setup        # validate prerequisites, build the pinned images
uv run ipl up           # start the proxy and health-check it
uv run ipl check        # confirm allow/deny behavior

export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080
curl https://github.com          # allowlisted → works
curl https://example.com         # not allowlisted → denied by the proxy
# ...
uv run ipl down         # remove proxy container
```

Requires Python 3.11+, [uv](https://docs.astral.sh/uv/), and Docker or Apple
`container`.

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
See [docs/policy.md](docs/policy.md).

## Commands

| | |
| --- | --- |
| `ipl setup` | validate prerequisites, build the pinned images |
| `ipl up` | (re)create the container and health-check it |
| `ipl status` | engine, backend, container state, image, live health |
| `ipl logs` | engine logs |
| `ipl check` | allow/deny behavior against the live proxy |
| `ipl restart` | render, then recreate the proxy |
| `ipl down` | remove this workspace's proxy at the selected endpoint |
| `ipl list` | list running IPL proxies across all workspaces on the selected backend |
| `ipl ca init/status/export/rotate` | manage the opt-in TLS-interception CA ([docs/tls-interception.md](docs/tls-interception.md)) |

`--engine pipelock|smokescreen|squid|iron` and `--backend docker|container`
override the defaults; `ipl --help` is the full reference.

## Multiple instances

Global `--ip` and `--port` options select the listening endpoint. Put them
before the subcommand:

```bash
uv run ipl --ip 127.0.0.1 --port 18080 up
uv run ipl --ip 127.0.0.2 --port 18080 up
uv run ipl --port 18081 --engine squid setup
uv run ipl --port 18081 --engine squid up
uv run ipl list
uv run ipl --port 18081 logs
uv run ipl --port 18081 down
```

`up`, `restart`, `down`, `status`, `logs`, and `check` target only the selected
endpoint in this workspace. Switching engines replaces only that endpoint's
proxy. Each IP/port pair gets a distinct container name; equivalent IPv6
spellings select the same instance. Different workspaces still cannot manage
each other's containers, and cannot claim the same engine/IP/port name.

Each CLI component overrides its corresponding component in `IPL_ENDPOINT`,
which otherwise defaults to `127.0.0.1:18080`. IPv6 literals are supported,
for example `--ip ::1`; an IPv6 environment endpoint can be `[::1]:18080`.
Non-loopback and wildcard addresses are allowed. Binding `0.0.0.0` or `::`
exposes the proxy on other interfaces; wildcard bindings can conflict with
specific addresses on the same port. Local checks and client hints use
loopback for wildcard bindings; remote clients use the host's reachable IP.

`list` ignores IP, port, and engine selectors and shows running operational,
lab, and legacy IPL proxies, their actual bind endpoints, container names,
workspace hashes, and roles. The current workspace is marked. It does not
check proxy health; use endpoint-specific `status` or `check` for that.

Instances share images, the source policy, and the workspace CA. Each instance
mounts a policy snapshot under `state/instances/`, so starting another instance
with a different TLS mode leaves existing configurations intact. Stop every
workspace-owned proxy on the selected backend before rotating the shared CA.
`ipl-lab` retains its single-instance workflow and loopback-only endpoint.

## Version pinning

For reproducibility and security versions should be pinned.

Every image is built from a Dockerfile in
`src/internet_proxy_locally/data/images/<name>/`, and every pin it depends
on — the base image, an apk version, an upstream commit SHA, Pipelock's
upstream manifest digest — is a literal in that file.

`images.py` holds one constant tag per image, which is what `up` runs and
what `setup` checks before deciding to build. To upgrade an engine: edit
its Dockerfile, bump the matching tag constant, commit, then `ipl setup`.

The unit suite asserts every `FROM` and every `apk add` is pinned and that
each tag still matches the pin its Dockerfile names.

## Choice of engine

**Pipelock is the default**, according to the [findings](docs/findings.md),
it has the most comprehensive blocking behaviour out of the box. To note though, the Squid
ruleset can likely be upgraded to be more secure, and Squid does have a
long history of operations. Our filtering configs using the other solutions
(smokescreen / iron proxy) could probably be improved also.

## Documentation

| | |
| --- | --- |
| [findings.md](docs/findings.md) | measured engine comparison and explanations |
| [policy.md](docs/policy.md) | the allowlist, the rules, how to change them |
| [security.md](docs/security.md) | threat model, non-goals, what it does *not* defend against |
| [lab.md](docs/lab.md) | the test policy, the DNS fixture, and how to reproduce the comparison |
| [tls-interception.md](docs/tls-interception.md) | opt-in TLS interception: the `ipl ca` lifecycle, per-engine notes, why Smokescreen is excluded |

Open work is tracked in [TODO.md](TODO.md).

### Coding agent backend traffic and TLS interception

Direct coding agent backend traffic (e.g. Codex) can fail through the intercepting proxy even
when `chatgpt.com` is allowlisted. Observed failures include:

- **WebSocket fallback with Squid.** The shipped configuration does not
  enable HTTP upgrades, so Squid drops the WebSocket upgrade header. Codex
  can fall back to streaming HTTPS (SSE).
- **Compressed requests blocked by Pipelock 3.3.0.** Codex sends POST bodies
  with `Content-Encoding: zstd`. Pipelock's request-body scanner rejects them
  with `compressed bodies cannot be scanned for secrets`, so HTTPS fallback
  can fail too. The log's generic suggestion to add a DLP suppression does
  not address this compression rejection.
- **Pipelock rate limits.** Logs showing `scanner: ratelimit` and
  `rate limit exceeded for chatgpt.com` explain an
  `HTTP CONNECT failed with status 429` error. This refusal happens before
  TLS or a WebSocket upgrade. Model traffic and the `codex_apps` MCP endpoint
  (`https://chatgpt.com/backend-api/ps/mcp`) share the destination; retries
  can add pressure to its rate limit. The MCP startup error alone does not
  identify which proxy check failed.

Using an agent gateway / bypassing the internet proxy for connections to the
LLM APIs is probably the best strategy.

See [TLS interception](docs/tls-interception.md),
[Squid's HTTP upgrade behavior](https://www.squid-cache.org/Doc/config/http_upgrade_request_protocols/),
and the [pinned Pipelock request-body scanner](https://github.com/luckyPipewrench/pipelock/blob/v3.3.0/internal/proxy/bodyscan.go#L541).
