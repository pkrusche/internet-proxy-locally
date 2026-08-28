# Container backends

Docker and Apple `container` are first-class; there is no Compose and no
backend-specific security semantics. `run.py` isolates every CLI
difference in one `Backend` class.

## Selection

* macOS: Apple `container` when installed, otherwise Docker;
* elsewhere: Docker, otherwise Apple `container` (if it ever exists there);
* explicit override: `./run.py --backend docker …` / `--backend container …`.

## CLI mapping

| Operation | docker | Apple `container` |
| --- | --- | --- |
| start | `run --detach --name … --publish 127.0.0.1:18080:<port> --volume <cfg>:<mount>:ro <image> <args>` | same |
| state | `inspect <name>` → `[{"State":{"Status":…}}]` | `inspect <name>` → `[{"status":…}]` (both parsed) |
| remove | `rm -f <name>` | `stop <name>` then `rm <name>` |
| logs | `logs [--follow] <name>` | same |
| pull | `pull <ref>` | `image pull <ref>` |
| run once (`pin squid`/`pin dnsmasq`) | `run --rm <image> <cmd>` | same |
| container address (DNS fixture) | `inspect` → `NetworkSettings.IPAddress` | `inspect` → `status.networks[].ipv4Address` as CIDR (both parsed) |
| resolver override | `run --dns <ip>` | same |
| build | `build --tag … --file … --build-arg … <ctx>` | same |
| image inspect | `image inspect <ref>` | same (JSON shape differs; both parsed) |
| published port (loopback check) | `inspect` → `HostConfig.PortBindings[].HostIp` | `inspect` → `configuration.publishedPorts[].hostAddress` (both parsed) |

## Parity checklist

Every runtime-affecting feature must be tested or explicitly documented as
backend-specific. The three end-to-end scripts under `scripts/` are what
fills this table in; each prints a named check per claim, so a row here is
a pasted result rather than a recollection:

```bash
scripts/verify_backend.py --backend docker --engine squid   # lifecycle + DNS fixture
scripts/verify_loopback.py                                  # every installed backend
scripts/verify_loopback.py --running                        # ... or the proxy that is up now
scripts/report.py --run --backend docker                    # the full engine matrix
```

Pass `--port 18081` to any of them to leave a proxy already serving 18080
alone.

| Feature | Docker | Apple `container` |
| --- | --- | --- |
| `setup` | ☑ verified (all three) | ☑ verified (all three) |
| image pull / build | ☑ verified (Pipelock pull by digest; local Smokescreen, Squid and fixture builds) | ☑ verified (same) |
| `up` | ☑ verified, all three engines | ☑ verified, all three engines |
| loopback port publication | ☑ verified (`scripts/verify_loopback.py`) | ☑ verified (`scripts/verify_loopback.py`) |
| `status` / `logs` / `check` / `down` | ☑ verified (`check --full` on all three) | ☑ verified (`check --full` on all three) |
| `pin` | ☑ implemented | ☑ verified (`pin squid` resolves the apk version from the base image) |
| DNS fixture (`up --test-policy`) | ☑ verified (`scripts/verify_backend.py`: fixture started, address read from `NetworkSettings`, `--dns` honoured, all fixture checks graded) | ☑ verified (address read from `status.networks[]`, `--dns` honoured, all fixture checks graded) |

Recorded runs:

| When | Backend and release | What |
| --- | --- | --- |
| 2026-08-17 | Apple `container`, macOS 26.6.1 / arm64 | Pipelock and Smokescreen, end to end |
| 2026-08-19 | Docker | Pipelock and Smokescreen, end to end |
| 2026-08-25 | Apple `container` | Squid, and the DNS fixture on all three engines |
| 2026-08-28 | Docker 29.7.2 (build a7dcaa6) | `scripts/verify_backend.py --engine squid`: 13/13, including the fixture chain; `scripts/verify_loopback.py`: 5/5; `scripts/report.py --run`: all three engines |
| 2026-08-28 | Apple `container` CLI 1.2.0 (commit 6e65319) | `scripts/verify_loopback.py --running`: 5/5 — `--publish ip:host:container` still honoured on this release |

**Re-run `scripts/verify_loopback.py` after every backend upgrade.** The
endpoint being loopback-only is one `--publish` argument, and a release
that stopped honouring the address half would widen it to every interface
with no error and no visible change in `run.py`'s output. If a release
fails it, **do not substitute a broader binding** — the endpoint must stay
loopback-only, and a backend that cannot express that is one this
repository cannot use.

The DNS fixture is the one place where a real backend difference is
load-bearing: `up --test-policy` has to read the fixture container's
address out of `inspect`, and the two CLIs report it in different shapes.
Both are now exercised against a real runtime, not only unit-tested —
`scripts/verify_backend.py` asserts the whole chain, ending at "the
fixture-dependent checks produced verdicts", which they can only do if the
engine actually resolved through the address it was handed.

The fake-backend tests in `tests/test_runpy.py` pin down the exact CLI
invocations either backend receives, without needing a runtime.

If Apple `container` lacks an exact Docker feature, prefer the common
lower-level behavior over divergent semantics — e.g. no restart policies
are used anywhere because Apple `container` has no equivalent.

## Pinning and upgrades

Pins live in `services/*.toml` and are ordinary reviewable changes:

```bash
# Pipelock: bump tag in services/pipelock.toml, then re-resolve the digest
./run.py pin pipelock            # pulls the tag, records the immutable digest
./run.py setup                   # pulls by digest, validates configs

# Smokescreen: re-pin the source commit and rebuild
./run.py pin smokescreen         # records upstream HEAD's full SHA
./run.py pin smokescreen --ref v1.2.3   # or a specific tag/branch
./run.py --engine smokescreen setup --rebuild

# Squid: re-pin the apk version and rebuild
./run.py pin squid               # asks the pinned base image what it would install
./run.py pin squid --ref 6.13-r0 # or a specific apk version
./run.py --engine squid setup --rebuild

# DNS fixture (test-only): same mechanism
./run.py pin dnsmasq
./run.py setup                   # rebuilds it whenever the pin moves
```

The three pins are different kinds of thing because the three upstreams
publish different things: an OCI image digest (Pipelock), a source commit
(Smokescreen), and a distribution package version (Squid). All three are
recorded in `services/*.toml`, all three are ordinary reviewable diffs,
and `up` refuses to start without one.

Bumping Squid's `base_image` and its `package_version` are separate
decisions, and the second is constrained by the first: Alpine carries one
squid version per release branch, so `pin squid` reports what *that* base
image would install. If a base-image bump moves squid, `setup` fails at
`apk add` with the pinned version rather than quietly installing another.

After any upgrade: `./run.py up && ./run.py check --quick`, and
`check --full` (with `up --test-policy`) before relying on it.

Re-validate the Pipelock configuration keys against the new release's
upstream configuration docs on every version bump. The keys in
`config/pipelock.yaml` were taken from the docs current at pinning time,
and an upstream rename would be accepted silently — a key Pipelock no
longer reads is not an error, it is a control that stopped applying. This
is enforced socially, not mechanically.

All three engines must work on `amd64` and `arm64` (Apple Silicon): the
Pipelock upstream image is multi-arch; the Smokescreen and Squid images
build from multi-arch Go/Alpine bases on whatever platform runs the
build.
