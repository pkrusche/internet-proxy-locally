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

## Parity checklist

Every runtime-affecting feature must be tested or explicitly documented as
backend-specific.

| Feature | Docker (Linux/macOS) | Apple `container` (macOS 26+) |
| --- | --- | --- |
| `setup` | ☑ verified (Pipelock, Smokescreen) | ☑ verified (all three) |
| image pull / build | ☑ verified | ☑ verified (Pipelock pull by digest; local Smokescreen and Squid builds) |
| `up` | ☑ verified (Pipelock, Smokescreen) | ☑ verified, all three engines |
| loopback port publication | `--publish 127.0.0.1:18080:…` | ☑ verified; if a future release drops `--publish ip:host:container`, do **not** substitute a broader binding — the endpoint must stay loopback-only |
| `status` / `logs` / `check` / `down` | ☑ verified (Pipelock, Smokescreen) | ☑ verified (`check --full` on all three) |
| `pin` | ☑ implemented | ☑ verified (`pin squid` resolves the apk version from the base image) |
| DNS fixture (`up --test-policy`) | ☐ **unverified** — the `NetworkSettings` parsing is unit-tested only | ☑ verified (fixture started, address read, `--dns` honoured, `dns-mixed-answers` graded on all three engines) |

Apple `container` was verified on macOS 26.6.1 / arm64: Pipelock and
Smokescreen on 2026-08-17, Squid on 2026-08-25 (docs/comparison.md).
Docker was exercised end to end on 2026-08-19 for Pipelock and
Smokescreen. **Squid and the DNS fixture have not been run on Docker.**
Nothing in Squid's setup is backend-specific (an ordinary build plus one
read-only bind mount). The fixture is the one place where a real backend
difference is load-bearing: `up --test-policy` has to read the fixture
container's address out of `inspect`, and the two CLIs report it in
different shapes. Both shapes are parsed and unit-tested, but only the
Apple path has met a real runtime (TODO.md).

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

All three engines must work on `amd64` and `arm64` (Apple Silicon): the
Pipelock upstream image is multi-arch; the Smokescreen and Squid images
build from multi-arch Go/Alpine bases on whatever platform runs the
build.
