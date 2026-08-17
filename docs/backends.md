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
| build | `build --tag … --file … --build-arg … <ctx>` | same |
| image inspect | `image inspect <ref>` | same (JSON shape differs; both parsed) |

## Parity checklist

Every runtime-affecting feature must be tested or explicitly documented as
backend-specific.

| Feature | Docker (Linux/macOS) | Apple `container` (macOS 26+) |
| --- | --- | --- |
| `setup` | ☑ implemented, ☐ verified on hardware | ☑ verified |
| image pull / build | ☑ implemented | ☑ verified (Pipelock pull by digest; local Smokescreen build) |
| `up` | ☑ implemented, exercised via backend shim tests | ☑ verified, both engines |
| loopback port publication | `--publish 127.0.0.1:18080:…` | ☑ verified; if a future release drops `--publish ip:host:container`, do **not** substitute a broader binding — the endpoint must stay loopback-only |
| `status` / `logs` / `check` / `down` | ☑ implemented | ☑ verified (`check --full` on both engines) |

Apple `container` was verified on macOS 26.6.1 / arm64 on 2026-08-17; the
full adversarial suite ran against both engines there
(docs/comparison.md). Docker is installed on that host but has not been
exercised end to end — that is the open parity item (TODO.md).

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
```

After any upgrade: `./run.py up && ./run.py check --quick`, and
`check --full` (with `up --test-policy`) before relying on it.

Both engines must work on `amd64` and `arm64` (Apple Silicon): the
Pipelock upstream image is multi-arch; the Smokescreen image builds from
multi-arch Go/Alpine bases on whatever platform runs the build.
