# Usage

One CLI drives both container backends. `run.py` is stdlib-only and needs
Python 3.11+ (it imports `tomllib`). 

```text
usage: run.py [--engine {pipelock,smokescreen}] [--backend {docker,container}]
              {setup,up,restart,down,status,logs,check,pin} ...
```

## Lifecycle semantics

* `up` and `down` are explicit; nothing starts implicitly.
* `up` **recreates** the container rather than mutating a stopped one.
* `restart` is explicit teardown then `up`.
* No platform-specific restart policy is used anywhere — Apple `container`
  has no equivalent, and diverging would create different fail-closed
  semantics per backend (docs/backends.md).
* If the container dies, nothing listens on `127.0.0.1:18080`; the sandbox
  loses Internet rather than gaining unfiltered access.

## Commands

### `setup`

`--rebuild` forces a Smokescreen image rebuild; `--all` prepares both
engines.

Validates the Python version, detects available backends, verifies engine
prerequisites, pulls the pinned Pipelock image by digest, builds the
Smokescreen image when needed, and validates both config files plus their
cross-engine allowlist sync. It never modifies system networking.

### `up [--test-policy]`

Validates the policy, recreates the container, publishes the stable
endpoint, and runs a post-start health check. It refuses to start when:

* the policy file is invalid or non-strict;
* the image is unpinned (no digest / no source SHA) or uses `latest`;
* the endpoint is occupied by an unknown process;
* the other engine's container is already running;
* the post-start health check fails.

On health-check failure the container is **left in place** with its last
logs printed, so the failure can be diagnosed; `./run.py down` removes it.

`--test-policy` mounts `config/<engine>.test.yaml` instead of the real
policy — see docs/policy.md. `up` prints a reminder to return to the
normal policy.

### The post-start health check

`probe_proxy()` sends an absolute-form `GET` for
`http://ipl-health-probe.invalid/` — a reserved TLD, so it can never
resolve and can never be allowlisted — and grades the status line:

| Response | Verdict |
| --- | --- |
| socket error / no data | unhealthy |
| not an HTTP status line | unhealthy |
| status ≥ 400 | **healthy** — the proxy is enforcing |
| 2xx / 3xx | **unhealthy** — the proxy forwarded what it should block |

A success response is deliberately treated as a failure. Grading on
`>= 400` rather than a specific code is what lets one check serve both
engines: Pipelock denies with `403`, Smokescreen with `407`
(docs/comparison.md).

### `status`

Prints backend, endpoint, and per-engine container state, image and pin,
marking the active engine. When an engine is running it also runs the
health probe above and exits non-zero if it fails.

### `logs [--follow]`

Engine logs through the selected runtime. Defaults to the running engine;
pass `--engine` to read a stopped container's logs. Logs live only in the
container log stream and are lost on recreate/remove.

### `check [--quick|--full] [--json]`

Runs `checks/egress.py` against the running engine through the stable
endpoint. `--quick` (default) covers ordinary allow/deny behavior;
`--full` adds the SSRF/DNS fixtures and CONNECT-abuse tests. `--json`
emits machine-readable results for docs/comparison.md.

`check` refuses to run when no engine is up, or when `--engine` names an
engine other than the running one — it will not silently test one engine's
expectations against another's container.

Outcome vocabulary: `pass` / `fail` (graded), `record` (behavior
documented, no pass/fail defined), `skip` (prerequisite missing, with
reason), `error` (the test itself could not run). Exit code is 1 if any
`fail` or `error` occurred — `record` and `skip` are not failures.

The `--full` DNS fixtures require `up --test-policy`; the suite
auto-detects this and skips them with an explanatory reason otherwise.

`--json` results are schema-versioned (`schema_version`) and, per check,
may include: `cause` (best-effort denial classification), `elapsed_ms`,
`attempts` (per-target evidence — e.g. what `dns-rebinding` and
`dns-private-ipv4`/`ipv6` actually resolved each fixture hostname to),
`headers` (full response headers on the allow-path checks), and
`engine_logs` (the running container's own log lines for that test's
window — `run.py check` wires `--backend-bin`/`--container` through
automatically; standalone `checks/egress.py` invocations omit them unless
those flags are passed).

### `checks/egress.py --diff A.json B.json`

Compares two prior `--json` runs (e.g. one per engine) and prints only
the checks whose `outcome`/`cause` diverge, instead of transcribing the
comparison table in docs/comparison.md by hand:

```bash
checks/egress.py --diff results/pipelock-20260817.json results/smokescreen-20260817.json
```

### `down`

Removes only containers owned by this repository (both engines). It never
touches Agentgateway or `project-sandbox` containers.

### `pin <engine> [--ref REF]`

Records immutable pins in `services/*.toml`; needs network. See
docs/backends.md for the upgrade procedure.

## Typical sessions

```bash
# first run
./run.py setup
./run.py up
./run.py check --quick

# full adversarial suite
./run.py up --test-policy
./run.py check --full
./run.py up                      # back to the real policy

# compare engines
./run.py --engine smokescreen setup
./run.py --engine smokescreen up --test-policy
./run.py check --full --json > results/smokescreen-$(date +%Y%m%d).json
```

## Local test suite

```bash
python3 -m unittest discover -s tests
```

No network and no container runtime required: a fake backend shim records
the exact docker/`container` invocations, and a TLS-terminating mock proxy
exercises the egress suite end to end, including SNI-mismatch and
raw-tunnel classification in both strict and lenient modes.

## Logging and privacy

Proxy logs can reveal requested hostnames, full URLs for plaintext HTTP,
timestamps, and traffic volume. Smokescreen writes a structured (logrus)
access line per connection: client address, requested hostname, resolved
IP, decision and reason, timing. Pipelock is left on its default
denial/access logging — its richer audit features (signed action receipts,
scan verdicts) stay off, since enabling them persists more than the
hostnames above; anything beyond stdout logs must be an explicit, reviewed
config change.

Retention is the container log stream only — logs are lost on
recreate/remove and nothing is shipped anywhere. No provider API keys
exist anywhere in this service, by design.
