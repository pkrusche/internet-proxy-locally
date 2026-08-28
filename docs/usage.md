# Usage

One CLI drives both container backends. `run.py` needs Python 3.11+ (it
imports `tomllib`) and refuses to run on anything older with a message
naming the interpreter it found. Its one dependency is Jinja2, used only
to render `config/*` from `config.toml` and imported lazily inside that
code path — so `down`, `status` and `logs` keep working on a bare
interpreter with no virtualenv, which is when you most want them.

```bash
uv sync    # once: creates .venv from pyproject.toml / uv.lock
```

```text
usage: run.py [--engine {pipelock,smokescreen,squid}] [--backend {docker,container}]
              {policy,setup,up,restart,down,status,logs,check,pin} ...
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

### `policy [--check]`

Renders `config.toml` into all six engine configs through `templates/*.j2`
and writes the ones that changed, naming each. `--check` instead prints a
unified diff for every stale file and exits 1 without writing — the form
for review and CI.

Either way the rendered text is validated first (the same
`validate_policy_file()` checks, plus the rule that each `.test` variant is
a strict superset of its real counterpart), so a bad `config.toml` fails
before it can overwrite a working policy. `setup`, `up` and `restart` run
this for you; the subcommand exists to review a `config.toml` edit without
a container runtime.

### `setup`

`--rebuild` forces a rebuild of a locally built image (Smokescreen,
Squid); `--all` prepares every engine.

Validates the Python version, detects available backends, verifies engine
prerequisites, pulls the pinned Pipelock image by digest, builds the
Smokescreen and Squid images when needed, and — after regenerating them
from `config.toml` — validates all three config files plus their
cross-engine allowlist sync. It never modifies system networking.

### `up [--test-policy]`

Regenerates `config/*` from `config.toml`, validates the policy, recreates
the container, publishes the stable endpoint, and runs a post-start health
check. Regeneration comes first so the file bind-mounted into the
container is always what `config.toml` says; a hand edit to `config/` is
overwritten rather than silently started. It refuses to start when:

* `config.toml` is malformed, or holds an entry that is not a bare
  hostname or a `*.` wildcard (nothing is written and nothing starts);

* the policy file is invalid or non-strict;
* the image is unpinned (no digest / source SHA / package version) or
  uses `latest`;
* the endpoint is occupied by an unknown process;
* the other engine's container is already running;
* the post-start health check fails.

On health-check failure the container is **left in place** with its last
logs printed, so the failure can be diagnosed; `./run.py down` removes it.

`--test-policy` mounts the engine's test policy (`config/*.test.yaml`,
`config/squid.test.conf`) instead of the real one, **and** starts the local
DNS fixture — a dnsmasq container serving `config/dns-fixture.hosts` — with
the engine's resolver pointed at it via `--dns`. See docs/policy.md and
docs/security.md. `up` prints a reminder to return to the normal policy; a
normal `./run.py up` removes the fixture along with the engine, so it can
never outlive the test run.

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
`>= 400` rather than a specific code is what lets one check serve every
engine: Pipelock and Squid deny with `403`, Smokescreen with `407`
(docs/engines.md).

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
emits machine-readable results — the input `scripts/report.py` generates
docs/comparison.md from.

`check` refuses to run when no engine is up, or when `--engine` names an
engine other than the running one — it will not silently test one engine's
expectations against another's container.

Outcome vocabulary: `pass` / `fail` (graded), `record` (behavior
documented, no pass/fail defined), `skip` (prerequisite missing, with
reason), `error` (the test itself could not run). Exit code is 1 if any
`fail` or `error` occurred — `record` and `skip` are not failures.

The `--full` DNS fixtures require `up --test-policy`; the suite
auto-detects this and skips them with an explanatory reason otherwise.
`dns-mixed-answers` and `dns-rebinding` additionally prove the fixture is
live before grading — a control probe, and the fixture's own record of the
lookups it answered — so that a missing or unreachable fixture skips the
row instead of turning into a pass it did not earn. `run.py check` passes
the fixture's container through with `--fixture-container` when it is
running; a standalone `checks/egress.py` invocation without that flag skips
`dns-rebinding`.

`--json` results are schema-versioned (`schema_version`). The envelope
records the conditions of the run — `engine`, `image`, `backend`,
`policy` (`test` or `real`, read back off the fixture rows rather than
declared), `host`, `generated_at`, `mode` and `exit_code` — so a result
file states what it measured without a table beside it. Per check, a row
may include: `cause` (best-effort denial classification), `observed`
(what the engine did — `allowed` or `denied` — for rows whose grade is
`record` and therefore says nothing about direction), `elapsed_ms`,
`attempts` (per-target evidence — e.g. what `dns-rebinding` and
`dns-private-ipv4`/`ipv6` actually resolved each fixture hostname to),
`headers` (full response headers on the allow-path checks), and
`engine_logs` (the running container's own log lines for that test's
window — `run.py check` wires `--backend-bin`/`--container` through
automatically; standalone `checks/egress.py` invocations omit them unless
those flags are passed).

### `checks/egress.py --diff A.json B.json`

Compares two prior `--json` runs (e.g. one per engine) and prints only
the checks whose `outcome`/`cause` diverge:

```bash
checks/egress.py --diff results/pipelock.json results/smokescreen.json
```

## The end-to-end scripts

`scripts/` holds the things the unit suite cannot do, because they need a
real container runtime. Each prints one named check per claim and exits
non-zero if any failed. All of them take `--port` so they can run on a
machine that already has a proxy on 18080 without taking it down.

| Script | What it settles |
| --- | --- |
| `scripts/report.py` | Regenerates docs/comparison.md from `results/*.json`. `--run` measures all three engines first (setup, `up --test-policy`, `check --full --json`, then `down`); `--check` reports drift and exits 1 without writing. |
| `scripts/verify_backend.py --backend B` | The whole lifecycle on a real backend, ending at the DNS fixture: the fixture's address is parsed out of *that* backend's `inspect` shape, `up` announced it, and the engine actually resolved through it — proved by the fixture-dependent checks producing verdicts instead of skipping. |
| `scripts/verify_loopback.py` | That the endpoint is bound to loopback and nothing else, from the runtime's own report of the binding and from the endpoint refusing every non-loopback address this host has. `--running` checks the proxy that is already up instead of replacing it. Re-run after a backend upgrade. |
| `scripts/upstream_fidelity.py` | Whether an engine forwards the request it was given or rewrites it, and whether it hands back the destination's own answer. This is what established that Pipelock follows redirects (docs/engines.md §6). `--redirect-authz` additionally settles whether a followed redirect's target is re-authorized, by narrowing the policy around a real cross-host redirect and running a control alongside it. |
| `scripts/verify_resilience.py` | That the service fails *closed*: with two request streams running, the container is killed and then restarted, and no request for a denied host may ever succeed. Also records startup time and image size. |
| `scripts/verify_sandbox.py` | Whether anything on this machine actually routes a sandbox through the endpoint. Reads it off the installed `project-sandbox` rather than assuming; `--run-sandbox` runs the in-sandbox assertions once the routing exists. |

### `down`

Removes only containers owned by this repository — every engine, plus the
DNS fixture. It never touches Agentgateway or `project-sandbox`
containers.

### `pin <service> [--ref REF]`

Records immutable pins in `services/*.toml`; needs network. Takes any
engine, or `dnsmasq` for the DNS fixture. See docs/backends.md for the
upgrade procedure.

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

# compare engines: measure all three and regenerate docs/comparison.md
scripts/report.py --run
```

## Local test suite

```bash
uv sync                                     # once
uv run python -m unittest discover -s tests
```

No network and no container runtime required: a fake backend shim records
the exact docker/`container` invocations, and a TLS-terminating mock proxy
exercises the egress suite end to end, including SNI-mismatch and
raw-tunnel classification in both strict and lenient modes.

## Logging and privacy

Proxy logs can reveal requested hostnames, full URLs for plaintext HTTP,
timestamps, and traffic volume. Smokescreen writes a structured (logrus)
access line per connection: client address, requested hostname, resolved
IP, decision and reason, timing. Squid writes its native access log to
the container's stdout — one line per request with the client address,
the decision tag (`TCP_DENIED/403`, `TCP_TUNNEL/200`) and the target —
and its cache log to stderr; no log files are kept inside the container
(`logfile_rotate 0`, no `cache_store_log`). Pipelock is left on its
default denial/access logging — its richer audit features (signed action receipts,
scan verdicts) stay off, since enabling them persists more than the
hostnames above; anything beyond stdout logs must be an explicit, reviewed
config change.

Retention is the container log stream only — logs are lost on
recreate/remove and nothing is shipped anywhere. No provider API keys
exist anywhere in this service, by design.
