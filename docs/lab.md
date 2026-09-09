# The lab

`ipl-lab` runs extended checks for engines:
local DNS fixture, the full egress suite, and reports the comparison
in [findings.md](findings.md).

`config.toml` contains both operational and lab settings. Only `ipl-lab`
adds `[policy.test].allow` to `[policy].allow` and starts the DNS fixture.
Fixture names use the reserved `.test` domain; `ipl up` removes any running
fixture container.

```bash
ipl-lab setup     # all three engines + the DNS fixture image
ipl-lab up        # fixture, then an engine on the TEST policy
ipl-lab check     # the full adversarial suite
ipl-lab down      # remove both
ipl-lab measure   # all three engines end to end, then rewrite findings.md
```

`--engine` and `--backend` work as they do on `ipl`.

## The test policy

`config.toml` holds `[policy.test]` — domains added **on top of**
`[policy].allow` — and `[fixture]`, the DNS records. `ipl-lab up`
renders both through the shared policy templates into `lab/config/`:

| generated | from |
| --- | --- |
| `lab/config/{pipelock,smokescreen}.test.yaml`, `squid.test.conf` | `[policy]` + `[policy.test]` |
| `lab/config/dns-fixture.hosts` | `[fixture.records]` |

`ipl-lab up` regenerates these files before starting the fixture and engine.

The test policy should be a strict superset of the operational one. 
Extra domains: `*.nip.io` and `*.sslip.io` resolve to
caller-chosen addresses, and the fixture zones resolve in a controlled
manner (in an adversarial setting). 

Operational-only configs work with `ipl`;  `[policy.test]` and `[fixture]`
in `config.toml` are read by `ipl-lab`. 

## The DNS fixture

Public DNS cannot serve a mixed public+private answer set, or an 
answer that changes between lookups. `ipl-lab up` starts
a private DNS server, reads its address, and starts the engine with 
`--dns <that address>`. It publishes no host port.

**Mixed answers.** dnsmasq serves `lab/config/dns-fixture.hosts`: a control
name with one public address, and two names carrying one public and one
private address in both orderings, so an engine that validates only the
first answer is distinguished from one that validates all of them.

**Rebinding.** dnsmasq delegates `rebind.fixture.test` to a small stdlib
responder (`data/images/dnsfixture/rebind.py`), which answers the *first* lookup of
a name with a public address and every later one with the fixture's own
private address — where it also listens. Each name is probed twice, with a
pause between passes, so the second answer is actually handed out; two
probes in the same second are served from one lookup by any resolver cache
with second granularity, and the rebind never happens.

`dns-rebinding` then grades on whether anything connected to the trap. 

The fixture supervisor logs DNS answers and trap connections as `IPL-FIXTURE`
lines. Required settings come from the mounted `fixture.env`; missing settings
stop startup to avoid measuring an unintended fixture. The PTR probe uses a
public address claiming an allowlisted hostname. PTR lookups are recorded but
not required: rejecting IP literals before reverse DNS is valid enforcement.

## Reproducing the comparison

`ipl-check` runs `quick` allow/deny checks or the `full` suite, which adds
DNS/SSRF fixtures and CONNECT-abuse probes. 

```bash
ipl check                          # check connectivity quickly
ipl lab check --full               # full check / egress suite; needs lab mode
```

Grades are `pass` (expectation met), `fail` (violated), `record` (behavior
observed without a defined verdict), `skip` (missing prerequisite), and `error`
(check could not run). Recorded rows retain the observed allowed/denied behavior.

JSON results include timing, available per-attempt evidence, response headers,
denial causes, and engine logs. 

```bash
ipl-lab measure                    # ipl check --full for all three engines, then rewrite findings.md
ipl-lab measure --backend docker   # or pin the backend
ipl-lab report                     # rewrite from the committed results/
ipl-lab report --check             # CI: exit 1 if the tables are stale
```

`measure` drives, per engine, `up` on the test policy and `check --json`
into `results/<engine>.json`, and finishes with a `down` so no engine and
no fixture is left running on a test allowlist. The result files are
committed: without them the generated blocks of `findings.md` could not be
re-derived, only believed.

`report` rewrites only the regions of `findings.md` between
`<!-- BEGIN GENERATED <name> -->` and `<!-- END GENERATED <name> -->`.
