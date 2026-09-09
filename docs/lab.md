# The lab

The other lane. `ipl` starts a proxy on the reviewed allowlist and
knows nothing about any of this. `ipl-lab` owns everything that exists to
**measure** an engine rather than run one: the adversarial test policy, the
local DNS fixture, the full egress suite, and the three-engine comparison
in [findings.md](findings.md).

Nothing here can reach an operational run. `ipl` never reads
`data/lab/fixtures.toml`, the fixture names live under `.test` (RFC 6761, can
never resolve publicly), and any `ipl up` removes the fixture
container.

```bash
ipl-lab setup     # all three engines + the DNS fixture image
ipl-lab up        # fixture, then an engine on the TEST policy
ipl-lab check     # the full adversarial suite
ipl-lab down      # remove both
ipl-lab measure   # all three engines end to end, then rewrite findings.md
```

`--engine` and `--backend` work as they do on `ipl`.

## The test policy

`data/lab/fixtures.toml` holds `[policy.test]` — domains added **on top of**
`config.toml`'s allowlist — and `[fixture]`, the DNS records. `ipl-lab
policy` renders both, with the same templates and the same Jinja
environment `ipl policy` uses, into `lab/config/`:

| generated | from |
| --- | --- |
| `lab/config/{pipelock,smokescreen}.test.yaml`, `squid.test.conf` | `config.toml` + `[policy.test]` |
| `lab/config/dns-fixture.hosts` | `[fixture.records]` |

`ipl-lab policy --check` reports drift as a diff without writing.

The test policy is a **strict superset** of the operational one by
construction. The rendering tests assert that every operational and test
entry reaches every engine config: a `.test` run that measured a *narrower*
policy than the one that ships would produce verdicts that do not transfer.

Why the extra domains exist: `*.nip.io` and `*.sslip.io` resolve to
caller-chosen addresses, and the fixture zones resolve to whatever the
fixture says. Allowlisting them is the whole point — it makes a denial
attributable to the IP-layer SSRF floors rather than to ordinary hostname
policy. **Never put an operational domain in `[policy.test]`.**

## The fixture records

One edit must not half-land, so `load_lab_config()` refuses to render when
the two halves disagree. It rejects a record the test policy does not
allowlist (the fixture would be denied by name and grade nothing), a
`.test` entry in `[policy.test]` with no record behind it (NXDOMAIN, so the
check silently skips), a fixture name `config.toml` also allows, a control
record with more than one address or a private one, a mixed record that is
not one public plus one private, a record set that does not cover both
orderings, and a `ptr_address` that collides with a record address.

## The DNS fixture

Public DNS cannot serve either fixture the suite needs — a mixed
public+private answer set, or an answer that changes between lookups — so
both run against a container this repository builds. `ipl-lab up` starts
it, reads its address, and starts the engine with `--dns <that address>`.
It publishes no host port.

**Mixed answers.** dnsmasq serves `lab/config/dns-fixture.hosts`: a control
name with one public address, and two names carrying one public and one
private address in both orderings, so an engine that validates only the
first answer is distinguished from one that validates all of them. The
control must establish before anything is graded; without it a denial could
not be attributed to mixed-answer handling, and the row skips.

**Rebinding.** dnsmasq delegates `rebind.fixture.test` to a small stdlib
responder (`data/images/dnsfixture/rebind.py`), which answers the *first* lookup of
a name with a public address and every later one with the fixture's own
private address — where it also listens. Each name is probed twice, with a
pause between passes, so the second answer is actually handed out; two
probes in the same second are served from one lookup by any resolver cache
with second granularity, and the rebind never happens.

That listener is the point. `dns-rebinding` grades on one thing: whether
anything connected to the trap. "Did the engine reach a private address"
stops being an inference from counts — which is what made the old
`rbndr.us` row ungradable — and becomes an observation by the thing that
would have received the connection. A repeat probe that succeeds while the
trap stays silent is *not* a failure: it means the engine reused an address
it had already validated, which is a legitimate defence. The engines split
on exactly this ([findings.md](findings.md) §3).

Two things to know before changing it:

* **A bind-mounted `/etc/hosts` does not work**, though it looks like it
  should. Duplicate names in a hosts file collapse to a single address —
  musl's `getent hosts` returns the first, Squid's own parser keeps the
  last — so the engine never sees more than one address and the check
  silently measures which record survived. dnsmasq's `--addn-hosts`
  aggregates them and returns both.
* **`--host-record=name,addr1,addr2` does not give two IPv4 answers.** The
  second slot is the IPv6 address; a second IPv4 there replaces the first
  rather than adding to it (measured: the query returns only `10.0.0.1`).

## Reproducing the comparison

```bash
ipl-lab measure                    # all three engines, then rewrite findings.md
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
`<!-- BEGIN GENERATED <name> -->` and `<!-- END GENERATED <name> -->`. The
narrative around them is copied through byte for byte, and a missing or
duplicated marker is fatal rather than silently skipped.

To compare two runs directly rather than re-reading the tables:

```bash
uv run ipl-check --diff results/pipelock.json results/smokescreen.json
```

## Operational smoke check

`scripts/e2e-smoke.sh --backend docker` exercises the real `ipl` lifecycle.
It starts the operational proxy, confirms its TCP endpoint is listening,
runs `ipl down`, and confirms the engine container is gone. Pass `--engine`
to select an engine. The lab needs no separate lifecycle smoke check because
`ipl-lab check` exercises the running engine and fixture directly.

## Running the unit suite

```bash
uv run python -m unittest discover -s tests -t .      # everything
uv run python -m unittest tests.test_runpy            # one module
uv run python -m unittest discover -s tests -t . -k rebind   # by name
```

Both `-s tests` (where to look) and `-t .` (the import root) are needed.
The code under test resolves through the installed package rather than
through `sys.path`, but `tests` itself still has to be importable as a
package: without `tests/__init__.py` unittest refuses with "Start directory
is not importable", and the modules get imported twice under two names,
which silently runs every inherited CLI test a second time.

The tests do not copy the code into a temporary directory. They copy the
*data* — `IPL_DATA_ROOT` for the templates and image build contexts,
`IPL_ROOT` for the workspace `up` regenerates `config/` in — so what runs
is always the checkout's code against an isolated repository.

The operational smoke check is **not** part of this suite: it needs a real
container runtime, while the unit suite uses a fake backend and mock proxy.

## Backend parity

Both backends use the same `setup`, image build, `up`,
`status`/`logs`/`check`/`down`, and DNS fixture paths. The fixture container's
address is read from `inspect`, which Docker reports under `NetworkSettings`
and Apple `container` under `status.networks[]` as a CIDR.

## Upgrading the fixture

The dnsmasq and python3 apk versions are literals in
`data/images/dnsfixture/Dockerfile`. Edit them, bump `DNSFIXTURE_IMAGE` in
`images.py` to the new dnsmasq version, commit, then `ipl-lab setup`.
Engine pins work the same way (README, "Pins").

What the fixture *serves* is not in the image at all: `[fixture]` in
`data/lab/fixtures.toml` is rendered into `lab/config/dns-fixture.hosts`
and `lab/config/fixture.env`, both bind-mounted read-only, so an edit
there takes effect on the next `ipl-lab up` rather than on the next
rebuild.
