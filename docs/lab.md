# The lab

`ipl-lab` runs extended checks for engines:
local DNS fixture, the full egress suite, and reports the comparison
in [findings.md](findings.md). The entire lab lane uses Docker, including
the fixture and all measured proxies. Apple `container` remains supported
for operational `ipl` setups. The lab tests proxy policy behavior, not runtime
isolation differences.

`config.toml` contains both operational and lab settings. Only `ipl-lab`
adds `[policy.test].allow` to `[policy].allow` and starts the DNS fixture.
Fixture names use the reserved `.test` domain; `ipl up` removes any running
fixture container.

```bash
ipl-lab setup     # all four engines + the DNS fixture image
ipl-lab up        # fixture, then an engine on the TEST policy
ipl-lab check     # the full adversarial suite
ipl-lab down      # remove both
ipl-lab measure   # both TLS modes, then rewrite findings.md
```

`--engine` selects the proxy. `--backend docker` is optional and is the only
lab backend; `--backend container` is rejected before starting anything.
Use a Docker version supporting multiple `--network` attachments (25+).

## The test policy

`config.toml` holds `[policy.test]` — domains added **on top of**
`[policy].allow` — and `[fixture]`, the DNS records. `ipl-lab up`
renders both through the shared policy templates into `lab/config/`:

| generated | from |
| --- | --- |
| `lab/config/{pipelock,smokescreen,iron}.test.yaml`, `squid.test.conf` | `[policy]` + `[policy.test]` |
| `lab/config/dns-fixture.hosts` | `[fixture.records]` |

`ipl-lab up` regenerates these files before starting the fixture and engine.

The test policy should be a strict superset of the operational one. 
Extra domains: `*.nip.io` and `*.sslip.io` resolve to
caller-chosen addresses, and the fixture zones resolve in a controlled
manner (in an adversarial setting). 

Operational-only configs work with `ipl`;  `[policy.test]` and `[fixture]`
in `config.toml` are read by `ipl-lab`. 

## The DNS fixture

The fixture runs DNS, a controlled HTTPS origin, and a private connection
trap. Docker attaches it and the proxy to the managed private bridge
`internet-proxy-fixture-private` (`172.30.203.0/24`) and to the
managed internal network `internet-proxy-fixture-public` (`11.203.0.0/24`).
The HTTPS origin binds `11.203.0.2:443` on that internal network; the trap
binds port 443 on the fixture's separate private bridge address. No fixture
port is published, no extra Linux capability is granted, and no host route
is installed. The internal subnet models a public destination for the proxy's
IP classifier; traffic to that origin stays on the local Docker network.
The private bridge supplies the default route for Internet probes. Both networks
are user-defined, as Docker rejects combining the built-in `bridge` with a
user-defined network at startup. See [Docker networking](https://docs.docker.com/engine/network/).
This shadows that small public-numbered subnet while the lab is running.

The addresses in `[fixture.records]` specify public/private roles. At startup,
the fixture substitutes its controlled origin address for the nominal public
address and its trap address for private entries, preserving record order.
It no longer connects to Quad9 or another external TLS server for these
checks. Other probes (for example, allowed pypi.org) still use the Internet.

**TLS.** Each fixture startup creates a separate seven-day CA and origin
certificate under gitignored `state/fixture-tls/`. The certificate covers
all fixture records and `*.rebind.fixture.test`. The CA is name-constrained
to `.test`, and its signing key is discarded after issuance. Only the origin's
leaf key is mounted into the fixture. Lab engines receive the public CA:
Squid adds it with `tls_outgoing_options cafile=...`; Go-based engines receive
`SSL_CERT_FILE` while retaining the system certificate directory. Peer and
hostname verification remain enabled. The operational interception CA is
independent, and operational runs receive none of this lab trust.

**Mixed answers.** dnsmasq serves the generated hosts file: a public-only
control, then public/private mixtures in both orders. A successful TLS/HTTP
control is required. Traffic through either a mixed-name tunnel or to the
private trap fails the check; a transport error cannot silently become a pass.

**Rebinding.** dnsmasq delegates `rebind.fixture.test` to the Python responder.
A fresh name resolves first to the controlled origin, then to the private
trap. The checker repeats probes after a 1.5-second gap. Lab Squid sets
`negative_dns_ttl 1 seconds`: despite its name, that directive also sets the
minimum positive cache lifetime, whose default is one minute. This is a
lab-only timing adjustment, not a claim that production uses that cache
setting. [Squid's directive documentation](https://www.squid-cache.org/Doc/config/negative_dns_ttl/)
explains the positive-cache floor.

The fixture logs origin requests, DNS answers, and trap connections as
`IPL-FIXTURE` lines. Startup waits for the origin and trap listeners and a
successful DNS control before the proxy starts. Missing network, TLS, or
DNS prerequisites stop startup instead of silently using an external origin.
Rebinding remains inconclusive unless a repeat DNS lookup was actually
observed; a connection to the private trap is a failure.

The PTR probe still uses a separate public address claiming an allowlisted
hostname. Rejecting literals before performing reverse DNS is valid enforcement.

`ipl-lab down` removes the Docker proxies, fixture, and both owned networks.
Operational `ipl --backend docker up` also removes stale lab networks after
removing its containers. Apple operational commands do not contact Docker.
Network ownership labels are checked before reuse or removal.

After updating from the old fixtures, rebuild with `uv run ipl-lab setup`.
The fixture image tag is now `2.91-r1-build3`, so setup cannot reuse the old
image. Then run `uv run ipl-lab measure` to replace the
historical results with Docker measurements.

## Reproducing the comparison

`ipl-check` runs `quick` allow/deny checks or the `full` suite, which adds
DNS/SSRF fixtures and CONNECT-abuse probes. 

```bash
ipl check                          # check connectivity quickly
ipl-lab check                      # full check / egress suite; needs lab mode
```

Grades are `pass` (expectation met), `fail` (violated), `record` (behavior
observed without a defined verdict), `skip` (missing prerequisite), and `error`
(check could not run). Historical recorded rows retain the observed allowed/denied behavior.
Concurrency sanity now passes when all ten simultaneous CONNECTs establish
and fails if any do not.

Checks exit 1 only for `error` outcomes; `pass` and `fail` grades are findings
reported in the summary. The checker's optional `--strict` flag also treats
skipped checks as execution errors. JSON `exit_code` matches the process status.
Historical result files retain the exit codes recorded when they were measured.

CONNECT deny probes require an active TLS/HTTP exchange after the CONNECT
acknowledgment. Explicit refusals pass; timeouts, resets, or ambiguous TLS/HTTP
failures remain `error` rather than proving access or denial. DNS and PTR
checks preserve that uncertainty. See
[tls-interception.md](tls-interception.md#late-denials-and-how-the-suite-grades-them).

JSON results include timing, available per-attempt evidence, response headers,
denial causes, and engine logs. 

```bash
ipl-lab measure                    # both TLS modes for all engines, then rewrite findings.md
ipl-lab --backend docker measure   # Docker is also the default
ipl-lab report                     # rewrite from the committed results/
ipl-lab report --check             # CI: exit 1 if the tables are stale
```

`measure` runs each engine with TLS interception off, then on where supported.
Pipelock, Squid and Iron run twice; Smokescreen runs once and is marked **off only**.
The comparison has one column per proxy: matching verdicts appear once, while
differences show **off** and **on**, including changes in attributed denial cause.
Per-check details retain the evidence from each mode.

All seven runs are saved together in `results/benchmark.json` only after the
batch completes; an interrupted batch leaves the previous results intact.
A final `down` removes the engine and fixture. `measure` has no TLS mode flag;
it always benchmarks all supported scenarios.
Commit the bundle and generated findings together. `report` prefers the bundle,
and still reads historical `results/<engine>.json` files if no bundle exists;
it never combines an incomplete bundle with older results.

Iron measurements are pending. The existing bundle and generated findings
retain the earlier three-engine measurements. Until a complete four-engine
batch is recorded, `ipl-lab report --check` rejects the bundle for missing
Iron results; this is not a successful Iron verification. On a Docker host,
run `uv run ipl ca init`, then `uv run ipl-lab measure` and
`uv run ipl-lab report --check`. Retain errors and failed policy checks as
evidence rather than reclassifying them to make the comparison pass.

`report` rewrites only the regions of `findings.md` between
`<!-- BEGIN GENERATED <name> -->` and `<!-- END GENERATED <name> -->`.
