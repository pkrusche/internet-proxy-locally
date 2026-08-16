# Pipelock vs Smokescreen — measured comparison

The default-backend decision (README §7, Phase 5) is empirical: run the
same suite against both engines and record the results here. Feature
tables alone do not decide it.

## How to reproduce a measurement row

```bash
./run.py --engine pipelock setup
./run.py --engine pipelock up --test-policy
./run.py check --full --json > results/pipelock-$(date +%Y%m%d).json

./run.py --engine smokescreen setup
./run.py --engine smokescreen up --test-policy
./run.py check --full --json > results/smokescreen-$(date +%Y%m%d).json

./run.py up   # back to the real policy
```

## Measured results

> Not yet measured — this sandbox has no container runtime. Fill in from
> the first run on a Docker host and on an Apple Silicon host with
> `container`. Keep the raw `--json` output alongside this table.

| Check | Pipelock | Smokescreen | Notes |
| --- | --- | --- | --- |
| allowed-http | _tbd_ | _tbd_ | |
| allowed-https | _tbd_ | _tbd_ | |
| blocked-host (CONNECT + GET) | _tbd_ | _tbd_ | |
| direct-ip-connect | _tbd_ | _tbd_ | |
| loopback / rfc1918 / link-local IPv4 | _tbd_ | _tbd_ | |
| metadata-endpoint | _tbd_ | _tbd_ | |
| loopback / private IPv6 | _tbd_ | _tbd_ | |
| dns-private-ipv4 (nip.io) | _tbd_ | _tbd_ | needs `--test-policy` |
| dns-private-ipv6 (sslip.io) | _tbd_ | _tbd_ | needs `--test-policy` |
| dns-rebinding (rbndr.us, recorded) | _tbd_ | _tbd_ | verify per-connection resolved-IP validation in engine logs |
| dns-mixed-answers (local fixture) | _tbd_ | _tbd_ | docs/security.md recipe |
| connect-sni-mismatch | expected: deny | recorded | decisive for the default choice |
| connect-raw-tunnel | expected: deny | recorded | decisive for the default choice |
| concurrency-sanity (recorded) | _tbd_ | _tbd_ | |
| crash → fail-closed (kill container, sandbox loses Internet) | _tbd_ | _tbd_ | manual |
| restart behavior (`./run.py restart`) | _tbd_ | _tbd_ | |

## Operational observations

Record here after real use: startup time, image size, log quality,
resource usage, upgrade friction, any config-surface surprises.

## Decision

Working hypothesis: **Pipelock default** for its explicit CONNECT/SNI
tunnel controls; **Smokescreen fallback** if operational simplicity and
maturity end up outweighing them. Confirm or overturn *only* after the
table above is filled in, then update `DEFAULT_ENGINE` in `run.py` and
record the reasons here.
