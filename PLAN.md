# Implementation status

Tracks the phases from README §13. The initial implementation was written
in a network-isolated sandbox without a container runtime; items that
inherently need network or real container hardware are marked ⏳ with the
exact command to run.

## Phase 1 — Pipelock minimum viable service

- [x] Repository skeleton (README §1 layout).
- [x] Backend detection (Docker / Apple `container`, macOS preference, override).
- [x] Pipelock service definition (`services/pipelock.toml`).
- [x] Pipelock release pinned (`v3.0.0`); ⏳ digest: `./run.py pin pipelock` on a networked machine, then commit.
- [x] Strict allowlist config (`config/pipelock.yaml`).
- [x] Stable endpoint `127.0.0.1:18080` (env-independent, engine-independent).
- [x] `up` / `status` / `logs` / `down` (+ explicit `restart`), fail-closed semantics.
- [x] Quick allow/deny check (`./run.py check --quick`).
- [ ] ⏳ Verify on Docker: `./run.py setup && ./run.py up && ./run.py check --quick`.
- [ ] ⏳ Verify on Apple `container` (macOS 26+, Apple Silicon): same commands with `--backend container`; confirm loopback `--publish` support (docs/backends.md).

Deliverable check: `HTTPS_PROXY=http://127.0.0.1:18080 curl https://github.com`
works while a non-allowlisted host fails. ⏳ needs a container host.

## Phase 2 — Smokescreen comparison backend

- [x] Pinning mechanism for upstream source (`./run.py pin smokescreen`); ⏳ record the SHA on a networked machine.
- [x] Local multi-stage image (`images/smokescreen/Dockerfile`, unprivileged, license notice, pinned bases).
- [x] Equivalent allowlist (`config/smokescreen.yaml`, cross-checked against Pipelock's on every setup/up).
- [x] Same host endpoint and lifecycle interface (`--engine smokescreen`).
- [ ] ⏳ Verify Docker build + run.
- [ ] ⏳ Verify Apple `container` build + run.

## Phase 3 — Adversarial parity suite

- [x] Suite implemented (`checks/egress.py`): private IPv4/IPv6, metadata,
      DNS fixtures (nip.io/sslip.io), DNS rebinding (rbndr.us, recorded),
      SNI mismatch, raw CONNECT tunnel, IP-form CONNECT, concurrency sanity.
- [x] Test-policy configs so SSRF fixtures test IP floors, not hostname policy.
- [x] Suite verified against a policy-enforcing mock proxy (21 local tests green).
- [ ] ⏳ Run against both real engines; record in docs/comparison.md.
- [ ] Mixed-DNS fixture run (local dnsmasq recipe in docs/security.md).
- [ ] Crash/restart/fail-closed manual checks (docs/comparison.md table).

## Phase 4 — project-sandbox integration

- [ ] ⏳ Verify `--internet-proxy`, iptables bypass prevention, `NO_PROXY`
      for Agentgateway, independent failure of the two services
      (checklist in README §9).
- [ ] Link the repositories' READMEs once verified.

## Phase 5 — choose default

- [ ] Blocked on Phase 3 measurements (docs/comparison.md). Pipelock
      remains the working-hypothesis default (`DEFAULT_ENGINE` in run.py).

## Local test suite

```bash
python3 -m unittest discover -s tests
```

No network, no container runtime needed: a fake backend shim records the
exact docker/container invocations, and a TLS-terminating mock proxy
exercises the egress suite end to end (including SNI-mismatch and
raw-tunnel classification in both strict and lenient modes).
