# TODO

Open work. Implementation notes for what is already done live in `docs/`;
measured engine results live in [docs/comparison.md](docs/comparison.md).

---

## 1. Richer collection and output from `check`

**Priority: high.** This is the largest gap. The 2026-08-17 run
(docs/comparison.md) produced three results the suite could not explain on
its own, and in each case the missing information was something the
checker could have collected.

**Status: implemented at the tooling level** (`checks/egress.py`,
verified against `tests/mock_proxy.py`). The sandbox this was built in has
no network and no docker/`container` binary, so none of it has been
re-run against real engines yet — that re-run (needs §2's Docker
verification or a networked macOS host) is the remaining step before
docs/comparison.md can be refreshed. Notably, the rebinding cache-busting
scheme and the denial-cause text classifier are both unverified against
real `rbndr.us` and real engine wording; the engine-log-capture feature
(now full-log-diff based, not `--since` — see below) is the more reliable
attribution path until that re-run happens. Note also that `dns-rebinding`
stays `record`: the collected evidence makes the row *legible*, but
`rbndr.us` cannot make it graded (see below).

### What went wrong

* **`dns-rebinding` was inconclusive.** Pipelock reported
  `denied=0 established=6`, Smokescreen `denied=6 established=0`. Both are
  consistent with a cached DNS answer rather than any difference in
  rebinding defence, and the output gives no way to tell. The suite
  reports aggregate counts and nothing about *which IP was resolved*, so
  the reader is told to "verify engine logs" by hand.
* **A denial's reason is invisible.** Every deny check reports only a
  status line (`403` / `407`). There is no way to distinguish "rejected by
  hostname policy" from "rejected after resolving to a private IP" — which
  is precisely the distinction the DNS-fixture tests exist to prove.
* **`allowed-http` returned 200 on Pipelock and 301 on Smokescreen** and
  the suite records neither the response headers nor enough context to
  attribute the difference.

### What to add

* [x] **Per-attempt records instead of aggregates.** `dns-rebinding` now
  emits one `Attempt` per probe (attempt number, resolved IP as seen by
  the checker, proxy status, elapsed ms), not `denied=N established=M`.
* [x] **Resolve the target locally alongside each attempt** and include
  the answer in the record (`resolve_locally`, applied to `dns-rebinding`
  and `dns-private-ipv4`/`ipv6`).
* [x] **Cache-busting for the rebinding fixture.** Each attempt now uses a
  fresh `rbndr.us` hostname (varying public IP × loopback octet, see
  `_rebind_target`), so no attempt can be answered from a cache an earlier
  one warmed, and the detail line states whether the fixture varied for
  the checker or a caching resolver flattened it — which is what the
  2026-08-17 `6/0` results could not tell us. The check stays `record`,
  deliberately: `rbndr.us` answers every query with one of its two IPs at
  random, so the checker's lookup and the engine's are independent draws
  and neither outcome attributes to what the engine resolved. Grading an
  attempt against the checker's own resolution would have failed *both*
  measured engines most runs. Making the row conclusive needs the local
  DNS fixture in §3, not `rbndr.us`. **Unverified against the real
  fixture** (no network here) — confirm on the next real-engine run.
* [x] **Capture engine logs for the window of each test**, attached as
  `Result.engine_logs`. Implemented as a before/after full-log diff
  (`--backend-bin`/`--container`, wired automatically by `run.py check`)
  rather than `docker logs --since`, since Apple `container`'s support
  for `--since` isn't confirmed (docs/backends.md) and full-log-diff works
  identically on both backends.
* [x] **Classify denials by cause** (`classify_denial`) into
  `hostname-not-allowlisted` / `private-ip` / `metadata` / `sni-mismatch`
  / `non-tls-in-tunnel` / `timeout` / `unknown`. Best-effort text
  matching over the checker's own detail text; accuracy against real
  engines' exact wording is unverified — treat `engine_logs` as the more
  trustworthy attribution until confirmed.
* [x] **Record full response headers** for allow-path checks
  (`Result.headers`, `test_allowed_http`), and decode TLS records (type,
  version, length, alert level/description) instead of dumping `repr()`
  for the raw-tunnel check (`annotate_tls_bytes`).
* [x] **Timing per check** (`Result.elapsed_ms`, plus per-attempt).
* [x] **Richer `--json`**: `schema_version` field; `attempts`/`headers`/
  `engine_logs`/`cause`/`elapsed_ms` alongside the existing fields.
* [x] **A `--diff` mode**: `checks/egress.py --diff A.json B.json` prints
  only the rows whose `outcome`/`cause` differ (plus rows unique to one
  file).

### Acceptance

Re-running `check --full` against both engines should make every row in
docs/comparison.md self-explanatory — no row should need "verify engine
logs" or "unattributed" as its note. **Not yet confirmed** — needs a real
run (§2's Docker verification, or a networked host) against both engines;
the tooling above hasn't touched real engines or a real DNS fixture yet.

---

## 2. Backend verification

* [ ] Verify the **Docker** backend end to end:
      `./run.py --backend docker setup && … up && … check --full`.
      Docker is installed on the measurement host but was not exercised.
* [x] Apple `container` verified on macOS 26.6.1 / arm64 (both engines,
      build + run + full suite).
* [ ] Confirm Apple `container` honours `--publish ip:host:container`
      loopback binding on the installed release. If it does not, **do not**
      substitute a broader binding — the endpoint must stay loopback-only
      (docs/backends.md).

## 3. Remaining suite coverage

* [ ] `dns-mixed-answers` — currently an unconditional `skip`. Needs the
      local dnsmasq fixture; recipe in docs/security.md. An engine that
      silently picks "just the public answer" from a mixed answer set is a
      finding worth recording.
* [ ] Crash → fail-closed: kill the container mid-session and confirm the
      sandbox loses Internet rather than gaining unfiltered access.
* [ ] `./run.py restart` behavior under load.
* [ ] Record operational observations in docs/comparison.md: startup time,
      image size, log quality, resource usage, upgrade friction.

## 4. Default-engine decision

* [x] Both engines measured against the common suite (docs/comparison.md).
* [x] Pipelock confirmed as default (`DEFAULT_ENGINE` in `run.py`) on the
      strength of its CONNECT-tunnel controls.
* [ ] Revisit if the §3 DNS fixture makes rebinding conclusive and the
      engines then differ there. (§1's evidence makes the `rbndr.us` row
      readable, not gradable.)

## 5. Smaller items

* [ ] Attribute the `allowed-http` 200-vs-301 difference (docs/comparison.md
      finding 5) or confirm it is upstream/CDN variation.
* [ ] Consider surfacing Smokescreen's `407` denials more usefully to
      clients — some HTTP clients treat it as a credentials prompt and
      retry-loop instead of surfacing the block. Upstream behavior; may
      only be documentable.
* [ ] Re-validate Pipelock config keys against the pinned release's
      upstream configuration docs after every version bump — the keys in
      `config/pipelock.yaml` were taken from the docs current at pinning
      time, and this is enforced socially, not mechanically.
