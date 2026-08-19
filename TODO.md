# TODO

Open work. Implementation notes for what is already done live in `docs/`;
measured engine results live in [docs/comparison.md](docs/comparison.md).

---

## 1. Richer collection and output from `check`

**Priority: high.** This is the largest gap. The 2026-08-17 run
(docs/comparison.md) produced three results the suite could not explain on
its own, and in each case the missing information was something the
checker could have collected.

**Status: done and verified against both real engines** on 2026-08-19
(Docker backend, macOS; docs/comparison.md). Every row on both engines now
carries an attributed cause — zero `unknown` — and `--diff` between the two
runs prints only genuine divergences.

The re-run corrected three things the offline implementation got wrong:

* **The classifier keyed on the destination, not the reason.** Pipelock
  reports `domain not in allowlist: 127.0.0.1`, so patterns matching bare
  `127.0.0.1`/`fd00`/`fe80`/`169.254.169.254` read the *target* and
  mislabelled plain allowlist denials as `private-ip`/`metadata`.
  `forbidden` was likewise matching every 403. Both are gone; patterns
  now match stated reasons only, and Smokescreen's wording
  (`default rule policy used`, `denied by rule 'Deny: Private Range'`) is
  covered.
* **Two causes were missing.** `dns-failure` (NXDOMAIN / resolve failure —
  not a policy verdict at all) and `unparseable-destination` (Smokescreen
  rejecting `[::1]:80` before policy). Without them, six NXDOMAINs read as
  six policy denials.
* **Aggregate cause was computed over concatenated text**, so a mixed set
  reported whichever bucket came first in the taxonomy
  (`dns-private-ipv4` read as `metadata` when three of four attempts were
  `private-ip`). Attempts are classified individually now and combined.

`dns-rebinding` stays `record`. `rbndr.us` no longer resolves at all, so
the row is six `dns-failure`s on both engines — legible, but not a
measurement. Only the local fixture in §3 can make it graded.

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
  `hostname-not-allowlisted` / `private-ip` / `metadata` / `dns-failure` /
  `unparseable-destination` / `sni-mismatch` / `non-tls-in-tunnel` /
  `timeout` / `unknown`. Verified against both engines' real wording on
  2026-08-19 (zero `unknown`); the exact strings are pinned in
  `tests/test_egress.py::ClassifyDenialRealWordingTest`. Patterns match
  stated reasons only — never an address the engine echoes back, and
  never a reason word the checker itself wrote.
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

**Met (2026-08-19).** Every row in docs/comparison.md is self-explanatory;
no row needs "verify engine logs" or "unattributed". The two notes that
remained are resolved rather than deferred: finding 5 (200 vs 301) is
attributed to the upstream tier by the captured headers, and finding 3
(rebinding) states plainly that the fixture is unreachable instead of
implying a result.

The evidence also caught a bug it was not looking for: `dns-private-ipv6`
used `--1.sslip.io`, an invalid IDNA label that both engines rejected by
name, so the IPv6-loopback SSRF case had never actually run while still
scoring `pass` (docs/comparison.md finding 6). Fixed to `0--1.sslip.io`.

---

## 2. Backend verification

* [x] Verified the **Docker** backend end to end on 2026-08-19 (Docker
      29.7.2, both engines, setup + up + `check --full`). Found and fixed a
      backend-specific race: Docker accepts connections on the published
      port before the engine listens behind it, so the single post-start
      probe failed `up` on a healthy proxy with `non-HTTP response: ''`.
      `probe_proxy()` now separates not-ready-yet (retry until the
      deadline) from a real verdict (never retried). Apple `container`
      does not accept early, which is why this never showed there.
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

* [x] Attributed the `allowed-http` 200-vs-301 difference: response
      headers show Smokescreen answered at the Fastly edge (`Server:
      Varnish`, `Location: https://pypi.org/`) and Pipelock at pypi.org's
      origin (`Server: gunicorn`). CDN variation, not a proxy feature.
      One residual: confirm Pipelock does not normalize the upstream
      request, since `200` over plain HTTP from a Fastly-fronted host is
      unusual (docs/comparison.md finding 5).
* [ ] Consider surfacing Smokescreen's `407` denials more usefully to
      clients — some HTTP clients treat it as a credentials prompt and
      retry-loop instead of surfacing the block. Upstream behavior; may
      only be documentable.
* [ ] Guard the Python version explicitly. `run.py` documents "Python
      3.11+" but only fails when `import tomllib` raises, so on a host
      whose `python3` is older (macOS Command Line Tools ships 3.9)
      `./run.py` dies with a bare `ModuleNotFoundError` traceback and no
      hint. The same applies to running the tests. A version check ahead
      of the stdlib imports, printing the interpreter found and what is
      required, would turn a confusing traceback into one line.

* [ ] Re-validate Pipelock config keys against the pinned release's
      upstream configuration docs after every version bump — the keys in
      `config/pipelock.yaml` were taken from the docs current at pinning
      time, and this is enforced socially, not mechanically.
