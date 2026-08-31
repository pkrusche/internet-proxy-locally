# TODO

Open work only. Implementation notes for what is already done live in
`docs/`.

## Simplification

Reviewed 2026-08-31 against `b38c90f`. Baseline: 211 unit tests pass in
~103s. Roughly 250 lines are removable with no behavior change; the items
are ordered by payoff. Nothing here is a bug — the two-lane design and the
generated-config invariants hold. What follows is where those invariants
are currently kept by *copying* rather than by construction, which is the
one place this repository does not follow its own stated principle.

### 1. The two lanes copy each other's plumbing (~120 lines)

`./lab.py` reuses `./run.py` for `down`, `start_engine` and
`egress_command`, but four things were copied instead of shared:

| duplicate | `run.py` | `lab.py` |
| --- | --- | --- |
| `cmd_policy` — render, validate, write-or-diff | `run.py:1136` | `lab.py:480` |
| `sync_*_policies` — validate, then write what changed | `run.py:734` | `lab.py:412` |
| `render_*_policies` — loop engines, render template | `run.py:671` | `lab.py:330` |
| `cmd_pin`, the apk-version branch | `run.py:1310` | `lab.py:591` |

The two `cmd_policy` bodies are identical except for the source label and
the order in which `stale` is computed — and that ordering difference is
itself the drift this section is about. Collapse each row into one helper
in `run.py`, parameterized on `(rendered, sync_fn, source_label, cli)`, and
have `lab.py` call it.

Then there is this, seven times over (`run.py:744`, `run.py:1147`,
`run.py:1201`, `run.py:1366`, `lab.py:418`, `lab.py:485`, `lab.py:544`):

```python
def fail_on(problems: list[str], message: str) -> None:
    for problem in problems:
        print(f"CONFIG ERROR: {problem}", file=sys.stderr)
    if problems:
        raise Fail(message)
```

### 2. Engine names hardcoded where `pin_kind` already exists

`ServiceSpec.pin_kind` (`run.py:145`) is the right abstraction — digest,
package or source — but `prepare_engine` (`run.py:1212`) and `cmd_pin`
(`run.py:1289`) still branch on `engine == "pipelock"`, and the helpers are
named after engines rather than after what they do. Rename to
`_setup_pulled_image` / `_setup_source_image` and dispatch purely on
`pin_kind`; a fourth engine then becomes a config-only change. Three
related pieces:

* `_setup_smokescreen` (`run.py:1242`) hardcodes
  `REPO_ROOT / "images" / "smokescreen"` while `_setup_package_image`
  (`run.py:1263`) uses `spec.image_context`. Use the property in both.
* `_setup_pipelock` (`run.py:1223`) has a "no digest yet, so pull one and
  record it" branch that duplicates `cmd_pin`'s pipelock path. Squid and
  Smokescreen both refuse and point at `pin` instead. Deleting it makes
  `setup` uniformly fail-closed (~15 lines). **This is a behavior change**
  — decide it deliberately.
* `[build] go_image` / `runtime_image` / `base_image` are three
  `ServiceSpec` fields mapped by hand to three uppercase build args. One
  generic `[build]` table rendered as `{KEY.upper(): value}` deletes the
  fields and the mapping.

### 3. `Backend` repeats the same JSON unwrap five times

`container_state` (`run.py:248`), `container_ip` (`:276`),
`published_ports` (`:311`), `image_digest` (`:427`) and `image_size`
(`:455`) each open with the same nine lines: run `inspect`, check the
return code, `json.loads` in a `try`, then
`entry = info[0] if isinstance(info, list) and info else info`. One
`_inspect_entry(*args) -> dict` cuts ~30 lines and removes the
inconsistency at `run.py:259`, where that copy lacks the `and info` and
`or {}` guards the other four have.

While in there: `Backend.image_size` (~28 lines parsing two runtime shapes)
exists for a single informational line in `scripts/verify_resilience.py:172`.
That is a lot of surface for a number that is explicitly reported rather
than graded.

### 4. `checks/egress.py`: parallel tables, triplicated fixture facts

* `TESTS` (`checks/egress.py:945`) and `CHECK_PURPOSE` (`:975`) are two
  tables keyed by the same nineteen names. One row per check — a small
  `Check` dataclass, or a six-tuple — removes the parallel dict *and* the
  test that exists only to catch orphans between them.
* The fixture constants are stated three times, each with a "keep in sync"
  comment and nothing enforcing it: `lab/fixtures.toml` (`ptr_address`,
  `ptr_claims`, `rebind_zone`, the `9.9.9.9` public half),
  `checks/egress.py:76-101`, and `lab/dnsfixture/rebind.py:38-50`.
  `tomllib` is stdlib, so `egress.py` can read `lab/fixtures.toml` when it
  is present without breaking its no-third-party rule, and `rebind.py` can
  take its values as Dockerfile ARGs. If that is too invasive for now, the
  cheap fix is a unit test asserting the three agree — today nothing does.
* `test_rfc1918` (`:578`) and `test_ipv6_private` (`:608`) are the same
  "deny every one of these targets" shape written twice.

### 5. Four different ways to import one module

`scripts/harness.py:28`, `scripts/report.py:51`, `tests/test_runpy.py:100`
and `tests/test_egress.py:24` each carry their own
`spec_from_file_location` shim; `lab.py:39` uses `sys.path.insert` plus a
plain `import run`. Everything runs under uv from the repository root, so
`checks/` and `scripts/` are already importable as namespace packages:
`import run`, `from checks import egress`, `from scripts import report`
would work everywhere and delete four loaders.

### 6. Small dead weight

* `_dedup` (`run.py:1124`): both call sites build a list of distinct
  container names plus `FIXTURE_CONTAINER`, so it can never dedup
  anything. Both also build that same list — one
  `owned_containers(include_fixture=True)` covers `start_engine` and
  `cmd_down`.
* `docs/findings.md` § "Corrections to earlier runs" (~34 lines) is
  changelog narrative that git already holds.
* README's "Findings, in ten lines" is a hand-maintained prose copy of the
  generated Summary and Decision in `docs/findings.md`. `scripts/report.py`
  already writes into marker blocks; either generate that block the same
  way or trim it to a pointer.

### 7. Test ergonomics

`uv run python -m unittest discover -s tests -t .` fails with "Start
directory is not importable" — `tests/` has no `__init__.py` — and nothing
in the README or `docs/` states the invocation that does work
(`uv run python -m unittest test_runpy test_lab test_egress test_scripts`).
Add `tests/__init__.py` and one line to `docs/lab.md`. The suite also leaks
a lot of subprocess stdout (report tables, the `Reporter` fixtures' `== t /
FAIL broken`) into the run.
