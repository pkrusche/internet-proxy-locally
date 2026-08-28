#!/usr/bin/env python3
"""Generate docs/comparison.md from `checks/egress.py --json` result files.

docs/comparison.md used to be written by hand from suite output, which made
it a transcription: every number in it was a claim about a run nobody could
re-derive from the repository. This script makes the file a *rendering* of
the result files in `results/`, the same way config/ is a rendering of
config.toml — so a stale table is a diff rather than a belief.

    scripts/report.py --run          # measure all three engines, then write
    scripts/report.py                # write from the existing results/
    scripts/report.py --check        # report drift as a diff, exit 1, write nothing

`--run` drives ./run.py for each engine (setup, `up --test-policy`,
`check --full --json`) and needs a container runtime; the other two modes
need nothing but the JSON.

What is *not* generated — why an engine behaves the way it does, what the
differences mean, and which engine to choose — lives in docs/engines.md and
is written by a person. This file only reports what was measured.

Stdlib only; Python 3.11+.
"""

from __future__ import annotations

import argparse
import difflib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS = REPO_ROOT / "results"
DEFAULT_OUT = REPO_ROOT / "docs" / "comparison.md"
ANALYSIS_DOC = "docs/engines.md"

# The engines, in the order the report presents them: the default first.
ENGINES = ("pipelock", "smokescreen", "squid")
LABELS = {"pipelock": "Pipelock", "smokescreen": "Smokescreen", "squid": "Squid"}


def load_egress():
    spec = importlib.util.spec_from_file_location(
        "egress_report", REPO_ROOT / "checks" / "egress.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


egress = load_egress()


class Fail(Exception):
    """Fatal, user-facing error."""


# ---------------------------------------------------------------------------
# Reading result files
# ---------------------------------------------------------------------------


def result_path(results_dir: Path, engine: str) -> Path:
    """`results/<engine>.json`, or the newest `results/<engine>-*.json`.

    The dated form is what docs/engines.md's reproduce recipe writes, so
    both are accepted rather than making the recipe wrong.
    """
    exact = results_dir / f"{engine}.json"
    if exact.is_file():
        return exact
    dated = sorted(results_dir.glob(f"{engine}-*.json"))
    if dated:
        return dated[-1]
    raise Fail(f"no results for {engine}: expected {exact} or "
               f"{results_dir / (engine + '-<date>.json')}.\n"
               "Run `scripts/report.py --run` (needs a container runtime), or "
               "`./run.py --engine {engine} up --test-policy && "
               "./run.py check --full --json > results/{engine}.json`.")


def load_runs(results_dir: Path, engines: "tuple[str, ...]") -> dict[str, dict]:
    runs: dict[str, dict] = {}
    for engine in engines:
        path = result_path(results_dir, engine)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise Fail(f"{path}: cannot read result file: {exc}") from exc
        version = data.get("schema_version")
        if version != egress.SCHEMA_VERSION:
            raise Fail(
                f"{path}: schema_version {version}, but this checker writes "
                f"{egress.SCHEMA_VERSION}. Re-run the suite for {engine}; an older "
                "file does not carry the conditions this report states.")
        if data.get("engine") != engine:
            raise Fail(f"{path}: holds results for {data.get('engine')!r}, not {engine!r}")
        if data.get("mode") != "full":
            raise Fail(f"{path}: is a `{data.get('mode')}` run. The comparison is "
                       "generated from `check --full`; a quick run has no fixture rows "
                       "and would report them as missing rather than as skipped.")
        runs[engine] = data
        runs[engine]["_path"] = path
    return runs


def rows_of(run: dict) -> dict[str, dict]:
    return {row["name"]: row for row in run.get("results", [])}


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def verdict(row: dict | None) -> str:
    """One cell: the outcome, plus the cause the engine gave for it."""
    if row is None:
        return "—"
    text = row["outcome"].upper()
    if row["outcome"] == "record" and row.get("observed"):
        text += f" ({row['observed']})"
    if row.get("cause"):
        text += f" [{row['cause']}]"
    return text


def counts(run: dict) -> str:
    tally: dict[str, int] = {}
    for row in run["results"]:
        tally[row["outcome"]] = tally.get(row["outcome"], 0) + 1
    order = ["pass", "fail", "record", "skip", "error"]
    parts = [f"{tally[name]} {name}" for name in order if tally.get(name)]
    return ", ".join(parts)


def graded_names(runs: dict[str, dict]) -> list[str]:
    """Checks graded `pass`/`fail` on *every* engine.

    The pass counts are not comparable on their own: a row graded `record`
    on one engine has left the pool there, so a lower count can mean either
    weaker behavior or a different expectation. This is the pool where the
    number means the same thing everywhere.
    """
    names = []
    for name, _, _, _, _ in egress.TESTS:
        rows = [rows_of(run).get(name) for run in runs.values()]
        if all(row is not None and row["expectation"] in ("allow", "deny")
               for row in rows):
            names.append(name)
    return names


def behavior(row: dict) -> str:
    """What the engine *did*, with the grade taken back out.

    A grade is a comparison against an expectation, and the expectations
    are not the same on every engine — so `PASS` on one row and `RECORD` on
    another can describe identical behavior, and `PASS` on two rows can
    describe opposite behavior. Reading the two apart is the difference
    between "Smokescreen behaves differently here" and "Smokescreen is
    graded differently here".
    """
    if row.get("observed"):
        return row["observed"]
    if row["outcome"] in ("pass", "fail") and row["expectation"] in ("allow", "deny"):
        wanted = "denied" if row["expectation"] == "deny" else "allowed"
        opposite = "allowed" if wanted == "denied" else "denied"
        return wanted if row["outcome"] == "pass" else opposite
    return row["outcome"]


def divergences(runs: dict[str, dict], names: "list[str]") -> list[tuple[str, dict]]:
    """Checks where the engines did not all report the same verdict.

    Grouped by the rendered verdict — outcome, observed behavior and stated
    cause together: two engines that both denied for the same stated reason
    agree, and two that denied for different reasons do not. The cause is
    where most of the interesting differences live.
    """
    diverging: list[tuple[str, dict]] = []
    for name in names:
        groups: dict[str, list[str]] = {}
        for engine, run in runs.items():
            row = rows_of(run).get(name)
            if row is None:
                continue
            groups.setdefault(verdict(row), []).append(engine)
        if len(groups) > 1:
            diverging.append((name, groups))
    return diverging


def behavior_differs(runs: dict[str, dict], name: str) -> bool:
    rows = [rows_of(run).get(name) for run in runs.values()]
    return len({behavior(row) for row in rows if row is not None}) > 1


def _describe(groups: dict) -> str:
    """`Pipelock/Smokescreen PASS [allowlist]; Squid PASS [private-ip]`."""
    return "; ".join(f"{'/'.join(LABELS[m] for m in members)} {label}"
                     for label, members in groups.items())


def conditions_table(runs: dict[str, dict]) -> list[str]:
    lines = ["| | " + " | ".join(LABELS[e] for e in runs) + " |",
             "| --- |" + " --- |" * len(runs)]
    fields = [
        ("Measured", lambda r: r.get("generated_at") or "?"),
        ("Backend", lambda r: r.get("backend") or "?"),
        ("Host", lambda r: r.get("host") or "?"),
        ("Image", lambda r: f"`{r['image']}`" if r.get("image") else "?"),
        ("Policy", lambda r: {"test": "test (`up --test-policy`)",
                              "real": "real", "unknown": "?"}.get(r.get("policy"), "?")),
        ("Endpoint", lambda r: f"`{r.get('proxy', '?')}`"),
        ("Result", counts),
        ("Exit code", lambda r: str(r.get("exit_code", "?"))),
    ]
    for label, get in fields:
        lines.append(f"| {label} | " + " | ".join(get(runs[e]) for e in runs) + " |")
    return lines


def render(runs: dict[str, dict], results_dir: Path) -> str:
    engines = list(runs)
    out: list[str] = []
    add = out.append

    add("# Engine comparison — measured results")
    add("")
    add("GENERATED FILE — do not edit.")
    add("")
    add(f"Rendered by `scripts/report.py` from the `{results_dir.name}/` result files "
        "listed below, which are the JSON output of `./run.py check --full --json`. "
        "Re-measure and rewrite it with `scripts/report.py --run`; "
        "`scripts/report.py --check` reports drift without writing.")
    add("")
    add(f"Everything this file does *not* say — why an engine behaves this way, what "
        f"each difference costs, and which engine to choose — is in "
        f"[{ANALYSIS_DOC}]({Path(ANALYSIS_DOC).name}), which is written by hand.")
    add("")

    add("## Conditions")
    add("")
    out += conditions_table(runs)
    add("")
    add("Source files: " + ", ".join(
        f"`{runs[e]['_path'].relative_to(REPO_ROOT)}`" for e in engines) + ".")
    add("")

    graded = graded_names(runs)
    add("## Summary")
    add("")
    total = len(rows_of(runs[engines[0]]))
    ungraded = [name for name, _, _, _, _ in egress.TESTS if name not in graded]
    add(f"{len(graded)} of the {total} checks are graded `pass`/`fail` on every "
        "engine. In that common pool:")
    add("")
    for engine in engines:
        rows = rows_of(runs[engine])
        failed = [n for n in graded if rows[n]["outcome"] != "pass"]
        state = "passes all of them" if not failed else \
            "does not pass " + ", ".join(f"`{n}` ({rows[n]['outcome']})" for n in failed)
        add(f"* **{LABELS[engine]}** {state}.")
    add("")
    if ungraded:
        add("**Passing that pool is not the same as behaving identically**, and the "
            f"{len(ungraded)} check(s) it leaves out are where the engines differ: "
            + ", ".join(f"[`{name}`](#{name})" for name in ungraded) + ". Each is "
            "graded `record` on at least one engine, which takes it out of any pass "
            "count — a `record` grade means no verdict is defined there, never that "
            "the behavior was the same. What each engine actually did is below.")
        add("")

    diverging = divergences(runs, [name for name, _, _, _, _ in egress.TESTS])
    # Two very different kinds of disagreement, kept apart because the
    # counts read as alarming when they are pooled: one engine behaving
    # differently, and three engines behaving identically while naming
    # different rules for it.
    behavioral = [(name, groups) for name, groups in diverging
                  if behavior_differs(runs, name)]
    attribution = [(name, groups) for name, groups in diverging
                   if not behavior_differs(runs, name)]

    if behavioral:
        add(f"**Different behavior** on {len(behavioral)} check(s) — one engine "
            "allowed what another refused:")
        add("")
        for name, groups in behavioral:
            add(f"* [`{name}`](#{name}) — " + _describe(groups))
        add("")
    else:
        add("**No engine behaved differently from another on any check**: every "
            "outcome above is the same across the three.")
        add("")
    if attribution:
        add(f"**Same behavior, different stated reason** on {len(attribution)} "
            "check(s). These are not behavioral differences — the request was "
            "refused either way — but they say which rule did the refusing, which "
            "is what decides whether a row is evidence of the thing it is named "
            "after:")
        add("")
        for name, groups in attribution:
            add(f"* [`{name}`](#{name}) — " + _describe(groups))
        add("")

    add("## Matrix")
    add("")
    add("Bracketed values are the **attributed cause**: what the engine said it was "
        "rejecting, not what the check is named after. A blank one means nothing was "
        "denied, so there is no reason to attribute.")
    add("")
    add("| Check | Group | Expectation | " + " | ".join(LABELS[e] for e in engines) + " |")
    add("| --- | --- | --- |" + " --- |" * len(engines))
    for name, group, _, _, _ in egress.TESTS:
        cells = []
        expectations = set()
        for engine in engines:
            row = rows_of(runs[engine]).get(name)
            cells.append(verdict(row))
            if row:
                expectations.add(row["expectation"])
        expectation = "/".join(sorted(expectations)) if expectations else "—"
        add(f"| [{name}](#{name}) | {group} | {expectation} | " + " | ".join(cells) + " |")
    add("")
    add("Where the expectation column shows two values, the check is graded "
        "differently per engine (`ENGINE_EXPECTATIONS` in `checks/egress.py` says why).")
    add("")

    add("## Every check, and what each engine did")
    add("")
    for name, group, _, _, _ in egress.TESTS:
        add(f"### {name}")
        add("")
        purpose = egress.check_purpose(name)
        if purpose:
            add(purpose)
            add("")
        for engine in engines:
            row = rows_of(runs[engine]).get(name)
            if row is None:
                add(f"* **{LABELS[engine]}** — not present in this run.")
                continue
            timing = f", {row['elapsed_ms']:.0f}ms" if row.get("elapsed_ms") else ""
            attempts = (f", {len(row['attempts'])} probes" if row.get("attempts") else "")
            add(f"* **{LABELS[engine]}** — {verdict(row)} "
                f"(expectation: {row['expectation']}{timing}{attempts})  ")
            add(f"  {row['detail']}")
        add("")

    add("---")
    add("")
    add(f"Analysis, decisions and the corrections behind these numbers: "
        f"[{ANALYSIS_DOC}]({Path(ANALYSIS_DOC).name}).")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# --run: measure first
# ---------------------------------------------------------------------------


def measure(engines: "tuple[str, ...]", results_dir: Path,
            backend: str | None) -> None:
    """Drive ./run.py through the full matrix, one engine at a time.

    Every engine publishes the same endpoint, so this is necessarily
    sequential, and each `up` removes whatever the last one left. The final
    `down` matters: `up --test-policy` starts a DNS fixture that must never
    outlive the run.
    """
    results_dir.mkdir(parents=True, exist_ok=True)
    run_py = [sys.executable, str(REPO_ROOT / "run.py")]
    common = (["--backend", backend] if backend else [])
    try:
        for engine in engines:
            print(f"=== {engine}: setup", flush=True)
            _run(run_py + common + ["--engine", engine, "setup"])
            print(f"=== {engine}: up --test-policy", flush=True)
            _run(run_py + common + ["--engine", engine, "up", "--test-policy"])
            print(f"=== {engine}: check --full --json", flush=True)
            proc = subprocess.run(run_py + common + ["check", "--full", "--json"],
                                  capture_output=True, text=True)
            # A failing check is data, not an error: the suite exits 1 when
            # a graded row failed, and that run is exactly what the report
            # has to show. Only unparseable output is a problem.
            try:
                json.loads(proc.stdout)
            except json.JSONDecodeError as exc:
                raise Fail(f"{engine}: `check --full --json` produced no result "
                           f"document ({exc}).\n{proc.stderr.strip()}") from exc
            path = results_dir / f"{engine}.json"
            path.write_text(proc.stdout, encoding="utf-8")
            print(f"=== {engine}: wrote {path.relative_to(REPO_ROOT)} "
                  f"(exit {proc.returncode})", flush=True)
    finally:
        # Back to no engine and no fixture, whatever happened above.
        subprocess.run(run_py + common + ["down"], check=False)


def _run(cmd: list[str]) -> None:
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        raise Fail(f"`{' '.join(cmd)}` failed with exit {proc.returncode}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", action="store_true",
                        help="measure every engine first (needs a container runtime)")
    parser.add_argument("--check", action="store_true",
                        help="report drift as a diff and exit 1 instead of writing")
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS,
                        help=f"directory of result files (default: {DEFAULT_RESULTS.name}/)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help=f"file to write (default: {DEFAULT_OUT.relative_to(REPO_ROOT)})")
    parser.add_argument("--engines", default=",".join(ENGINES),
                        help="comma-separated engines to report on")
    parser.add_argument("--backend", choices=("docker", "container"), default=None,
                        help="container backend for --run (default: run.py's own choice)")
    opts = parser.parse_args(argv)

    engines = tuple(name.strip() for name in opts.engines.split(",") if name.strip())
    unknown = [name for name in engines if name not in ENGINES]
    if unknown:
        parser.error(f"unknown engine(s): {', '.join(unknown)}")

    try:
        if opts.run:
            if opts.check:
                parser.error("--run writes new results; it cannot be combined with --check")
            measure(engines, opts.results, opts.backend)
        runs = load_runs(opts.results, engines)
        body = render(runs, opts.results)
    except Fail as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    current = opts.out.read_text(encoding="utf-8") if opts.out.is_file() else ""
    if opts.check:
        if current == body:
            print(f"{opts.out.relative_to(REPO_ROOT)}: up to date with "
                  f"{opts.results.name}/")
            return 0
        sys.stdout.writelines(difflib.unified_diff(
            current.splitlines(keepends=True), body.splitlines(keepends=True),
            fromfile=f"{opts.out.relative_to(REPO_ROOT)} (on disk)",
            tofile=f"{opts.out.relative_to(REPO_ROOT)} (from {opts.results.name}/)"))
        print(f"\nSTALE: {opts.out.relative_to(REPO_ROOT)}", file=sys.stderr)
        print("Run `scripts/report.py` to regenerate, then commit.", file=sys.stderr)
        return 1

    if current == body:
        print(f"{opts.out.relative_to(REPO_ROOT)}: already up to date")
        return 0
    opts.out.write_text(body, encoding="utf-8")
    print(f"wrote {opts.out.relative_to(REPO_ROOT)} from "
          f"{', '.join(str(runs[e]['_path'].relative_to(REPO_ROOT)) for e in engines)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
