"""Render the measured tables of docs/findings.md from result files."""

from __future__ import annotations

import difflib
import json
import subprocess
import sys
from pathlib import Path

# Marker names in docs/findings.md; only their contents are regenerated.
SECTIONS = ("conditions", "summary", "matrix", "per-check")

from internet_proxy_locally import paths
from internet_proxy_locally.checks import egress  # the catalogue this renders
from internet_proxy_locally.cli import CLI_MODULE
from internet_proxy_locally.constants import ENGINE_LABELS as LABELS
from internet_proxy_locally.constants import ENGINES
from internet_proxy_locally.errors import Fail


def result_path(results_dir: Path, engine: str) -> Path:
    """`results/<engine>.json`, or the newest `results/<engine>-*.json`.

    The dated form is what docs/lab.md's reproduce recipe writes, so both
    are accepted rather than making the recipe wrong.
    """
    exact = results_dir / f"{engine}.json"
    if exact.is_file():
        return exact
    dated = sorted(results_dir.glob(f"{engine}-*.json"))
    if dated:
        return dated[-1]
    raise Fail(
        f"no results for {engine}: expected {exact} or "
        f"{results_dir / (engine + '-<date>.json')}.\n"
        "Run `ipl-lab measure` (needs a container runtime), or "
        f"`ipl-lab --engine {engine} up && ipl-lab check --json > "
        f"results/{engine}.json`."
    )


def load_runs(results_dir: Path, engines: tuple[str, ...]) -> dict[str, dict]:
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
                "file does not carry the conditions this report states."
            )
        if data.get("engine") != engine:
            raise Fail(
                f"{path}: holds results for {data.get('engine')!r}, not {engine!r}"
            )
        if data.get("mode") != "full":
            raise Fail(
                f"{path}: is a `{data.get('mode')}` run. The comparison is "
                "generated from `ipl-lab check`; a quick run has no fixture rows "
                "and would report them as missing rather than as skipped."
            )
        runs[engine] = data
        runs[engine]["_path"] = path
    return runs


def rows_of(run: dict) -> dict[str, dict]:
    return {row["name"]: row for row in run.get("results", [])}


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
    """Checks graded `pass`/`fail` on *every* engine."""
    names = []
    for name in (c.name for c in egress.TESTS):
        rows = [rows_of(run).get(name) for run in runs.values()]
        if all(
            row is not None and row["expectation"] in ("allow", "deny") for row in rows
        ):
            names.append(name)
    return names


def behavior(row: dict) -> str:
    """What the engine did, with the grade taken back out."""
    if row.get("observed"):
        return row["observed"]
    if row["outcome"] in ("pass", "fail") and row["expectation"] in ("allow", "deny"):
        wanted = "denied" if row["expectation"] == "deny" else "allowed"
        opposite = "allowed" if wanted == "denied" else "denied"
        return wanted if row["outcome"] == "pass" else opposite
    return row["outcome"]


def divergences(runs: dict[str, dict], names: list[str]) -> list[tuple[str, dict]]:
    """Checks where the engines did not all report the same verdict."""
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
    return "; ".join(
        f"{'/'.join(LABELS[m] for m in members)} {label}"
        for label, members in groups.items()
    )


def conditions_table(runs: dict[str, dict]) -> list[str]:
    lines = [
        "| | " + " | ".join(LABELS[e] for e in runs) + " |",
        "| --- |" + " --- |" * len(runs),
    ]
    fields = [
        ("Measured", lambda r: r.get("generated_at") or "?"),
        ("Backend", lambda r: r.get("backend") or "?"),
        ("Host", lambda r: r.get("host") or "?"),
        ("Image", lambda r: f"`{r['image']}`" if r.get("image") else "?"),
        (
            "Policy",
            lambda r: {
                "test": "test (`ipl-lab up`)",
                "real": "real",
                "unknown": "?",
            }.get(r.get("policy"), "?"),
        ),
        ("Endpoint", lambda r: f"`{r.get('proxy', '?')}`"),
        ("Result", counts),
        ("Exit code", lambda r: str(r.get("exit_code", "?"))),
    ]
    for label, get in fields:
        lines.append(f"| {label} | " + " | ".join(get(runs[e]) for e in runs) + " |")
    return lines


def render_sections(runs: dict[str, dict], results_dir: Path) -> dict[str, str]:
    """The generated blocks of docs/findings.md, keyed by marker name."""
    return {
        "conditions": _conditions(runs, results_dir),
        "summary": _summary(runs),
        "matrix": _matrix(runs),
        "per-check": _per_check(runs),
    }


def _conditions(runs: dict[str, dict], results_dir: Path) -> str:
    engines = list(runs)
    out = conditions_table(runs)
    out.append("")
    out.append(
        "Source files: "
        + ", ".join(
            f"`{runs[e]['_path'].relative_to(paths.workspace_root())}`" for e in engines
        )
        + "."
    )
    return "\n".join(out)


def _summary(runs: dict[str, dict]) -> str:
    engines = list(runs)
    out: list[str] = []
    add = out.append
    graded = graded_names(runs)
    total = len(rows_of(runs[engines[0]]))
    ungraded = [c.name for c in egress.TESTS if c.name not in graded]
    add(
        f"{len(graded)} of the {total} checks are graded `pass`/`fail` on every "
        "engine. In that common pool:"
    )
    add("")
    for engine in engines:
        rows = rows_of(runs[engine])
        failed = [n for n in graded if rows[n]["outcome"] != "pass"]
        state = (
            "passes all of them"
            if not failed
            else "does not pass "
            + ", ".join(f"`{n}` ({rows[n]['outcome']})" for n in failed)
        )
        add(f"* **{LABELS[engine]}** {state}.")
    add("")
    if ungraded:
        add(
            "**Passing that pool is not the same as behaving identically**, and the "
            f"{len(ungraded)} check(s) it leaves out are where the engines differ: "
            + ", ".join(f"[`{name}`](#{name})" for name in ungraded)
            + ". Each is "
            "graded `record` on at least one engine, which takes it out of any pass "
            "count — a `record` grade means no verdict is defined there, never that "
            "the behavior was the same. What each engine actually did is below."
        )
        add("")

    diverging = divergences(runs, [c.name for c in egress.TESTS])
    # Separate behavioral disagreements from different names for the same denial.
    behavioral = [
        (name, groups) for name, groups in diverging if behavior_differs(runs, name)
    ]
    attribution = [
        (name, groups) for name, groups in diverging if not behavior_differs(runs, name)
    ]

    if behavioral:
        add(
            f"**Different behavior** on {len(behavioral)} check(s) — one engine "
            "allowed what another refused:"
        )
        add("")
        for name, groups in behavioral:
            add(f"* [`{name}`](#{name}) — " + _describe(groups))
        add("")
    else:
        add(
            "**No engine behaved differently from another on any check**: every "
            "outcome below is the same across the three."
        )
        add("")
    if attribution:
        add(
            f"**Same behavior, different stated reason** on {len(attribution)} "
            "check(s). These are not behavioral differences — the request was "
            "refused either way — but they say which rule did the refusing, which "
            "is what decides whether a row is evidence of the thing it is named "
            "after:"
        )
        add("")
        for name, groups in attribution:
            add(f"* [`{name}`](#{name}) — " + _describe(groups))
    return "\n".join(out).rstrip()


def _matrix(runs: dict[str, dict]) -> str:
    engines = list(runs)
    out: list[str] = []
    add = out.append
    add(
        "Bracketed values are the **attributed cause**: what the engine said it was "
        "rejecting, not what the check is named after. A blank one means nothing was "
        "denied, so there is no reason to attribute."
    )
    add("")
    add(
        "| Check | Group | Expectation | "
        + " | ".join(LABELS[e] for e in engines)
        + " |"
    )
    add("| --- | --- | --- |" + " --- |" * len(engines))
    mixed = False
    for name, group in ((c.name, c.group) for c in egress.TESTS):
        cells = []
        expectations = set()
        for engine in engines:
            row = rows_of(runs[engine]).get(name)
            cells.append(verdict(row))
            if row:
                expectations.add(row["expectation"])
        mixed = mixed or len(expectations) > 1
        expectation = "/".join(sorted(expectations)) if expectations else "—"
        add(
            f"| [{name}](#{name}) | {group} | {expectation} | "
            + " | ".join(cells)
            + " |"
        )
    if mixed:
        add("")
        add(
            "Where the expectation column shows two values, the check was "
            "graded differently per engine in this run."
        )
    return "\n".join(out)


def _per_check(runs: dict[str, dict]) -> str:
    engines = list(runs)
    out: list[str] = []
    add = out.append
    for name, group in ((c.name, c.group) for c in egress.TESTS):
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
            attempts = f", {len(row['attempts'])} probes" if row.get("attempts") else ""
            add(
                f"* **{LABELS[engine]}** — {verdict(row)} "
                f"(expectation: {row['expectation']}{timing}{attempts})  "
            )
            add(f"  {row['detail']}")
        add("")
    return "\n".join(out).rstrip()


def _marker(name: str, edge: str) -> str:
    return f"<!-- {edge} GENERATED {name} -->"


def inject(document: str, sections: dict[str, str], out: Path) -> str:
    """Replace each marked region of `document` with its rendered section.

    Everything outside the markers is copied through byte for byte. A
    missing or duplicated marker is fatal rather than silently skipped: a
    findings document that quietly stopped carrying a table would read as
    if the measurement had never been made.
    """
    for name, body in sections.items():
        begin, end = _marker(name, "BEGIN"), _marker(name, "END")
        for edge in (begin, end):
            found = document.count(edge)
            if found != 1:
                raise Fail(
                    f"{out.relative_to(paths.workspace_root())}: expected exactly one "
                    f"`{edge}`, found {found}. The generated blocks are "
                    f"{', '.join(SECTIONS)}."
                )
        if document.index(begin) > document.index(end):
            raise Fail(
                f"{out.relative_to(paths.workspace_root())}: `{end}` appears before "
                f"`{begin}`"
            )
        head, _, rest = document.partition(begin)
        _, _, tail = rest.partition(end)
        document = f"{head}{begin}\n\n{body}\n\n{end}{tail}"
    return document


def build(runs: dict[str, dict], results_dir: Path, out: Path) -> str:
    """The full text `out` should have, given these results."""
    if not out.is_file():
        raise Fail(
            f"missing {out.relative_to(paths.workspace_root())}. It is written by hand "
            "around the generated blocks; this script does not create it."
        )
    return inject(
        out.read_text(encoding="utf-8"), render_sections(runs, results_dir), out
    )


def write_findings(
    check: bool = False,
    results_dir: Path | None = None,
    out: Path | None = None,
    engines: tuple[str, ...] = ENGINES,
) -> int:
    """Regenerate (or verify) the generated blocks. Returns an exit code."""
    results_dir = paths.results_dir() if results_dir is None else results_dir
    out = paths.findings_file() if out is None else out
    try:
        runs = load_runs(results_dir, engines)
        body = build(runs, results_dir, out)
    except Fail as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    current = out.read_text(encoding="utf-8")
    rel = out.relative_to(paths.workspace_root())
    if current == body:
        print(f"{rel}: up to date with {results_dir.name}/")
        return 0
    if check:
        sys.stdout.writelines(
            difflib.unified_diff(
                current.splitlines(keepends=True),
                body.splitlines(keepends=True),
                fromfile=f"{rel} (on disk)",
                tofile=f"{rel} (from {results_dir.name}/)",
            )
        )
        print(f"\nSTALE: {rel}", file=sys.stderr)
        print("Run `ipl-lab report` to regenerate, then commit.", file=sys.stderr)
        return 1
    out.write_text(body, encoding="utf-8")
    print(
        f"rewrote the generated blocks of {rel} from "
        f"{', '.join(str(runs[e]['_path'].relative_to(paths.workspace_root())) for e in engines)}"
    )
    return 0


def measure_all(
    backend: str | None = None,
    engines: tuple[str, ...] = ENGINES,
    results_dir: Path | None = None,
    out: Path | None = None,
) -> int:
    """Measure every engine, then rewrite the generated blocks of findings.

    Every engine publishes the same endpoint, so this is necessarily
    sequential, and each `ipl-lab up` removes whatever the last one left.
    The final `down` matters: `ipl-lab up` starts a DNS fixture that must
    never outlive the run.
    """
    results_dir = paths.results_dir() if results_dir is None else results_dir
    out = paths.findings_file() if out is None else out
    results_dir.mkdir(parents=True, exist_ok=True)
    lab_cli = [sys.executable, "-m", CLI_MODULE["ipl-lab"]]
    common = ["--backend", backend] if backend else []
    try:
        try:
            print("=== lab setup (all engines + the DNS fixture)", flush=True)
            _run(lab_cli + common + ["setup"])
            for engine in engines:
                print(f"=== {engine}: up (test policy)", flush=True)
                _run(lab_cli + common + ["--engine", engine, "up"])
                print(f"=== {engine}: check --json", flush=True)
                proc = subprocess.run(
                    lab_cli + common + ["check", "--json"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                # Exit 1 is a measured failure to report; only invalid output aborts.
                try:
                    json.loads(proc.stdout)
                except json.JSONDecodeError as exc:
                    raise Fail(
                        f"{engine}: `ipl-lab check --json` produced no result "
                        f"document ({exc}).\n{proc.stderr.strip()}"
                    ) from exc
                path = results_dir / f"{engine}.json"
                path.write_text(proc.stdout, encoding="utf-8")
                print(
                    f"=== {engine}: wrote {path.relative_to(paths.workspace_root())} "
                    f"(exit {proc.returncode})",
                    flush=True,
                )
        finally:
            subprocess.run(lab_cli + common + ["down"], check=False)
    except Fail as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return write_findings(
        check=False, results_dir=results_dir, out=out, engines=engines
    )


def _run(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, check=False)
    if proc.returncode != 0:
        raise Fail(f"`{' '.join(cmd)}` failed with exit {proc.returncode}")
