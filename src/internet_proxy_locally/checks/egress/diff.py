"""`--diff A.json B.json`: compare two prior `--json` runs and print only
the rows that diverge, instead of running the suite."""

from __future__ import annotations

import json
import sys


def _load_results(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def diff_results(a: dict, b: dict) -> list[str]:
    a_by_name = {r["name"]: r for r in a.get("results", [])}
    b_by_name = {r["name"]: r for r in b.get("results", [])}
    lines: list[str] = []
    for name in sorted(set(a_by_name) | set(b_by_name)):
        rb = b_by_name.get(name)
        if rb is None:
            # `name` came from one side or the other, so absent from B puts
            # it in A: the index cannot raise, and says so.
            ra = a_by_name[name]
            lines.append(f"{name}: only in A — {ra['outcome']} ({ra['detail']})")
            continue
        ra = a_by_name.get(name)
        if ra is None:
            lines.append(f"{name}: only in B — {rb['outcome']} ({rb['detail']})")
            continue
        if ra["outcome"] != rb["outcome"] or ra.get("cause") != rb.get("cause"):
            a_tag = f"{ra['outcome']}" + (
                f" [{ra['cause']}]" if ra.get("cause") else ""
            )
            b_tag = f"{rb['outcome']}" + (
                f" [{rb['cause']}]" if rb.get("cause") else ""
            )
            lines.append(
                f"{name}: A={a_tag} vs B={b_tag}\n    A: {ra['detail']}\n    B: {rb['detail']}"
            )
    return lines


def cmd_diff(path_a: str, path_b: str) -> int:
    a, b = _load_results(path_a), _load_results(path_b)
    if a.get("schema_version") != b.get("schema_version"):
        print(
            f"warning: schema_version mismatch ({a.get('schema_version')} vs "
            f"{b.get('schema_version')}); fields may not align",
            file=sys.stderr,
        )
    lines = diff_results(a, b)
    label_a, label_b = a.get("engine", path_a), b.get("engine", path_b)
    if not lines:
        print(
            f"no divergence between {label_a} ({path_a}) and {label_b} ({path_b}): "
            f"all {len(a.get('results', []))} checks agree"
        )
        return 0
    print(f"divergences between {label_a} ({path_a}) and {label_b} ({path_b}):")
    for line in lines:
        print(f"  {line}")
    return 0
