# Working in this repo

## Tooling

Everything runs through `uv` — there is no supported bare-interpreter path.

| | command | notes |
|---|---|---|
| lint | `uv run ruff check .` | `--fix` to apply. Ruff's default rule set; no `[tool.ruff]` section |
| format | `uv run ruff format .` | `--check` to verify only |
| types | `uv run ty check` | needs the runtime deps installed, so no `--only-group dev` |
| tests | `uv run python -m unittest discover -s tests -t .` | ~105s, no network or container runtime |

`ruff` and `ty` are pinned in `uv.lock` and CI runs them with `--frozen`, so a
local run and a CI run are the same binary. Upgrading either is a deliberate
`uv lock --upgrade-package ruff` (or `ty`), never something a fresh checkout
does on its own. `.github/workflows/checks.yml` runs the first three rows.

## Versioning: jj, not git

This repo is worked with [jujutsu](https://jj-vcs.github.io/jj/); `.jj` is the
source of truth and `jj log` / `jj status` are the commands to reach for.

**Substantial changes belong in their own jj revision, with `ruff` and `ty`
passing before that revision is described.** In practice:

```sh
jj new -m "what this change is"      # start a revision for the work
# ... make the change ...
uv run ruff check . && uv run ruff format --check . && uv run ty check
```

The reason is that jj snapshots the working copy into whatever revision is
`@` at that moment. A refactor and an unrelated repo-wide reformat run
together land as one indivisible blob, and separating them afterwards means
hunk-level surgery on a revision someone is still working in. Starting the
revision first is what keeps that from happening.

Two consequences worth stating:

- A mechanical, whole-tree change (a reformat, a rename, a codemod) is always
  its own revision. It is the change most likely to bury a real edit.
- Do not leave a revision described until the checks pass, so `jj log` reads
  as a list of states that were each known-good.

## Suppressions

Both tools are taken at their defaults, so a suppression is a claim that the
tool is wrong about this line — write it in that tool's own syntax and say
why:

- `# noqa: RULE - reason` for ruff.
- `# ty: ignore[rule]` for ty. Note that mypy-style `# type: ignore[code]`
  does **not** suppress a ty diagnostic; ty does not know mypy's rule names.

The existing `# ty: ignore[invalid-assignment]` markers in `tests/` are all
the same case: substituting a plain function for a bound method, which is the
technique those tests are built on and which no type checker can model.
