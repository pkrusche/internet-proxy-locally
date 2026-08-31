# TODO

Open work only. Implementation notes for what is already done live in
`docs/`.

## Simplification

The pass reviewed against `b38c90f` is done. All seven items were applied;
216 unit tests pass in ~105s (`uv run python -m unittest discover -s tests
-t .`, see [docs/lab.md](docs/lab.md)). Two things about it are worth
knowing rather than rediscovering:

* **`setup` no longer records a pin for you.** Pipelock's "no digest yet,
  so pull the tag and write one down" branch is gone, so all three services
  fail closed and point at `pin` — the reviewable path — exactly as Squid
  and Smokescreen always did. This was the one deliberate behavior change
  in the pass; `test_setup_is_fail_closed_for_every_pin_kind` holds it.
* **The DNS fixture image now carries what it serves.** `lab/fixtures.toml`
  is the single source: `checks/egress.py` reads it directly, and
  `lab/dnsfixture/rebind.py` takes the rebind zone, the PTR claim and the
  public answer as Dockerfile ARGs. **An image built before this change
  will refuse to start** (`REBIND_ZONE is empty`) — run
  `./lab.py setup --rebuild` once.

### Still open

* `Backend.image_size` is down from ~28 lines to ~13 now that it shares
  `_inspect_entry`, but it still parses two runtime shapes to produce a
  single informational line in `scripts/verify_resilience.py`. It is
  reported, never graded. Kept because image size is one of the operational
  numbers the engine choice is weighed on and it was deliberately collected
  — delete it if that stops being true.
