# TODO

Open work only. Implementation notes for what is already done live in
`docs/`.

Everything carried here on 2026-08-28 has been closed. Two items were
closed by measuring them (`scripts/verify_resilience.py`); one was closed
by establishing that it is not this repository's to do.

---

## 1. Still open

* [ ] **Resource usage in steady state, and upgrade friction.** The two
      operational numbers `scripts/verify_resilience.py` does not collect:
      it measures startup time and image size, not memory and CPU under
      sustained load, and nothing measures how much work a version bump
      actually costs (docs/engines.md, "Not yet measured"). Neither blocks
      anything; both are inputs to the engine choice that are currently
      guesses.

## 2. Closed, and where the answer went

Kept briefly so the next reader does not re-open them.

* **Crash → fail-closed** and **`restart` under load** — measured on all
  three engines under continuous load; the endpoint stops accepting when
  the engine dies and no request for a denied host ever succeeded across
  either transition. docs/security.md, "Fail-closed properties".

* **The `project-sandbox` integration matrix** — not unverified work here.
  The installed `project-sandbox` does not route sandboxes through this
  proxy at all: it sets no `HTTP_PROXY`/`HTTPS_PROXY`, never names the
  endpoint, and filters egress with its own iptables/ipset allowlist.
  `scripts/verify_sandbox.py` reads that off the installation on every
  run, so it cannot quietly stop being true, and carries the in-sandbox
  assertions ready for when the routing exists. Wiring it is work in
  `project-sandbox`. docs/architecture.md now says the topology is an
  intended integration rather than a description of any machine.

* **Is a followed redirect's target re-authorized?** — yes, measured with
  a control. docs/engines.md §6.
