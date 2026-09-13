# TODO

First public release review (2026-09-13):

- [x] P1: Make generated configs readable by non-root proxy containers, and
  give Squid secure access to the host-owned interception key.
  Config rendering now sets and repairs mode `0644`. Squid interception starts
  with privileges to read the `0600` key, then drops to the configured Squid user.
- [x] P1: Base container/network ownership on the resolved workspace root so
  subdirectory commands work and different IPL_ROOT workspaces cannot remove
  each other's containers.
  Ownership labels now hash the canonical workspace root, not the current directory.
- [x] P1: Make the release gate reject policy regressions, including failed or
  missing required checks, while retaining known engine limitations as findings.
  Smoke tests require passing quick checks; lab results use an explicit
  engine/TLS-mode acceptance matrix, rejecting missing, skipped or errored checks.
- [x] P2: Require explicit proxy-denial evidence for plain HTTP; gateway errors
  and generic origin error responses must remain inconclusive.
  Engine-specific response evidence or a matching, timestamped Iron rejection
  audit is required. Metadata checks retain independent CONNECT and HTTP attempts.
- [x] P2: Disclose Elastic License 2.0 for the enterprise code included in the
  pinned Pipelock Docker release, alongside its Apache-2.0 core.
  `LICENSE` links both licenses for the pinned release.
- [x] P2: Correct the security guide's Squid SNI-mismatch claim to agree with
  the committed measurements.
  The guide now states that Squid fails this check in both TLS modes, and also
  qualifies the measured mixed-DNS limitations of Smokescreen and Iron.

Remaining release validation:

- [ ] Run `scripts/e2e-release.sh docker` on a Docker-capable host, including
  Linux bind-mount permissions, Squid interception with a host-owned `0600` key,
  and fresh policy measurements. No container runtime is available in the
  implementation workspace; unit/static/package checks do not replace this gate.
