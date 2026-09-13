# TODO

- [ ] Harden Pipelock and Iron so their proxy processes do not run as root
  when TLS interception injects a CA. Add non-root runtime users and secure
  container-local CA staging, with checks that the private key remains
  inaccessible to the proxy's startup/runtime process after privilege drop.

- [ ] Run `scripts/e2e-release.sh docker` on a Docker-capable host, including
  Linux bind-mount permissions, Squid `build2` interception with a host-owned
  `0600` key, non-root Squid process IDs and tmpfs staging, and fresh policy
  measurements. No container runtime is available in the
  implementation workspace; unit/static/package checks do not replace this gate.
