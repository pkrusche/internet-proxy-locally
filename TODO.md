# TODO

## Open work

- [ ] Harden Pipelock and Iron so their proxy processes do not run as root
  when TLS interception injects a CA. Add non-root runtime users and secure
  container-local CA staging, with checks that the private key remains
  inaccessible to the proxy's startup/runtime process after privilege drop.
