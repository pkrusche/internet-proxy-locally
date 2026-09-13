# TODO

## Before the repository goes public

- [ ] Give security reports a private channel. SECURITY.md sends findings to
  public issues, which for a proxy bypass discloses it to attackers the
  moment it is filed. Enable GitHub private vulnerability reporting and name
  it in SECURITY.md.

## Open work

- [ ] Harden Pipelock and Iron so their proxy processes do not run as root
  when TLS interception injects a CA. Add non-root runtime users and secure
  container-local CA staging, with checks that the private key remains
  inaccessible to the proxy's startup/runtime process after privilege drop.

- [ ] Move to the PEP 639 license spelling: `license = "MIT"` with
  `license-files = ["LICENSE"]`, dropping the deprecated
  `License :: OSI Approved :: MIT License` classifier. Builds are correct
  today; the classifier form is what PyPI has deprecated.
