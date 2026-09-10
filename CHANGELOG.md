# Changelog

## 0.1.0 — unreleased

Initial release. Pipelock, Squid and Iron support optional TLS interception;
Smokescreen does not. Upgrade by stopping the owned instance, installing the
new artifact, reviewing regenerated policy, rebuilding images, and starting it.
Rollback reverses those steps. CA rotation is separate: restart the engine,
export/install the new public CA, verify new connections, then remove old trust.

Iron v0.49.0 is selectable with `--engine iron`, using the shared hostname
policy and explicit destination deny ranges in operational and lab runs.
Its DNS/private-address checks can attribute late denials to correlated
`upstream_deny_cidrs` audit errors, retaining the original client failure.
