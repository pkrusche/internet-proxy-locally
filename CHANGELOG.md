# Changelog

## 0.1.0 — unreleased

Initial release. Pipelock, Squid and Iron support optional TLS interception;
Smokescreen does not. Upgrade by stopping the owned instance, installing the
new artifact, reviewing regenerated policy, rebuilding images, and starting it.
Rollback reverses those steps. CA rotation is separate: restart the engine,
export/install the new public CA, verify new connections, then remove old trust.
