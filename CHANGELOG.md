# Changelog

## Unreleased

Add `ipl --ip ADDRESS --port PORT` for independent proxy instances, including
IPv6 and non-loopback bindings. Lifecycle commands target the selected
endpoint; `ipl list` shows running IPL proxies from all workspaces on the
selected backend. Instance policy snapshots isolate TLS modes, and shared CA
rotation requires all workspace-owned proxy instances to be stopped.

## 0.1.0 — 2026-09-14

Initial release. Pipelock, Squid and Iron support optional TLS interception;
Smokescreen does not. Upgrade by stopping the owned instance, installing the
new artifact, reviewing regenerated policy, rebuilding images, and starting it.
Rollback reverses those steps. CA rotation is separate: restart the engine,
export/install the new public CA, verify new connections, then remove old trust.
