# Smokescreen engine

Conservative/minimal comparison engine.
Upstream: <https://github.com/stripe/smokescreen>.

## Operating mode

* egress ACL (`config/smokescreen.yaml`): `version: v1`, a single
  `default` service with `action: enforce` and the shared allowlist —
  never `open` or `report`;
* daemon config (`config/smokescreen.conf.yaml`, mounted at
  `/etc/smokescreen/config.yaml` and passed with `--config-file`) sets
  `allow_missing_role: true`, so every client (no client TLS in v1) is
  subject to that default service. It lives in a config file because
  upstream exposes that key there only — there is no CLI flag for it, and
  without it requests are rejected before the ACL is consulted;
* Smokescreen's built-in protections stay on: public-IP validation,
  private/loopback/link-local range blocking, resolved-IP checking
  (`--unsafe-allow-private-ranges` is forbidden and rejected by
  validation);
* connection timeout: upstream default (10s); tune with upstream flags in
  `services/smokescreen.toml` only via a reviewed change;
* listens on `0.0.0.0:4750` in-container; the host publishes
  `127.0.0.1:18080 → 4750`.

## CONNECT tunnel behavior

Smokescreen validates the CONNECT *destination* but — unlike Pipelock —
has no documented SNI↔CONNECT verification or TLS-requirement inside
tunnels. The adversarial suite records its actual behavior
(`connect-sni-mismatch`, `connect-raw-tunnel`) rather than judging it;
those measurements feed the backend decision (docs/comparison.md).

## Image

No turnkey upstream OCI packaging, so `images/smokescreen/Dockerfile`
builds a local multi-stage image:

* source pinned to a full commit SHA in `services/smokescreen.toml`
  (recorded by `./run.py pin smokescreen`); the Dockerfile refuses
  non-SHA refs;
* pinned Go builder and Alpine runtime bases (`[build]` in the toml);
* static binary, unprivileged `smokescreen` user, upstream LICENSE at
  `/licenses/smokescreen.LICENSE`;
* built through Docker or Apple `container` by `./run.py setup`
  (`--rebuild` to force); local by default — publishing the image is out
  of scope until third-party distribution requirements are reviewed.

## Logging and privacy

Smokescreen writes structured (logrus) access log lines to stdout with,
per connection: client address, requested hostname (CONNECT target or
absolute-form URL — full URLs are visible for plaintext HTTP), resolved
IP, decision (allow/deny) and reason, and timing. Retention is the
container log stream only: logs disappear when the container is
recreated/removed. Nothing is shipped anywhere.

## mTLS

Not enabled. Smokescreen's client-certificate identity/per-service ACLs
become relevant only if one shared proxy must serve multiple caller
identities with different policies; revisit then.
