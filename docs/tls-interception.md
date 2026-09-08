# TLS interception (opt-in)

Off by default. `[policy].tls_interception = true` in `config.toml` turns
Pipelock or Squid into the real TLS endpoint for allowlisted HTTPS
destinations instead of an opaque CONNECT tunnel. This is a genuine change
to the threat model, not a tuning knob — read this whole page before
flipping the switch, not just the config line.

Smokescreen cannot do this at all and is excluded by design, not by an
oversight: it is structurally an opaque CONNECT tunnel, with no
cert-generation or decrypt code path in its own upstream source. `ipl up
--engine smokescreen` with `tls_interception = true` fails closed with a
message saying so, rather than silently running an unintercepted tunnel
under a policy that claims otherwise.

## What changes in the threat model

* **This becomes a real MITM for allowlisted HTTPS destinations.** With
  interception off, [security.md](security.md) states plainly that this
  service cannot see encrypted request bodies — an allowed destination can
  still receive anything the client sends it. With interception on, the
  engine decrypts and can evaluate the real HTTP request. The shipped policy
  defines no upload/content restriction, so an allowed service can still
  receive data, including through attacker-controlled accounts on shared
  hosting. Interception enables content policy; it is not one by itself.
* **The host now custodies a private key.** `ipl ca init` generates a
  signing CA and writes its private key to `state/ca/ca-key.pem`,
  `0600`, outside the checkout's reviewed files (`.gitignore`d — see
  `paths.ca_dir()`). Anyone who can read that file can mint a certificate
  for any hostname and impersonate any allowlisted destination to a client
  that trusts this CA. Treat the checkout's `state/` directory the way you
  would treat any other private-key store.
* **Every sandbox that is meant to see decrypted traffic needs this CA in
  its trust store.** That is a manual step (below) — `ipl` does not reach
  into `project-sandbox` or any other image to install anything.
* Denials change shape for the better: with interception on, a denied
  HTTPS request gets a real HTTP 4xx from the engine instead of a hung or
  reset CONNECT tunnel, because the engine is now evaluating the actual
  request rather than guessing from SNI alone.

## The `ipl ca` lifecycle

`ipl` owns the CA's whole lifecycle — generate, check, export, rotate.
Nothing outside `ca.py` touches the private key.

```bash
ipl ca init            # generate a CA if none exists yet
ipl ca init --rebuild   # force a fresh CA even if one is present
ipl ca status           # present/absent, cert subject, expiry
ipl ca export --out ca.pem   # write the PUBLIC cert only, never the key
ipl ca rotate            # generate a new CA (same as init --rebuild)
```

`ipl setup` also generates the CA automatically, but only when
`tls_interception = true` in `config.toml` and no CA exists yet — a repo
that never opts in gets zero new files under `state/`. `ipl up` refuses to
start an engine with `tls_interception = true` and no CA present, telling
you to run `ipl ca init` first, rather than starting a half-configured
engine.

### Rotation and compromise runbook

Rotating is generating a new CA under a different, more honest name: there
is exactly one code path (`ca.generate_ca()`) for "make a new CA," and
`init --rebuild` and `rotate` are both thin aliases over it. There is no
separate revocation mechanism — the old CA's public cert simply stops
being trusted once every sandbox's trust store is updated to the new one.

If you suspect the private key has been read by anything untrusted
(a compromised sandbox, a leaked backup of `state/`, a workstation you no
longer trust):

1. Stop the engine, then run `ipl ca rotate`. The validated pair is replaced
   transactionally. A running process or old connection may retain old key
   material, so neither may be relied on after rotation. Anything that only had the
   old *public* cert cannot forge anything with it, but anything that had
   the old *private* key could keep doing so until every consumer moves to
   the new cert.
2. Re-run the manual install step (below) in every `project-sandbox` image
   or trust store that had the old cert installed. Until that happens,
   those sandboxes will fail every intercepted HTTPS connection (the
   engine now presents leaf certs signed by a CA they no longer trust) —
   which is a safe failure mode, not a silent one.
3. Restart the engine, verify a new connection chains to the exported new CA,
   and then remove old trust. A stale-trust client must fail.
4. If the compromise was of a running sandbox rather than the host, also
   treat that sandbox as compromised independently of anything here:
   rotating the CA closes the "impersonate future connections" exposure,
   not whatever got the key out in the first place.

### Installing the cert into `project-sandbox` (manual)

`project-sandbox` is an external tool/repo, not part of this checkout, so
this stops at producing a file for it to consume — the same way exporting
`HTTP_PROXY`/`HTTPS_PROXY` into a sandbox is already a manual step today.
Nothing here is automated or scheduled; do it once per CA (and again after
every rotation).

```bash
ipl ca export --out ca.pem
```

In the sandbox's own Dockerfile (Debian/Ubuntu-family base — adjust the
paths for Alpine):

```dockerfile
COPY ca.pem /usr/local/share/ca-certificates/internet-proxy-locally.crt
RUN update-ca-certificates
```

Rebuild the sandbox image after every `ipl ca rotate`. A sandbox running
an old image after a rotation will see every intercepted connection fail
TLS verification — which is the fail-closed behavior, not a bug to work
around by re-disabling verification.

## Per-engine notes

### Pipelock

Already had first-class support before this change (`tls_interception.
enabled`, `ca_cert`, `ca_key` — this repo just switched it on). The
rendered config additionally sets `max_response_bytes: 5242880` (5 MiB):
Pipelock buffers a decrypted response to inspect it, and an unbounded
buffer on a MITM path is a memory-exhaustion surface a plain tunnel does
not have. 5 MiB is a starting point for the traffic this proxy is meant to
carry (git/package-registry API responses), not a measured ceiling —
revisit it if a real workload needs more, as a reviewed change to the
template rather than a config.toml knob (docs/policy.md's "what is
generated and what is not").

### Squid

Full `ssl_bump ... bump` with a CA-backed listener — a structurally
different mode from the `peek`+`splice`-without-a-CA configuration that
was built, measured, and rejected (`docs/findings.md`, "Rejected: tunnel
peeking on Squid"). The earlier crash came from Squid reaching for a
signing certificate that did not exist; supplying a real one is what
closes that failure mode rather than working around it.

`policy/validate.py` enforces the whole recipe or none of it: if any
`ssl_bump` directive is present, `http_port` must carry
`ssl-bump tls-cert=...`, `generate-host-certificates=on` must be present,
an `sslcrtd_program` must be configured, and both `ssl_bump peek step1`
and `ssl_bump bump all` must be present together. An orphaned `peek` with
no `bump` is exactly the historical crash shape, called out by name in the
validator's own failure message.

Squid's SNI ↔ CONNECT-target behavior must be established by the live suite,
not inferred from `ssl_bump`. The `connect-sni-mismatch` row records the
observed behavior in each mode.

The image's cert database (`/var/lib/ssl_db`, via
`security_file_certgen -c`) is initialized unconditionally at build time —
cheap enough that one image serves both `tls_interception` states, so
there is no tag fork for that reason alone.

### Smokescreen

Excluded, forever, for this feature — not a temporary gap. Confirmed
against Smokescreen's own upstream source: it has no code path that
generates a leaf certificate or terminates TLS on the CONNECT path, so
there is nothing to enable. `ipl up --engine smokescreen` with
`tls_interception = true` fails closed with a message naming the reason,
rather than silently running an unintercepted tunnel under a policy that
claims otherwise.

## Verifying interception end to end

Run `scripts/e2e-release.sh` on each supported runtime. A focused manual check is:

```bash
ipl ca export --out ca.pem
ipl --engine pipelock up   # or --engine squid, with tls_interception = true
export HTTP_PROXY=http://127.0.0.1:18080 HTTPS_PROXY=http://127.0.0.1:18080
curl --cacert ca.pem https://github.com   # allowlisted: succeeds, and
                                           # `ipl logs` shows the decrypted request
curl --cacert ca.pem https://example.com  # denied: a real 4xx, not a hung tunnel
```

`ipl-lab up && ipl-lab check` with `tls_interception = true` in the test
policy runs the same adversarial suite against the intercepting
configuration, including the SNI-mismatch check Squid can now enforce.
