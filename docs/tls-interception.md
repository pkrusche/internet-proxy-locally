# TLS interception (opt-in)

Off by default. The `--tls-interception` CLI switch turns
Pipelock or Squid into the real TLS endpoint for allowlisted HTTPS
destinations instead of an opaque CONNECT tunnel.  Smokescreen does not 
support this, starting smokescreen with `--tls-interception`
fails.

Pass the switch after the subcommand: `ipl up --tls-interception`,
`ipl restart --tls-interception`, or `ipl-lab up --tls-interception`.
It is also available on both CLIs' `setup` commands. The choice is per
invocation: repeat it on restart; omitting it renders tunnel mode.
Remove the old `[policy].tls_interception` key from existing TOML files;
it is no longer accepted. For the lab, initialize the CA with `ipl ca init`.

## What changes

* **This enables MITM inspection for allowlisted HTTPS destinations.** 
  With interception on, the engine decrypts and can evaluate the real HTTP request.
  Note interception could enable a content policy; it is not one by itself.
* **The host now custodies a private key.** `ipl ca init` generates a
  signing CA and writes its private key to `state/ca/ca-key.pem`,
  `0600`, outside the checkout's reviewed files (`.gitignore`d — see
  `paths.ca_dir()`). Anyone who can read that file can mint a certificate
  for any hostname and impersonate any allowlisted destination to a client
  that trusts this CA. Treat the checkout's `state/` directory the way you
  would treat any other private-key store.
* **Every sandbox that is meant to see decrypted traffic needs this CA in
  its trust store.** 

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

`ipl setup --tls-interception` also generates the CA automatically
when no CA exists yet — a repo that never opts in gets zero new files under `state/`. `ipl up` refuses to
start an engine with `--tls-interception` and no CA present, telling
you to run `ipl ca init` first, rather than starting a half-configured
engine.

### Rotation and compromise runbook

If you suspect the private key has been read by anything untrusted
(a compromised sandbox, a leaked backup of `state/`, a workstation you no
longer trust):

1. Stop the engine, then run `ipl ca rotate`. The validated pair is replaced
   transactionally. A running process or old connection may retain old key
   material, so neither may be relied on after rotation. Anything that only had the
   old *public* cert cannot forge anything with it, but anything that had
   the old *private* key could keep doing so until every consumer moves to
   the new cert.
2. Re-run the manual install step (below) in every sandbox image
   or trust store that had the old cert installed. 
3. Restart the engine, verify a new connection chains to the exported new CA,
   and then remove old trust. A stale-trust client must fail.
4. If the compromise was of a running sandbox rather than the host, also
   treat that sandbox as compromised independently of anything here:
   rotating the CA closes the "impersonate future connections" exposure,
   not whatever got the key out in the first place.

### Installing the cert into a sandbox

You can export a certificate file as follows:

```bash
ipl ca export --out ca.pem
```

In Debian/Ubuntu-family images, add:

```dockerfile
COPY ca.pem /usr/local/share/ca-certificates/internet-proxy-locally.crt
RUN update-ca-certificates
```

## Per-engine notes

### Pipelock

The rendered config additionally sets `max_response_bytes: 5242880` (5 MiB):
Pipelock buffers a decrypted response to inspect it, and an unbounded
buffer on a MITM path is a memory-exhaustion surface. A future addition might
be a config setting to adjust this to allow larger downloads. Our assumption
is that the proxy would be used largely to read documentation, not install
packages (this should be part of the sandbox image build process).

### Squid

Full `ssl_bump ... bump` with a CA-backed listener. In interception
mode, `http_port` carries the certificate options and
`generate-host-certificates=on`, an `sslcrtd_program` is configured, and a
gated `ssl_bump peek step1` / `ssl_bump bump` pair is emitted together with
an `ssl_bump splice all` fallback.

### Smokescreen

Smokescreen doesn't support TLS interception.

## Late denials, and how the suite grades them

A deny check asks whether the destination was reached, not what status came
back. `ProxyClient.tunnel_carried()` watches a tunnel that was answered
`200`: if it is torn down without carrying anything, the row passes with
cause `aborted-after-connect`, and only a tunnel that stays open and usable
fails. Grading the status line alone reported a correctly-enforcing Squid
as an open proxy — 13 rows at once, every one of them a refusal.

## Verifying interception end to end

Run `scripts/e2e-release.sh` on each supported runtime. A focused manual check is:

```bash
ipl ca export --out ca.pem
ipl --engine pipelock up --tls-interception   # or --engine squid
export HTTP_PROXY=http://127.0.0.1:18080 HTTPS_PROXY=http://127.0.0.1:18080
curl --cacert ca.pem https://github.com   # allowlisted: succeeds, and
                                           # `ipl logs` shows the decrypted request
curl --cacert ca.pem https://example.com  # denied: a real 4xx, not a hung tunnel
```

That second line is the one that catches an ungated peek on Squid: a
`curl: (56) Recv failure` or an empty reply where a 403 page belongs means
the CONNECT is being acknowledged before policy runs, and the peek is
covering destinations the floors deny (see [Squid](#squid) above). The
egress suite still passes such a run — the tunnel carries nothing either
way — so this is the check that sees it.

`ipl-lab up --tls-interception && ipl-lab check` runs the adversarial suite
against the intercepting configuration. `ipl-lab measure --tls-interception`
does this across all three engines and rewrites `docs/findings.md`: pipelock
and squid are measured with interception on, and smokescreen — which doesn't
support it — is still measured in tunnel mode rather than failing the run.

Every `--json` result records whether the engine it measured was running
with interception on (`tls_interception`, schema version 3+) — `check`
detects this from the running container's own ownership label rather than
needing it repeated on the command line, so it stays right even when `check`
is invoked separately from the `up` that started the engine. `docs/findings.md`'s
conditions table has a matching "TLS interception" row per engine.
