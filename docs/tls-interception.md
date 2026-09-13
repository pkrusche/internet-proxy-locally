# TLS interception (opt-in)

Off by default. The `--tls-interception` CLI switch turns
Pipelock, Squid or Iron into the real TLS endpoint for allowlisted HTTPS
destinations instead of an opaque CONNECT tunnel.  Smokescreen does not 
support this, starting smokescreen with `--tls-interception`
fails.

Pass the switch after the subcommand: `ipl up --tls-interception`,
`ipl restart --tls-interception`, or `ipl-lab up --tls-interception`.

Initialize the CA with `ipl ca init`.

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
  its trust store.** Project-sandbox supports this: <https://github.com/pkrusche/project-sandbox/blob/main/docs/internet-proxy.md#injecting-proxy-ca-certificates>.

## The `ipl ca` lifecycle

```bash
ipl ca init            # generate a CA if none exists yet
ipl ca init --rebuild   # force a fresh CA even if one is present
ipl ca status           # present/absent, cert subject, expiry
ipl ca export --out ca.pem   # write the PUBLIC cert only, never the key
ipl ca rotate            # generate a new CA (same as init --rebuild)
```

`ipl setup --tls-interception` also generates the CA automatically
when no CA exists yet — a repo that never opts in gets zero new files under `state/`. `ipl up` refuses to
start an engine with `--tls-interception` and no CA present.

### Rotation 

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

Squid runs as `squid:squid` from its first instruction, including configuration
parsing. With interception enabled, only a small entrypoint starts as root:
it copies the read-only CA mounts from root-only `/run/ipl-ca/` into
`/dev/shm/ipl-squid-ca/` (a `0500` directory with `0400` files, owned by Squid),
then uses `su-exec` to permanently drop user/group privileges before executing
Squid. No root wrapper stays behind, and container signals reach Squid directly.
The host key's `0600` permissions and ownership are unchanged.

The entrypoint requires `/dev/shm` to be tmpfs and refuses an existing staging
directory or any copy/permission failure. The copy survives only for the
container's runtime lifetime, never in its writable image layer; it is needed
for configuration reloads. As with any tmpfs, [host swap](https://docs.docker.com/engine/storage/tmpfs/)
or VM snapshots can retain memory, so this is not a secure-erasure guarantee. Without interception,
the image's `USER squid` remains in effect and no CA copy is made.

This requires image `squid:6.12-r0-build2`; run `ipl --engine squid setup` to
build it, then restart Squid. Recorded `build1` benchmark results remain historical
evidence, not validation of the new image; run the release gate for fresh results.
The gate checks Squid's real/effective/saved IDs, supplementary groups, and CA
staging permissions. On an already running instance, the same read-only check
is `sh scripts/check-squid-runtime.sh docker on` (or `container`, and `off`
without interception).

Full `ssl_bump ... bump` with a CA-backed listener. In interception
mode, `http_port` carries the certificate options and
`generate-host-certificates=on`, an `sslcrtd_program` is configured, and a
gated `ssl_bump peek step1` / `ssl_bump bump` pair is emitted together with
an `ssl_bump splice all` fallback.

### Smokescreen

Smokescreen doesn't support TLS interception.

### Iron

Without interception, `tls.mode: sni-only` checks the TLS ClientHello SNI
and passes TLS through without a signing CA. With interception, `tls.mode: mitm`
uses the same managed CA as the other engines, mounted read-only at
`/config/ca.pem` and `/config/ca-key.pem`. Upstream certificate verification
remains enabled; lab runs also receive the fixture's public CA through
`SSL_CERT_FILE`.

## Late denials, and how the suite grades them

A CONNECT `200` only acknowledges the tunnel. With interception, even a
successful TLS handshake may be with the proxy itself. The CONNECT deny
probes therefore send ClientHello with the destination name, complete TLS,
and send an HTTP GET. A complete HTTP 2xx/3xx response is evidence of access;
Squid's HTTP 403 containing our `internet-proxy-locally denied this request:`
page is a denial, with its stated reason retained for classification. These
custom `deny_info` pages need not include `X-Squid-Error`. An explicit
`X-Squid-Error: ERR_ACCESS_DENIED` also counts (`proxy-access-denied`).
Ordinary CONNECT 4xx refusals also pass. Generic origin 403s remain inconclusive.
Error responses retain a bounded body excerpt and any `X-Squid-Error` value,
so a fixture's 503 can be diagnosed rather than reduced to its status line.

Timeouts, resets, TLS alerts, incomplete responses, and other HTTP errors
remain inconclusive (`error`): the client alone cannot tell an origin failure
from a proxy refusal. In particular, waiting silently for 0.5 seconds does
not prove a tunnel carried traffic. The old `aborted-after-connect` grade
also overstated what a client-side close proves; it remains readable in
historical results but new probes do not emit it.

The active probe uses TLS even for CONNECT targets on port 80, to exercise
an intercepting listener. A plaintext-only origin may therefore produce an
inconclusive result; this is not proof that the proxy blocked it. Certificate
verification is disabled for these behavioral probes, so they do not verify
CA trust or upstream identity. Engine logs remain attached for diagnosis.

## Verifying interception end to end

Run `scripts/e2e-release.sh` on each supported runtime. It performs trusted,
untrusted, and denied-destination checks for every engine that supports
interception, plus a CA-rotation check through Pipelock. The equivalent focused
manual check is:

```bash
ipl ca export --out ca.pem
ipl --engine pipelock up --tls-interception   # or --engine squid / --engine iron
export HTTP_PROXY=http://127.0.0.1:18080 HTTPS_PROXY=http://127.0.0.1:18080
curl --cacert ca.pem https://github.com   # allowlisted: succeeds, and
                                           # `ipl logs` shows the decrypted request
curl --cacert ca.pem https://example.com  # denied: a real 4xx, not a hung tunnel
```

For the denied request, the release gate accepts a CONNECT 4xx or a completed
HTTP 403 inside TLS carrying the project's denial marker or Squid's
`X-Squid-Error: ERR_ACCESS_DENIED`. A CONNECT 200 alone does not establish
whether the request was allowed. Generic origin 403s, resets, and timeouts
remain inconclusive. Untrusted and stale-trust checks require curl's
certificate-verification failure (exit 60); an arbitrary network error cannot
count as successful rejection.
