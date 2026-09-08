# Opt-in TLS interception (MITM) for Pipelock and Squid

## Context

This repo's whole design has, until now, deliberately excluded TLS
interception: `docs/security.md`'s "Non-goals" section calls it out by name,
`config/squid.conf`'s history records a specific rejected attempt
(`ssl_bump peek`+`splice` without a signing CA crashed Squid and hid every
denial — see the `squid-peek-rejected` memory and `docs/findings.md`,
"Rejected: tunnel peeking on Squid"), and every template currently renders
`tls_interception: enabled: false` / no `ssl_bump` as unconditional literal
text.

We looked at adding `iron-proxy` as a fourth engine and found it *always*
MITMs — no passthrough mode exists. Rather than adopt a new engine for that
capability, the decision was to scope out MITM support for the engines
already here (iron-proxy stays parked on the backlog). Research into each
existing engine found:

- **Pipelock** already has first-class support (`tls_interception.enabled`,
  `ca_cert`, `ca_key` config keys; a `pipelock tls init`/`install-ca` CLI
  workflow) — just switched off in our template.
- **Squid** can do it too, but not the way it was tried before: the prior
  crash was `peek`+`splice` *without* a CA. Full `ssl_bump ... bump` *with* a
  real signing CA is a structurally different mode — Squid becomes the real
  TLS endpoint, decrypts, evaluates `http_access` against the actual
  request, and can answer a real HTTP 4xx instead of aborting an opaque
  tunnel. As a side effect this also gives Squid real SNI/CONNECT-mismatch
  detection, a capability `docs/security.md` currently says only Pipelock
  has.
- **Smokescreen** cannot do this at all — confirmed from its own upstream
  docs: it is structurally an opaque CONNECT tunnel with no cert-generation
  or decrypt code path. It stays destination-only, unaffected, and is
  excluded by design (not an oversight) from everything below.

The goal of this change: make TLS interception an **opt-in, off-by-default**
mode for pipelock and squid, with `ipl` owning the CA's whole lifecycle
(generate, persist, export, rotate), and CA *distribution* to
`project-sandbox` staying a manual, documented step — `project-sandbox` is
an external tool/repo not present in this checkout, so this stops at
`ipl ca export` producing a file to hand to it, the same way exporting
`HTTP_PROXY` is already a manual step today.

## Scope boundaries (decided, not open questions)

- Smokescreen: destination-only, forever, for this change. `ipl up
  --engine smokescreen` with interception on fails closed with a clear
  message rather than silently ignoring the setting.
- CA distribution: `ipl ca export --out <path>` writes the public cert only;
  installing it into a `project-sandbox` image's trust store is documented,
  not automated, in the new doc.
- Reachable through the existing `--engine` flag, not a new one. Off by
  default (`tls_interception = false` in `config.toml`).

## Design

### 1. `config.toml` gains one key

```toml
[policy]
allow = [...]
tls_interception = false   # opt-in; see docs/tls-interception.md
```

`policy/config.py::load_policy_config()` (the sole parser, already strict —
`reject_unknown()` at line 118 currently only permits `{"allow"}` in
`[policy]`) needs: the known-key set widened to `{"allow",
"tls_interception"}`, and `PolicyConfig` (line 27, currently `allow:
tuple[str, ...]` only) gains `tls_interception: bool = False`, parsed with a
type check (`isinstance(raw, bool)`, `Fail` otherwise) the same defensive
way `allow_list()` already validates its input. `config.toml`'s own header
comment (lines 9-12, "no TLS interception... are NOT configurable here") is
now wrong and must be rewritten in the same change.

### 2. New module `src/internet_proxy_locally/ca.py`

Owns the CA lifecycle, filesystem-only (no `Backend`/container dependency,
matching how `policy/validate.py` and `policy/config.py` stay pure and
therefore trivially unit-testable):

- `paths.py` gains `ca_dir() -> Path` returning `workspace_root() / "state"
  / "ca"` — a new, gitignored, host-specific directory (see `.gitignore`
  below). Follow `paths.py`'s existing one-function-one-question style.
- `ca_cert_path()` / `ca_key_path()`, `ca_present() -> bool`.
- `generate_ca(force: bool = False) -> None` — a P-256 ECDSA self-signed CA
  in PEM, via the new `cryptography` dependency
  (`cryptography.hazmat.primitives.asymmetric.ec` + `cryptography.x509`).
  Skip if already present unless `force=True` — mirror `images.py`'s
  `prepare_image()` skip/rebuild pattern exactly (same reasoning: generating
  on every `up` would invalidate whatever already trusts the old cert).
  Write the private key with `os.open(path, os.O_CREAT|os.O_WRONLY, 0o600)`
  before writing bytes — never `chmod` after the fact, which leaves a window
  where the key is world-readable.
- `export_ca_cert(destination: Path) -> None` — copies the **cert only**;
  `Fail`s if no CA exists yet (tell the user to run `ipl ca init`).

Add `cryptography` to `pyproject.toml` `dependencies` (with a one-line
why-comment matching the existing `jinja2`/`pyyaml` block) and run `uv lock`
(or `uv add cryptography`) to update `uv.lock`.

### 3. `spec.py`: CA mounts as their own thing, not `extra_config_file`

`ServiceSpec.mounts()` (lines 66-81) resolves `config_file`/
`extra_config_file` as **workspace-relative, checked-in** paths — CA
material is neither (it's generated, lives under `paths.ca_dir()`, outside
`workspace_root()`). Don't overload `mounts()`; add:

```python
supports_tls_interception: bool = False
ca_cert_mount: str = ""
ca_key_mount: str = ""


def ca_mounts(self) -> list[tuple[Path, str]]:
    if not self.supports_tls_interception:
        return []
    return [
        (ca.ca_cert_path(), self.ca_cert_mount),
        (ca.ca_key_path(), self.ca_key_mount),
    ]
```

Set on the `pipelock` and `squid` entries in `SERVICES` only:
- pipelock: `ca_cert_mount="/config/ca.pem"`, `ca_key_mount="/config/ca-key.pem"`
- squid: `ca_cert_mount="/etc/squid/ca.pem"`, `ca_key_mount="/etc/squid/ca-key.pem"`

`smokescreen`/`dnsfixture` keep the `False`/`""` defaults — this is what
makes the smokescreen fail-closed check in `lifecycle.py` (below) work
without any smokescreen-specific code.

### 4. Threading `tls_interception` through rendering (both lanes)

`policy/render.py::render_engine_policies()` (lines 103-133) is the single
function both `render_policies()` (operational, `cli/run.py`) and
`render_test_policies()` (lab lane, `lab/render.py`) call — add a
`tls_interception: bool = False` parameter, pass it into `render_template()`
as a Jinja variable. Because the Jinja env uses `StrictUndefined` (line 69
of `render.py`), **every** call site must supply it once the templates
reference it, or rendering crashes:

- `render_policies()` (`policy/render.py`): pass `config.tls_interception`
  from the already-loaded `PolicyConfig`.
- `render_test_policies()` (`lab/render.py`): `LabConfig` (in
  `lab/fixtures.py`) needs a `tls_interception: bool` field sourced from the
  same underlying `config.toml` (the operational `PolicyConfig`), the same
  way `LabConfig.allow` already carries the operational allowlist through to
  the test policy. Pass `config.tls_interception` into
  `render_engine_policies()` alongside `allow`/`allow_test`.

Update `render.py`'s module docstring — it currently claims "Nothing
security-critical is parameterized... `tls_interception: false`... are
literal text," which stops being true the moment this is a real variable.
Rewrite to describe the switch as a single on/off gate producing one of two
fixed, literal recipes — not a partially-parameterized feature.

### 5. Template changes

**`data/templates/pipelock.yaml.j2`** — replace the unconditional tail
(lines 39-40) with:

```jinja
{% if tls_interception %}
tls_interception:
  enabled: true
  ca_cert: "/config/ca.pem"
  ca_key: "/config/ca-key.pem"
  max_response_bytes: 5242880
{% else %}
tls_interception:
  enabled: false
{% endif %}
```

In-container paths are literal (matching `ca_cert_mount`/`ca_key_mount`
above) — not further templated, since a configurable path could point at
somewhere nothing is actually mounted. Fix the header comment at lines
13-14 ("TLS interception stays disabled for v1... Non-goals") which is
otherwise generated-false text baked into every rendered file.
`passthrough_domains` is explicitly **out of scope** for this change —
nothing in `config.toml` carries a passthrough list; don't add the key.

**`data/templates/squid.conf.j2`** — two conditional blocks:

```jinja
{% if tls_interception %}
http_port 3128 ssl-bump tls-cert=/etc/squid/ca.pem tls-key=/etc/squid/ca-key.pem generate-host-certificates=on dynamic_cert_mem_cache_size=4MB
sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/ssl_db -M 4MB
sslcrtd_children 8
{% else %}
http_port 3128
{% endif %}
```

...and, after the allowlist/deny-all block (near where the current
"Not configured here" footer explains the *absence* of `ssl_bump`):

```jinja
{% if tls_interception %}
acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all
{% endif %}
```

`ssl_bump peek step1` **must always be paired with** `ssl_bump bump all` —
an orphaned `peek` with no `bump` is exactly the crashing shape from
`squid-peek-rejected`; this pairing is enforced again independently in
`validate.py` (below) so a hand-edit can't reintroduce it. Rewrite the
top-of-file comment (lines 19-22) and the "Not configured here" footer
(lines 148-154), both of which currently state `ssl_bump` is categorically
absent.

**Open verification items** (do not guess further — confirm against the
built image before finalizing these lines): the exact Squid 6.x `http_port`
flag spelling (`tls-cert=`/`tls-key=` vs. older `cert=`), and the real path
to `security_file_certgen` in Alpine's `squid` package (check `apk info -L
squid` or a build-time `find` inside the image).

### 6. `policy/validate.py`: allow either state, forbid partial ones

`validate_policy_text()` doesn't need to know what `config.toml` *intends*
— that drift is already caught separately by `ipl policy --check`
(`run_policy_command()` in `cli/common.py`). Its job stays "is this text
well-formed," per its own docstring. Replace the current hard bans:

- Pipelock (lines 282-288, currently `_require(ti.get("enabled") is
  False, ...)`): accept `True` if `ca_cert` and `ca_key` are both non-empty;
  accept `False` unconditionally as today; anything else is a problem.
- Squid (lines 367-372, currently bans any `ssl_bump ... bump`): if **any**
  `ssl_bump` directive is present, require the whole recipe — `http_port
  ... ssl-bump ... tls-cert=` present, `generate-host-certificates=on`
  present, an `sslcrtd_program` line present, **both** `ssl_bump peek
  step1` and `ssl_bump bump all` present. Word the failure message for a
  missing `bump all` explicitly against the historical crash ("peek without
  bump is the configuration that crashed Squid — see docs/findings.md").

### 7. `lifecycle.py`: mounts + fail-closed gates

`start_engine()` (lines 57-130) gains a `tls_interception: bool = False`
parameter. Where it currently builds `mounts=spec.mounts(config_path)`
(line 102):

```python
mounts = spec.mounts(config_path)
if tls_interception:
    if not spec.supports_tls_interception:
        raise Fail(
            f"{engine} does not support TLS interception "
            "(pipelock and squid do; set tls_interception = false or switch engine)"
        )
    if not ca.ca_present():
        raise Fail("tls_interception is enabled but no CA exists — run `ipl ca init`")
    mounts += spec.ca_mounts()
```

This single check is what makes Smokescreen's exclusion fail closed at
`up`-time with no smokescreen-specific code anywhere else — it falls out of
`supports_tls_interception` being `False` on that one `ServiceSpec` entry.

### 8. CLI wiring (`cli/run.py`, `cli/common.py`, and `cli/lab.py` analog)

- `cli/common.py::run_up_command()` (lines 130-179) gains a
  `tls_interception: bool = False` parameter, passed straight to
  `start_engine(..., tls_interception=tls_interception)`.
- `cli/run.py::cmd_up()` loads `load_policy_config()` once and passes
  `.tls_interception` into `run_up_command(...)`. `cli/lab.py`'s `cmd_up`
  analog does the same from `load_lab_config().tls_interception`.
- `cli/run.py::cmd_setup()` (lines 66-96): after the existing
  `report_synced(sync_policies(), _POLICY_SOURCE)`, add: if
  `load_policy_config().tls_interception` and not `ca.ca_present()`, call
  `ca.generate_ca()` and print where it landed. Gated strictly on the
  config flag — a repo that never opts in gets zero new files, identical
  footprint to today.
- New subcommand group in `cli/run.py::build_parser()`, matching the
  existing `sub.add_parser(...).set_defaults(func=...)` pattern exactly:

  ```
  ipl ca init [--rebuild]     # generate if absent; --rebuild forces
  ipl ca status                # present/absent, cert subject + expiry
  ipl ca export --out <path>   # public cert only, never the key
  ipl ca rotate                # generate_ca(force=True) under a clearer verb
  ```

  `rotate` is not a new mechanism — it's `init --rebuild` under a verb that
  states the real consequence (invalidates trust everywhere the old cert
  was installed); implement it as a thin alias so there is exactly one
  code path (`generate_ca`) for "make a new CA."

### 9. Squid image

`data/images/squid/Dockerfile`: before `USER squid` (line 41), add the
cert-DB init (unconditional — cheap, and it lets one image serve both
`tls_interception` states, so no tag fork needed for that reason):

```dockerfile
RUN security_file_certgen -c -s /var/lib/ssl_db -M 4MB \
    && chown -R squid:squid /var/lib/ssl_db
```

Bump `SQUID_IMAGE` in `images.py` (currently `6.12-r0`) since the build
context changed and `prepare_image()` skips a build when the tag is already
present — a stale cached image would silently lack the cert DB. Add a
Dockerfile comment explaining the suffix is a local build revision, not a
new upstream apk release, so it isn't misread against the apk pin. Confirm
`security_file_certgen`'s real path per the open item in §5 before
finalizing this line.

Pipelock's Dockerfile needs no change — the binary already supports
`tls_interception`; only the mounted CA and rendered YAML change.

### 10. `.gitignore`

```gitignore
# state/ca/ is the mirror image of results/ above: the CA private key is
# generated once per checkout and trusted by that checkout's sandboxes
# specifically. Unlike config/*, it is never reviewed in a diff —
# committing it would make a private key a shared secret.
state/
```

### 11. Docs

- New `docs/tls-interception.md`: what turning this on changes in the
  threat model (this becomes a real MITM for allowlisted HTTPS
  destinations; the host now custodies a private key); the `ipl ca`
  lifecycle including an explicit rotation/compromise runbook; the manual
  recipe for a `project-sandbox` Dockerfile (`ipl ca export --out ...`, copy
  in, `update-ca-certificates`) stated plainly as manual/undelegated;
  per-engine notes (pipelock's `max_response_bytes` cap; squid's
  peek+bump recipe and its new SNI-mismatch detection); Smokescreen's
  exclusion with the structural reason cited from its own docs.
- `docs/security.md`: rewrite "Non-goals" (currently states this is
  categorically out of scope) to describe it as opt-in/off-by-default,
  pointing at the new doc; update "What it does not defend against"
  (exfiltration-to-allowed-destination bullet is now conditional, not
  absolute); update the fail-closed properties list (line 75's blanket
  "`tls_interception.enabled: true`... forbidden" is no longer accurate —
  describe the new conditional rule instead; add the CA-missing-refusal and
  key-permission bullets); update the CONNECT-tunnel-abuse-detection line to
  note Squid gains it too, conditionally, when bumping.
- `docs/policy.md`: add `tls_interception` to the (short) list of things
  `config.toml` actually controls.
- `docs/findings.md`: **do not delete** "Rejected: tunnel peeking on
  Squid" (lines 417-451) — it's a real historical record. Add a short
  addendum after it clarifying that finding was specifically about
  peek+splice *without* a CA, and that full bump *with* a CA is the
  different, now-shipped mode.
- `config.toml`'s header comment and `README.md` (command table + engine
  capability notes) — both need the new `ipl ca` surface described.

### 12. Tests

New `tests/test_ca.py` (pure filesystem, no container/subprocess — same
isolation `policy/validate.py`'s tests get):
- generates a valid P-256 ECDSA cert+key (round-trip through
  `cryptography`'s loaders, assert curve);
- idempotent without `force`, produces a new key with `force=True`;
- private key file is `0600`;
- `export_ca_cert()` copies cert bytes only and `Fail`s with no CA present.

`tests/test_runpy.py` additions/replacements (mirroring existing style —
see `test_pipelock_policy_rejects_tls_interception` line 617 and
`test_squid_policy_rejects_tls_interception` line 782, both of which assert
behavior this change removes and must be replaced, not left in place):
- pipelock accepts `enabled: true` with both CA paths set, rejects it with
  either path empty;
- squid accepts a fully-formed `ssl_bump` recipe, rejects an orphaned
  `peek` without `bump all`, rejects `ssl_bump` present without
  `tls-cert=` on the `http_port` line;
- a render+validate round trip with `tls_interception=True` for both
  pipelock and squid (proving template output and validator agree, not
  just that hand-written text passes);
- CLI-level (subprocess, `FAKE_BACKEND` harness): `up` fails closed on
  `--engine smokescreen` with interception on; `up` fails closed with
  interception on and no CA generated; `up` mounts both CA files for
  pipelock/squid when enabled (assert on the `backend_log()` run line, the
  same way `test_up_squid_mounts_policy_over_the_stock_config` does);
  `ipl ca init`/`--rebuild`/`export` wiring.

`tests/test_lab.py`: extend the existing superset-policy test coverage to
assert the lab lane's rendered `.test` config agrees with the operational
one on `tls_interception`, once `LabConfig` carries the field.

## Suggested jj revision split (per CLAUDE.md)

1. `ca.py` + `paths.ca_dir()` + `.gitignore` + `cryptography` dependency +
   `tests/test_ca.py` — CA lifecycle in isolation.
2. `policy/config.py` (`tls_interception` field) + `spec.py` (new
   `ServiceSpec` fields/`ca_mounts()`) + `policy/render.py` +
   `lab/fixtures.py`/`lab/render.py` threading + both templates +
   `policy/validate.py` + the render/validate tests — fully testable
   without a container runtime.
3. `lifecycle.py` + `cli/common.py` + `cli/run.py` + `cli/lab.py` (`ipl ca`
   subcommands, `cmd_setup`/`cmd_up` wiring) + CLI-level tests.
4. `data/images/squid/Dockerfile` + `images.py` tag bump — isolated since
   it needs the external verification from §5/§9 before it's done.
5. Docs, last, once the shipped shape (exact CLI verbs, exact config keys)
   is settled.

Run `uv run ruff check . && uv run ruff format --check . && uv run ty
check` before each revision is described, per CLAUDE.md.

## Verification

- `uv run python -m unittest discover -s tests -t .` — the new
  `test_ca.py` and the `test_runpy.py`/`test_lab.py` additions run here
  with no container runtime needed (CA generation and render/validate are
  pure Python).
- With a real backend available: `ipl policy` (set `tls_interception =
  true` in `config.toml` first) to confirm both templates render and
  validate; `ipl setup` to confirm the CA auto-generates and the squid
  image builds with the cert-DB init; `ipl --engine pipelock up` and
  `ipl --engine squid up` to confirm both start healthy with the CA
  mounted; `ipl --engine smokescreen up` to confirm the fail-closed
  message.
- End-to-end interception check (manual, not scripted by this plan): with
  `ipl ca export --out ca.pem`, install it as a trusted CA in a local
  client (e.g. `curl --cacert ca.pem`), point it at the running proxy, and
  confirm an allowlisted HTTPS request succeeds while the engine's logs
  show the decrypted request — and that a denied host now gets a real
  4xx instead of a hung/reset connection.
- `ipl-lab up && ipl-lab check` with `tls_interception = true` in the test
  policy, to confirm the adversarial suite still passes and that Squid's
  SNI-mismatch check (`test_connect_sni_mismatch.py`-equivalent in the
  `full` group) now catches what it previously couldn't.
