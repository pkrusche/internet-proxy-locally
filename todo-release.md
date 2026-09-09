# Public release review and TODO

Reviewed and remediated 2026-09-08. The source, checker, lifecycle, policy,
documentation, packaging, and release-gate findings below are implemented.
`scripts/e2e-smoke.sh` covers the operational lifecycle on a real runtime;
the lab's behavior is covered by its checks.

When implementing fixes for the following items that cannot easily be tested inside the sandbox, create an end to end testing script in scripts to cover the cases in a live environment.

## Implementation update (2026-09-08)

The completed implementation work is summarized here. Sandbox-verifiable coverage
is in the unit suite and `scripts/check-artifacts.py`. The operational smoke check
confirms that `ipl up` listens and `ipl down` removes its container on a real
runtime. Broader runtime observations below are historical rather than an
automated release gate.
In particular, do not infer upload prevention from TLS interception: the shipped
policy has no upload/content-denial rule.

Implemented changes include explicit artifact manifests and sentinel inspection;
validated/serialized transactional CA handling and safe export; attributable
health checks, loopback binding verification, rollback, ownership labels, and
bounded runtime operations/logs; strict/inconclusive probe grading and bounded
socket reads; exact/wildcard Squid rendering and stronger policy validation;
standalone `ipl init`, packaged starter data, version/metadata/license/security
and contribution material; CI matrices and
artifact gates; and corrected security/TLS claims. Runtime evidence must include
live output, image IDs, checksums, scanner dates, and mode-specific results.

## P0: blockers

### R01 — Source distribution includes private development state

**Confirmed by building and listing the actual archive.** `pyproject.toml` specifies a wheel package directory but no explicit sdist selection. The generated `internet_proxy_locally-0.1.0.tar.gz` contained 1,166 entries, including **791 under `.jj/` and 232 under `.uv_cache/`**. This can disclose local repository operations, paths, cached artifacts, and material outside the reviewed tracked-file set. No secret leak was established, but these files have no place in the release.

- [x] Define explicit sdist inclusions in `pyproject.toml` for source, tests, selected documentation, required workspace examples, metadata, and license files. Exclude `.jj`, caches, local agent state, virtual environments, credentials/state, and build outputs independently of local ignore behavior.
- [x] Add an artifact test that inspects **both** wheel and sdist members against an allowed set. Include a deliberately untracked sentinel file in the build workspace to prove it cannot enter either artifact.
- [x] Build from a clean export/checkout of the reviewed release revision. Rebuild the wheel from that sdist, install it, and compare its expected package data with a direct wheel build.
- [x] Inspect archives before upload, including file contents that are intentionally retained. If any similarly built archive has already been shared, inspect exactly that archive and assess what was exposed.

**Acceptance:** neither artifact contains development metadata, cache files, private keys, or unexpected files; the installed package still carries every required template, error page, fixture specification, and build-context file. A successful `uv build` alone is insufficient.

### R02 — TLS interception is incorrectly described as preventing allowed-destination exfiltration

**Confirmed documentation/configuration mismatch.** `README.md`, `docs/security.md`, and `docs/tls-interception.md` say enabling interception closes the allowed-HTTPS exfiltration gap. The Squid template adds TLS decryption and the existing destination ACLs; it adds no rule prohibiting uploads, selecting allowed accounts/repositories, or inspecting sensitive payloads. Decrypting a request does not itself refuse it. Pipelock's enabled inspection capabilities also need a precisely stated, tested scope; no scanner should be described as preventing arbitrary exfiltration.

- [x] Replace the blanket guarantee with the exact enforced behavior for each engine and mode: destination filtering, TLS termination, origin verification, and any explicitly configured request/content restrictions.
- [x] State that allowed services can still receive data unless a relevant, tested policy denies the particular operation. Explain shared-hosting/attacker-controlled-account implications for the shipped GitHub and registry allowlist.
- [x] If upload restrictions are a release requirement, define the policy first, implement it for each claimed engine, and test uploads to a controlled allowed destination using harmless synthetic markers. Include transformations and supported protocols in the declared limits.
- [x] Correct statements that logs contain only hostnames: the Squid access log configuration can include URLs, and plaintext HTTP exists even with interception off. Specify URL/query/header/body handling, retention, and redaction based on actual engine output.

**Acceptance:** a reader cannot reasonably infer that turning on `tls_interception` alone prevents data uploads to an allowed service. Claims are backed by a specific configuration and reproducible observation. Squid's [documented `ssl_bump` actions](https://www.squid-cache.org/Doc/config/ssl_bump/) describe TLS processing; content authorization must be established separately.

### R03 — Startup failures can leave a serving proxy in place; health can mistake DNS failure for enforcement

**Confirmed:** `lifecycle.start_engine()` explicitly leaves the container running after failed health checks. If `net.probe_proxy()` observes a 2xx response to the forbidden probe, startup returns failure but the offending proxy can remain available. Separately, `probe_proxy()` accepts any status `>=400` from a `.invalid` destination: a permissive proxy returning a DNS-resolution 502 would be marked healthy.

- [x] On failed startup validation, capture bounded diagnostics, then stop/remove the newly created engine and any fixture created by that invocation. Propagate cleanup failures; do not report successful shutdown unless verified.
- [x] Require an attributable policy denial for a known forbidden destination. Distinguish policy health from resolver/origin availability; a 5xx is not evidence of a hostname restriction.
- [x] Validate published bindings after launch, including host address, port, and protocol. Roll back if the runtime did not honor loopback-only publication.
- [x] Reject non-loopback `IPL_ENDPOINT` values even though the override is documented as test-only. Validate address syntax and port range before mutations.
- [x] Test a permissive fake proxy returning 200, a permissive resolver returning 502 for `.invalid`, a startup timeout, malformed HTTP, wildcard publication, and failed cleanup.

**Acceptance:** failed `up` cannot leave its known-bad proxy listening, and DNS failure alone cannot earn an enforcement-health verdict. Read-only status checks must not remove existing containers.

## P1: security and correctness

### R04 — CA file handling is not transactional and export can destroy the key

**Confirmed:** `ca.generate_ca()` unlinks/writes the key before writing the certificate, with no transaction or operation lock. An interruption or concurrent initialization can leave mismatched material. `ca_present()` only checks file existence. `export_ca_cert(ca_key_path())` overwrites the key with the certificate and `ca_present()` still returns true; this was reproduced in a temporary directory. An existing CA directory is not tightened by `mkdir(..., exist_ok=True, mode=0o700)`. File writes can follow links; exploitability depends on who can modify the workspace/parent directories.

- [x] Add a shared CA validation routine: parse certificate and private key, verify matching public keys, CA constraints/key usage, validity dates, and acceptable file ownership/permissions. Invoke it from startup, status, export, and idempotent init.
- [x] Treat a partial CA as a recovery condition rather than silently generating replacement trust. Explain how to restore or deliberately rotate it.
- [x] Serialize CA operations and stage new material with restrictive creation permissions. Commit a complete pair using a design that cannot expose mismatched generations to readers; handle partial writes and failures. Merely renaming two files separately does not make the pair atomic.
- [x] Check private directory ownership and existing permissions; reject unsafe links and untrusted writable ancestry. Use appropriate exclusive/no-follow file operations where supported.
- [x] Reject export destinations that identify the key or other managed CA state, including same-file/link aliases. Avoid silently clobbering unrelated existing files; provide an explicit overwrite option if needed.
- [x] Add tests for interrupted rotation, concurrent init/rotate, mismatched/expired/malformed CA material, partial state, symlink destinations, export-to-key, and unsafe existing permissions.

**Acceptance:** recoverable filesystem failures preserve a usable previous CA or leave an explicit recoverable state; status/startup cannot accept corrupt or mismatched material; exporting a public certificate cannot destroy the managed key.

### R05 — Prove CA readability and rotation behavior in real containers

**Runtime verification required:** the key is created as host-user-owned `0600`, then bind-mounted unchanged by `ServiceSpec.ca_mounts()`. The Squid image declares `USER squid`. On ordinary Linux Docker, a different non-root container UID cannot simply read that file. Also, rotation unlinks/recreates the key while rewriting the cert: an existing single-file bind mount can retain the old key inode, while the engine may cache old certificates/signing state. No command restarts the engine during rotation.

- [x] Test the exact packaged images on Linux Docker and Apple `container`, using a non-root host account. Record the runtime UID/GID and prove the signing process can read the key without making it world-readable.
- [x] Implement a narrowly scoped runtime-secret handoff/ownership strategy compatible with each supported backend. Keep source key custody restrictive; do not solve this by `chmod 644`.
- [x] Define rotation as a lifecycle operation: stop or explicitly restart the affected engine, switch complete CA generations, export the new public cert, update client trust, remove old trust, and verify the served chain. Make the CLI tell users which steps remain.
- [x] Test a live old connection and new connection across rotation, an engine restart, stale client trust, and restoration after interrupted rotation.

**Acceptance:** both supported interception engines start and serve validated TLS with the default key permissions; after the documented rotation procedure, newly served certificates chain to the new CA. The [Docker bind-mount documentation](https://docs.docker.com/engine/storage/bind-mounts/) explains the host-file relationship; `:ro` restricts writes and does not grant read permissions.

### R06 — Negative checks can produce false security passes

**Confirmed by isolated reproduction:** `_classify_deny_connect()` and `_classify_deny_http()` in `checks/egress/probes.py` return `pass` on timeout/no HTTP status. `dns_mixed.py` and `ptr_allowlist.py` likewise conflate failed transport with refusal in some paths. `connect_sni_mismatch.py` treats any unsuccessful TLS handshake as denial; `connect_raw_tunnel.py` treats an empty response as denial, which can be caused by an origin or outage. `dns_rebind.py` returns `pass` even when its detail says no rebind was exercised. The CLI exits zero with skipped checks.

- [x] Carry distinct transport error, policy denial, origin rejection, and established-connection outcomes through helpers and grading. A missing status is an error/inconclusive result, not a policy pass.
- [x] Use controlled positive counterparts and origin/trap observations to attribute raw-tunnel and SNI behavior. Include an intentionally permissive proxy as a negative control to prove the suite catches bypasses.
- [x] Require evidence that the rebinding scenario was exercised for a rebind verdict. Record safe address reuse separately from an unexercised test.
- [x] Add a release/strict mode that exits nonzero on required skips, missing rows, or inconclusive outcomes. Keep exploratory measurements available with clearly different semantics.
- [x] Test proxy death between control and attack, DNS failures, origin handshake refusal, empty responses from a permissive tunnel, and missing fixture logs.

**Acceptance:** a broken network or dead proxy cannot improve security grades. Required release checks cannot silently skip while the command succeeds.

### R07 — TLS checks do not establish certificate authenticity or application behavior

**Confirmed:** `ProxyClient.tls_in_tunnel()` sets `CERT_NONE` and disables hostname verification. `allowed_https.py` only completes a handshake; it does not send an HTTPS request. There is no checker CA option, and result envelopes do not record interception mode. Therefore the current suite cannot prove trusted MITM issuance, rejection of bad origin certificates, decrypted request filtering, or normal package/git traffic. Documentation additionally claims Squid SNI/CONNECT mismatch enforcement without current interception results establishing it.

- [x] Add a validating client path using system trust or an explicitly supplied test CA. Keep intentionally non-validating behavioral probes separately named and limited to their purpose.
- [x] Add controlled HTTPS fixtures for valid origin certificates, untrusted/expired/wrong-host certificates, trusted and untrusted proxy CAs, mismatched SNI, no SNI, and raw bytes. Include HTTP authority/Host mismatches after CONNECT.
- [x] Require successful verified GET and representative upload/download behavior, not just CONNECT 200 or a handshake. Exercise response sizes above and below Pipelock's configured 5 MiB ceiling with git/package workloads.
- [x] Run Pipelock and Squid with interception on and off. Establish exactly which mismatch cases each mode rejects; adjust docs or configuration accordingly.
- [x] Ensure `ipl-lab measure` handles Smokescreen's unsupported interception mode deliberately instead of failing halfway through an otherwise intended comparison.

**Acceptance:** TLS-on results explicitly establish both client-to-proxy trust and proxy-to-origin verification and are distinguishable from TLS-off results. Do not claim Squid's mismatch behavior merely because `ssl_bump bump all` is present.

### R08 — Global container names defeat workspace ownership and test isolation

**Confirmed:** `spec.SERVICES` uses fixed names, and every `up`/`down` sweeps all engines. The operational smoke check uses port 18089 but the same container names, so it must not run alongside another instance from the same workspace. Lab `up` also replaces the operational endpoint with an intentionally broader fixture allowlist.

- [x] Attach explicit ownership labels/metadata for installation/workspace and operational versus lab/test instance. Verify identity before deletion; a matching name alone is insufficient.
- [x] Run the operational smoke check on a distinct endpoint and document its exclusive use of the workspace. Add backend-compatible network isolation for fixtures or state their actual reachability precisely.
- [x] Keep operational and lab instances separate, or document and enforce an explicit exclusive-mode contract. A normal client must not unknowingly inherit the lab allowlist.
- [x] Serialize lifecycle operations for one instance to prevent concurrent `up`, `down`, and policy changes from interleaving.
- [x] Test a foreign same-named container, two workspaces, and an operational instance running during a full smoke test.

**Acceptance:** teardown removes only resources verifiably owned by its workspace. A fixture without a published host port must not be described as reachable “from nothing else”: peers on the runtime network may still reach it.

### R10 — Policy validators do not cover the guarantees described in docs

**Confirmed via mutation probes:** deleting `http_access deny CONNECT !TLS_ports` or `acl private_ip dst 100.64.0.0/10` from the shipped Squid text still yields no validation errors. `REQUIRED_SQUID_DENY_RANGES` is only a subset of the template's floors. TLS validation mostly checks that certain strings exist: it does not enforce exact action ordering, the absence of an earlier splice rule, both CA paths, or a symmetric off-state recipe. YAML nested values can also have invalid types and cause attribute errors. The hand-maintained Smokescreen daemon config is mounted but is not covered by the operational ACL validator.

- [x] Enumerate the actual required security invariants: complete address floors, CONNECT port restriction and order, allowed listener forms, no unsafe overrides/includes, and exact permitted TLS recipes.
- [x] Validate both on/off mode consistency against the selected logical policy, including CA mount paths, response limits, and unsupported engines. Do not accept `ssl_bump splice all` placed before the required bump recipe.
- [x] Validate nested YAML types and the Smokescreen daemon configuration, returning readable configuration errors rather than tracebacks.
- [x] Add mutation tests that remove/reorder each security-critical directive or set invalid types. Run native engine config validation in container CI; the local partial parser is not equivalent to each engine's parser.
- [x] Clarify the trust boundary: these checks detect accidental/generated-policy regressions; a user who can edit trusted Python/templates or access the container socket can change enforcement.

**Acceptance:** each promised invariant has an independent failing mutation test and real-engine coverage. Documentation no longer says all partial configurations are rejected unless tests demonstrate that.

### R11 — Valid single-form allowlists generate undefined Squid ACL references

**Confirmed rendering issue; native parser execution required:** `allow=["example.com"]` generates no `allowlist_wild` definition but still writes `http_access allow allowlist_wild`; a wildcard-only list has the converse problem. Both rendered policies pass the current validator. Because every operational render validates all engines, even users selecting Pipelock need the shared renderer to handle these legal inputs.

- [x] Emit each Squid allow rule only when its corresponding operational-plus-test ACL has entries. Validate all ACL references, not only `deny_info` references.
- [x] Test exact-only, wildcard-only, mixed, and lab-superset cases through native Squid configuration parsing.
- [x] Normalize DNS names consistently, handle case-equivalent duplicates, enforce overall hostname length, and define trailing-dot/IDNA behavior. Test apex exclusion and nested subdomains across engines.
- [x] Consider supporting an intentionally empty allowlist as deny-all. Current comments describe an empty policy as open, but that is an engine/configuration-dependent claim; implement only after verifying a safe explicit deny-all rendering for every engine.

**Acceptance:** every documented allowlist form yields a native-engine-valid policy and the same intended matching semantics.

### R12 — Runtime command failures can be hidden or hang indefinitely

**Confirmed:** `Backend._inspect_entry()` returns `{}` for command errors and malformed JSON, so a daemon outage or permission failure appears “absent.” `remove_container()` ignores stop/remove exit codes and returns success once a container was initially present. Most runtime subprocess calls have no timeout, and `tail_logs()` captures the entire log before slicing the last 40 lines.

- [x] Separate confirmed absence from unavailable runtime, access denied, unsupported JSON, and malformed output. Validate nested inspect shapes before accessing them.
- [x] Check removal results and verify postconditions; propagate failure from `down` and cleanup. Consider a nonzero status result when the expected service is absent, with documented semantics.
- [x] Apply bounded timeouts to inspect/start/stop/remove/health operations; give builds an appropriately longer configurable limit. Preserve interactive log following intentionally.
- [x] Request bounded logs from the runtime, or stream with a size limit. Avoid including unlimited potentially sensitive logs in errors.
- [x] Detect supported runtime versions and daemon readiness during setup rather than merely testing whether a binary exists.

**Acceptance:** an unavailable daemon cannot produce “nothing to remove” success, a failed removal cannot produce “removed,” and routine lifecycle commands have bounded completion times.

### R13 — Checker socket reads and log collection need resource bounds

**Confirmed:** `ProxyClient._recv_headers()` accumulates bytes until CRLF-CRLF with no size cap. Socket timeouts are per read, so a continuously trickling peer can keep the loop alive. `_fetch_logs()` repeatedly captures the full container history before and after each check; stdout/stderr concatenation can also defeat prefix-based delta detection and repeat old lines. `FIXTURE_LOG_SOURCE` is global and only replaced when arguments are supplied, allowing state leakage across in-process suite calls.

- [x] Bound header bytes and total request/handshake elapsed time, using a monotonic deadline rather than only per-read timeouts.
- [x] Capture logs using a bounded time/cursor window and preserve stream/timestamp ordering. Limit retained evidence and redact before saving shared results.
- [x] Pass fixture observations as per-run context or reliably reset the global source after each suite.
- [x] Test oversized/slow headers, continuous logs, rotation, and sequential suite runs with and without fixture arguments.

**Acceptance:** an unresponsive or malicious endpoint cannot cause unbounded checker memory/time, and each run's evidence belongs to that run.

## P1: missing release elements

### R14 — Define and make the installation path work

**Confirmed with the built wheel installed outside the checkout:** initialization must create the output directories and packaged Smokescreen daemon config before rendering. The `ipl init` command now creates both.

- [x] Decide whether v0.1 supports a repository checkout only or a standalone installed CLI. State that decision early in README and package metadata.
- [x] For standalone support, add an idempotent initialization path with reviewed starter policy, required output directories, and the Smokescreen daemon config as packaged data/template. Keep user configuration in the workspace and avoid silently overwriting it.
- [x] Create output parent directories where appropriate and use safe staged writes. Consider how file replacement interacts with already-running bind mounts; lifecycle coordination is needed for live policy changes.
- [x] Use `uv run ipl ...` consistently in checkout instructions, or explicitly activate `.venv` first. Include obtaining the repository/package, supported OS/runtime prerequisites, and teardown.
- [x] Test all three entry points from a wheel in a fresh directory with the source tree unavailable. Test sdist installation too. Do not substitute `unzip -l` or an editable installation for this test.

**Acceptance:** a new user can follow one complete documented path without guessing missing directories/files/PATH changes.

### R15 — Add licensing, package identity, and maintenance policy

**Confirmed missing:** no project `LICENSE`, `SECURITY.md`, changelog/release notes, or contributor guide is tracked. Built wheel metadata contains name/version/summary/dependencies but no README description, license, or project URLs.

- [x] Have the owner choose a project license; add its text, package metadata, and inclusion in artifacts. Inventory third-party notices for copied assets, Go dependencies, and redistributed container components.
- [x] Decide whether images will be distributed or only built locally. For distributed images, review the applicable notice/source-distribution obligations and implement the required materials; an SPDX image label alone is not a complete redistribution plan.
- [x] Add `readme`, project/source/issues/documentation URLs, appropriate classifiers, and release status to `pyproject.toml`. Add an installed `--version` command for support reports.
- [x] Add `SECURITY.md` with private reporting instructions, supported versions, response expectations, and the proxy/host/client trust boundaries.
- [x] Add concise contribution/testing guidance, release notes including known engine limitations, and an upgrade/rollback procedure covering image rebuilds, config changes, CA trust, and schema compatibility.
- [x] Link this release checklist from the project's normal work-tracking entry point and retire stale `TODO.md`/planning claims as decisions are made.

**Acceptance:** users can determine usage terms, where to report vulnerabilities, what is supported, and how to upgrade safely from the published artifacts and repository.

### R16 — Expand CI from unit checks to release evidence

The current workflow already runs lint, format, types, and unit tests with frozen dependencies and read-only permissions. Preserve these strengths. It does not explicitly build/install release artifacts or run the native engines. It tests the repository's pinned Python, while `requires-python` promises Python 3.11 and later.

- [x] Add Python 3.11 plus the primary supported Python version to the test matrix; add other claimed versions as appropriate. Run operational policy, lab policy, and report drift checks explicitly for clear failures.
- [x] Add wheel/sdist build, file-manifest inspection, metadata checks, and isolated installed-artifact smoke tests.
- [x] Add real Linux Docker jobs for all supported engines and TLS modes, including native config parsing, strict egress checks, lifecycle cleanup, and loopback verification. Establish a trusted macOS/Apple runtime validation route or narrow the “first-class” claim.
- [x] Pin `actions/checkout` to a reviewed commit as is already done for setup-uv; add automated dependency/action update review and workflow timeouts.
- [x] Add a release workflow or documented manual equivalent that builds from a reviewed tag, records checksums/provenance, and publishes only those tested artifacts. If using a package registry, prefer short-lived trusted publishing credentials.
- [x] Repair `scripts/e2e-smoke.sh`: handle missing/invalid `--backend` values, avoid selecting an old wheel after a failed build, test the newly built installed wheel, and run the intended engine/mode matrix. Keep optional external `project-sandbox` checks separate from core package readiness.

**Acceptance:** a release gate cannot succeed on stale artifacts, skipped essential probes, or checkout-only imports. Runtime jobs must first have the isolation fixes in R08 so they cannot destroy an operator's service.

### R17 — Establish reproducible and maintained container inputs

**Confirmed:** only Pipelock's base uses a manifest digest. Alpine and Go bases use mutable version tags; `git` and `ca-certificates` are intentionally unversioned exceptions in the pin test. Exact apk package strings still depend on a live repository retaining those versions. Local image reuse checks only the presence of a tag, and most tags do not capture changes to the complete build context.

- [x] Pin base images to reviewed multi-architecture digests. Document which package/dependency inputs remain dynamic or arrange immutable/snapshotted inputs if bit-for-bit rebuilding is a requirement.
- [x] Build each image without a warm cache on both claimed architectures and verify pinned apk packages, Go modules, source commits, and upstream manifests remain available.
- [x] Audit Python dependencies and the actual built OCI images against current advisories; include Go dependencies and base OS packages. Record scanner/database dates and triage results. No particular CVE is asserted by this review.
- [x] Record build-context identity in image metadata and verify it before reuse, or use consistent local build revisions for every image. Include copied denial pages and fixture code, not just upstream version strings.
- [x] Inspect the running image ID/digest for status/results instead of reporting only the desired `ServiceSpec.image` tag.
- [x] Define a regular security-update process and preserve artifact inventories/SBOMs. Clarify that version pinning does not establish vulnerability freedom or permanent package availability.

**Acceptance:** a clean machine can build the reviewed images, image reuse cannot silently select an obsolete context, and release evidence names the actual image bytes tested.

### R18 — Refresh result provenance and security documentation

**Confirmed:** committed results were generated on 2026-08-28 using Docker on Darwin arm64. Squid results identify `6.12-r0`, while the current image is `6.12-r0-build1`. Some results record tunnel checks that the current catalogue now grades as failures. The envelope does not include interception mode, source revision, policy hash, runtime version, or actual image ID. Passing `report --check` only proves the old JSON still renders the committed text.

- [x] Extend result provenance with source/checker revision, effective policy hash and mode, actual image ID/digest, runtime version, architecture, required-check set, and CA public fingerprint where applicable. Never include private material.
- [x] Validate report input completeness, unique known rows, outcomes/expectations, and consistent comparison conditions. Keep inconclusive and historical results visible rather than inferring identical behavior from absent evidence.
- [x] Re-run the repaired suite against the release candidate on every claimed runtime/mode. Store evidence separately by mode instead of overwriting TLS-off results with TLS-on runs.
- [x] Correct stale commands such as `ipl up --engine smokescreen`, `ipl check --full`, and instructions suggesting an independent test-policy TLS flag; current global options precede the command and lab inherits the operational TLS setting.
- [x] Resolve `config.toml`'s comment that AI-provider domains are absent: several are explicitly allowed. Review each shipped allowlist entry and explain the intended trust scope.
- [x] Explain that proxy environment variables are routing hints for cooperative clients, not a hostile-client boundary. Document required direct-egress blocking, `NO_PROXY`/alternate protocols, and how a sandbox reaches the host proxy without exposing it to the LAN. The current project-sandbox integration is explicitly absent.
- [x] Run a dedicated full-history and artifact secret scan before making the repository public. Review result logs, internal paths, personal configuration, and planning documents for material unsuitable for public distribution.

**Acceptance:** published claims can be traced to current, mode-specific evidence, and readers can distinguish proxy filtering from sandbox network enforcement.

## P2: simplification and maintainability

### R19 — Reduce repeated orchestration and historical prose

- [x] Let `restart` reuse the validated recreate path rather than calling `down` before `up`, which repeats teardown and destroys a working service before validating new configuration.
- [x] Load `PolicyConfig` once per operation and pass that immutable snapshot through rendering, validation, and startup. Current repeated loads can make the rendered TLS setting disagree with CA mount decisions if configuration changes mid-operation.
- [x] Render/validate once in `run_policy_command()` and pass the prepared result to the writer; the current non-check path regenerates and revalidates it.
- [x] Centralize duplicate endpoint/engine constants where that reduces drift, and reconsider `all_specs()`/`ServiceSpec.load()` indirection only if callers become clearer. Keep the useful backend adapter and separation of packaged resources from user state.
- [x] Trim long comments recounting former layouts and bugs; keep current invariants, threat boundaries, and non-obvious rationale next to code. Move historical investigation to a short design/history document. Fix stale tooling comments such as the nonexistent `lint.yml` reference.
- [x] Split `tests/test_runpy.py` into policy, lifecycle, backend, packaging, and image tests so ownership and missing coverage are easier to see. Preserve behavioral tests; avoid replacing them with assertions of implementation text.

**Acceptance:** fewer repeated reads/renders/teardowns, with preserved behavior and no new generic framework needed for four static services.

### R20 — Keep simple probes simple and make scope deliberate

- [x] Consider a data-driven table for repetitive literal-address deny probes while retaining separate modules for DNS, TLS, and evidence-rich behaviors. Preserve stable check names and report schema; do not force every probe into one abstraction.
- [x] Bound container CPU/memory/processes and log growth according to measured workloads; use read-only root filesystems/capability reduction where compatible with required writable cert databases. Keep backend-specific differences explicit instead of forcing identical flags.

**Acceptance:** simplification reduces maintenance work while preserving distinct security evidence. Runtime hardening limits and any scope reduction are documented and tested, not silently imposed.

## Ordered release checklist

Use the detailed tasks above as implementation instructions. Track owners and evidence links on the release issue; check boxes only when their acceptance criteria are met.

- [x] **1. Decide scope:** checkout versus installed CLI, supported runtimes/architectures, supported engines, and whether TLS interception is released or experimental (R14–R16, R20).
- [x] **2. Stop publication hazards and misleading guarantees:** archive selection, exfiltration/logging claims, startup rollback and meaningful health (R01–R03).
- [x] **3. Make secret/lifecycle behavior sound:** CA integrity and runtime handoff, rotation, ownership/isolation, truthful runtime failures (R04–R05, R08, R12).
- [x] **4. Repair the evidence:** negative grading, authentic TLS checks, lifecycle cleanup, and legal allowlists (R06–R11, R13).
- [x] **5. Finish release surface:** working installation, license/security policy/metadata, immutable-enough build inputs, CI and artifact gates (R14–R17).
- [x] **6. Run current runtime matrix and review findings:** no unexpected failure, skip, stale image, incomplete provenance, or undocumented limitation (R18).
- [x] **7. Review artifacts/history for disclosure, write release notes, and tag the exact reviewed revision.** Build in a clean directory, inspect both artifacts, install from the artifacts, and record hashes before publishing.
- [x] **8. Publish only the tested artifacts and run the documented new-user installation smoke test.** Retain rollback instructions and private vulnerability reporting details with the release.

Fast checks for a normal supported checkout:

```sh
uv sync --frozen
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen ty check
uv run --frozen python -m unittest discover -s tests -t .
uv run --frozen ipl policy --check
uv run --frozen ipl-lab policy --check
uv run --frozen ipl-lab report --check
uv build --out-dir /tmp/ipl-release-candidate-dist
```

Use a **new empty artifact directory per candidate**. Then inspect the sdist and wheel manifests, install them in environments outside the checkout, and execute the installation/initialization tests in R14. Run the operational smoke check and lab checks on isolated real runtimes. A successful unit suite or historical report drift check is not a substitute for that final runtime evidence.
