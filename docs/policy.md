# Internet policy

One logical policy, written once. **`config.toml` at the repository root
is the source of truth**; `config/pipelock.yaml`, `config/smokescreen.yaml`
and `config/squid.conf` (and the three `.test` variants), plus
`config/dns-fixture.hosts`, are rendered from it by `./run.py` through the
templates in `templates/`, and carry a "GENERATED FILE — do not edit"
banner saying so.

`setup`, `up` and `restart` regenerate them first, so the policy a
container runs is always the one `config.toml` states. The generated text
is put through `validate_policy_file()` *before* it is written, so a bad
`config.toml` fails without replacing a working config. `./run.py policy
--check` reports drift as a diff and exits 1 without writing — the check
to run in review.

This replaces "expressed three times, kept in sync by hand". The pairwise
`check_allowlist_sync()` warning is still there, but it is now a check on
the generator rather than on the reader: the three files cannot disagree
unless something rendered them wrong.

## Mode

```text
default: deny
```

Nothing is reachable unless a hostname on the allowlist matches, and the
resolved destination IP passes the SSRF checks below.

## Current allowlist

Written in `[policy].allow` in `config.toml`, in one of exactly two forms:

| Form | Means |
| --- | --- |
| `d` | that host, exactly |
| `*.d` | subdomains of `d`, never the apex |

| Domain | Why |
| --- | --- |
| `github.com`, `*.github.com`, `*.githubusercontent.com` | git clone/fetch, raw file access |
| `pypi.org`, `files.pythonhosted.org` | Python packages |
| `registry.npmjs.org` | npm packages |

Deliberately small. Expand only from demonstrated requirements, one
reviewed change at a time.

`./run.py` refuses anything that is not one of the two forms above: an
address (`1.2.3.4`), a bare `.d` (Squid's own form, which silently covers
the apex too), a hand-written regex, a single label, or anything carrying
a scheme, port or path. An address-form entry is exactly what
`http_access deny ip_literal` exists to refuse — this policy allowlists by
name and never by address.

AI provider domains (OpenAI, Anthropic, …) are intentionally absent: AI
API traffic goes through Agentgateway, not this proxy.

## Rules (every engine)

* allowlist, never denylist;
* reject private IPv4 (RFC1918), loopback, link-local;
* reject cloud metadata addresses (`169.254.169.254` is covered by
  link-local blocking; every engine also checks it explicitly);
* reject private/link-local/loopback IPv6;
* validate the destination **after** DNS resolution — a public hostname
  resolving to a private address is rejected;
* protect against DNS rebinding (validation applies to the address the
  proxy actually connects to);
* rejected destinations are logged by the engine (docs/usage.md's logging
  section covers what each engine's lines contain).

## What is generated and what is not

Only domains are generated. Everything else in the three engine configs —
Squid's deny floors and their order, `cache deny all`, `deny_info`,
Pipelock's `sni_verification` / `sni_require_tls`, `tls_interception:
false`, Smokescreen's `action: enforce` — is literal text in
`templates/*.j2`, unparameterized and unreachable from `config.toml`.
Changing a rule means editing a template and reviewing that diff, which is
the same review it needed before.

## Where each rule lives

Pipelock and Smokescreen implement the IP-layer floors in engine code:
the configuration turns them on (or, in the case of
`--unsafe-allow-private-ranges`, would turn them off — which `run.py`
refuses). Squid has no such built-in, so the floors are written out as
`dst` ACLs in `config/squid.conf` and placed **above** the allowlist,
because `http_access` is first-match-wins.

That is a real difference in review burden, so it is checked rather than
trusted. `validate_policy_file()` rejects a Squid policy that

* does not end in `http_access deny all`, or contains `http_access allow all`;
* places `http_access deny private_ip` / `deny metadata_ip` after the
  first `http_access allow`;
* omits any of the required ranges in `REQUIRED_SQUID_DENY_RANGES`
  (RFC1918, loopback, link-local, the metadata address, IPv6
  loopback/ULA/link-local);
* places `http_access deny ip_literal` after the first `http_access allow`,
  or omits it. Squid retries a `dstdomain` miss as a **reverse** lookup, so
  an address-form destination that matches nothing gets a second chance
  under whatever name its PTR claims. Refusing address-form destinations
  before the allowlist is the only fix Squid offers, and it costs nothing:
  this policy allowlists by hostname and never by address
  (docs/engines.md);
* enables `ssl_bump ... bump` (TLS interception);
* drops `cache deny all`;
* has a `deny_info` naming an ACL the file does not define, gives one ACL
  two denial pages, or drops one of the five required page-to-ACL pairs in
  `REQUIRED_SQUID_DENY_INFO`. Squid says nothing about a `deny_info` whose
  ACL no longer exists — the page simply never fires and the denial falls
  back to the stock "Access control configuration prevents your request"
  page, which carries no reason at all. Renaming `private_ip` without
  updating its page would therefore turn every SSRF denial into `unknown`
  while leaving a config that starts, validates and denies exactly the same
  requests. `check_squid_error_pages()` additionally requires each named
  page to exist in `images/squid/errors`, since a missing one answers
  `Internal Error: Missing Template`.

## Wildcards in Squid

Squid refuses to start when a `dstdomain` list holds both `d` and `.d`
("'.d' is a subdomain of 'd'"), and its `.d` form matches the apex as
well — so it cannot express `*.d` the way the shared policy means it. The
two shared forms therefore map onto two ACLs:

| Shared form | Squid |
| --- | --- |
| `d` | `acl allowlist_exact dstdomain d` |
| `*.d` | `acl allowlist_wild dstdom_regex -i \.d$` |

The anchored regex matches subdomains only, never the apex, which is
exactly `*.d`. The `squid_wild` template filter writes that form and
`_squid_regex_to_glob()` reads it back; a test asserts they are inverses,
so the generated file and the cross-engine comparison cannot disagree
about what a wildcard means. `_squid_regex_to_glob()` leaves any pattern
that is not that exact shape untranslated, so a hand-written regex still
shows up as drift.

## Changing the policy

1. Add or remove one entry in `[policy].allow` in `config.toml`, with a
   comment saying why.
2. `./run.py policy` — regenerates the six engine configs and the DNS
   fixture's records (or go straight to step 3, which does it too).
3. `./run.py up` — regenerates, validates, and recreates the container.
4. `./run.py check --quick` — confirms allow/deny behavior.
5. Commit `config.toml` **and** the regenerated `config/*` files. Review
   both: the generated diff is what actually ships, and it is small enough
   to read. `./run.py policy --check` fails if they were not regenerated.

`project-sandbox --extra-domain` never mutates these files; there is no
dynamic policy channel by design.

## Test policy

`config/*.test.yaml` and `config/squid.test.conf` are rendered from the
same templates with the `[policy.test].allow` entries appended, so the
test policy is a strict superset of the real one by construction rather
than by care — a test asserts it. They additionally allowlist
`*.nip.io` and `*.sslip.io` — wildcard DNS services whose hostnames
resolve to attacker-chosen IPs — plus the names served by the local DNS
fixture: the `*.fixture.test` records for mixed answers, and the
`*.rebind.fixture.test` zone for rebinding. They exist **only** so
`./run.py check --full` can prove that the IP-layer SSRF floors hold even
for allowlisted hostnames. Start them with `./run.py up --test-policy`,
which also starts the fixture; a normal `./run.py up` returns to the real
policy and removes it.

### The fixture records

`[fixture]` in `config.toml` is the source of truth for what the local DNS
fixture serves, and `config/dns-fixture.hosts` is rendered from it like
every other generated file:

```toml
[fixture]
control     = "public-only.fixture.test"   # one public address; must establish
rebind_zone = "rebind.fixture.test"        # served by images/dnsfixture/rebind.py
ptr_address = "1.0.0.1"                    # answers PTR with ptr_claims
ptr_claims  = "pypi.org"

[fixture.records]
"public-only.fixture.test"         = ["9.9.9.9"]
"mixed-public-first.fixture.test"  = ["9.9.9.9", "10.0.0.1"]
"mixed-private-first.fixture.test" = ["10.0.0.1", "9.9.9.9"]
```

Loading it cross-checks the two lists against each other, because a
half-landed edit here does not fail loudly — it produces a check that
silently grades nothing:

* every record name must be allowlisted by `[policy.test].allow`, or the
  engine would refuse it by *name* and the row would measure the allowlist
  instead of the address check it is named after;
* every `.test` name in `[policy.test].allow` must have a record behind it
  (or be `*.<rebind_zone>`), or it resolves to NXDOMAIN and its check
  skips;
* no fixture name — record or rebinding zone — may be reachable from
  `[policy].allow`, by wildcard or otherwise. In the real policy it would
  be a shipped allowlist entry for a name that resolves to whatever the
  fixture says, private addresses included, and `up` without
  `--test-policy` does not even start the fixture;
* the control must resolve to exactly one public address — it is the probe
  that proves the fixture is live, and it cannot do that job if it could
  fail for any other reason;
* every other record must mix one public and one private address, and both
  orderings must appear, or an engine that validates only the first answer
  would not be distinguished from one that validates all of them;
* `ptr_claims` must be an exact entry in the *real* `[policy].allow` —
  `ptr-allowlist` asks whether a PTR record can satisfy the allowlist that
  actually ships;
* `ptr_address` must not be one of the record addresses. dnsmasq
  synthesizes PTR records from the records it serves, and Squid retries an
  address-form destination as a reverse lookup, so a shared address let a
  bare-IP CONNECT satisfy the allowlist under a fixture name.

What is left hand-synced is the code that reads these names —
`MIXED_FIXTURE_*` / `REBIND_ZONE` / `PTR_FIXTURE_*` in `checks/egress.py`
and the literals in `images/dnsfixture/rebind.py` — and tests assert both
against `config.toml` rather than against each other.
