# Internet policy

One logical policy, written once. **`config.toml` at the repository root
is the source of truth**; `config/pipelock.yaml`, `config/smokescreen.yaml`
and `config/squid.conf` (and the three `.test` variants) are rendered from
it by `./run.py` through the templates in `templates/`, and carry a
"GENERATED FILE — do not edit" banner saying so.

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
  (docs/comparison.md);
* enables `ssl_bump ... bump` (TLS interception);
* drops `cache deny all`.

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
2. `./run.py policy` — regenerates all six engine configs (or go straight
   to step 3, which does it too).
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
fixture: three `*.fixture.test` records for mixed answers, and the
`*.rebind.fixture.test` zone for rebinding. They exist **only**
so `./run.py check --full` can prove that the IP-layer SSRF floors hold
even for allowlisted hostnames. Start them with
`./run.py up --test-policy`, which also starts the fixture; a normal
`./run.py up` returns to the real policy and removes it.

The fixture names must stay in sync three ways: the records in
`config/dns-fixture.hosts` (and the `rebind.fixture.test` zone in
`images/dnsfixture/rebind.py`), the `MIXED_FIXTURE_*` / `REBIND_ZONE`
constants in `checks/egress.py`, and `[policy.test].allow` in
`config.toml`. The third is now one list instead of three, but it is still
hand-synced against the first two: a test checks the records against the
checker's constants, and nothing yet checks either against `config.toml`
(TODO.md §3).
