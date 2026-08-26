# Internet policy

One logical policy, expressed three times: `config/pipelock.yaml`,
`config/smokescreen.yaml` and `config/squid.conf` are the source of truth.
`./run.py setup` (and every `up`) validates all three files and warns
when their allowlists drift apart — compared pairwise, since none of them
is the master.

## Mode

```text
default: deny
```

Nothing is reachable unless a hostname on the allowlist matches, and the
resolved destination IP passes the SSRF checks below.

## Current allowlist

| Domain | Why |
| --- | --- |
| `github.com`, `*.github.com`, `*.githubusercontent.com` | git clone/fetch, raw file access |
| `pypi.org`, `files.pythonhosted.org` | Python packages |
| `registry.npmjs.org` | npm packages |

Deliberately small. Expand only from demonstrated requirements, one
reviewed change at a time.

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
exactly `*.d`. `run.py` reads both back into the shared forms for the
cross-engine sync check, and leaves any pattern that is not that exact
shape untranslated so a hand-written regex shows up as drift.

## Changing the policy

1. Edit **all three** of `config/pipelock.yaml`,
   `config/smokescreen.yaml` and `config/squid.conf` (and the
   `.test.yaml` / `.test.conf` variants, which must stay a strict superset
   that only adds the DNS fixture domains).
2. `./run.py setup` — validates the files and the cross-engine sync.
3. `./run.py up` — recreates the container with the new policy.
4. `./run.py check --quick` — confirms allow/deny behavior.
5. Commit the change. `project-sandbox --extra-domain` never mutates these
   files; there is no dynamic policy channel by design.

## Test policy

`config/*.test.yaml` and `config/squid.test.conf` additionally allowlist
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
constants in `checks/egress.py`, and the allowlists in all three test
policies. A test checks the records against the checker's constants, and
the allowlist-sync check covers the third.
