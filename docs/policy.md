# Internet policy

One logical policy, written once. **`config.toml` at the repository root is
the source of truth**; `config/pipelock.yaml`, `config/smokescreen.yaml`
and `config/squid.conf` are rendered from it by `ipl` through the
templates in `data/templates/`, and carry a "GENERATED FILE — do not edit"
banner saying so.

`setup`, `up` and `restart` regenerate them first, so the policy a
container runs is always the one `config.toml` states. `config.toml` is
parsed and validated before rendering, so a bad source fails without
replacing a working config.

The adversarial test policy is a separate file in a separate lane
(`data/lab/fixtures.toml`, [lab.md](lab.md)); `ipl` never reads it.

## Mode

```text
default: deny
```

Nothing is reachable unless a hostname on the allowlist matches, and the
resolved destination IP passes the SSRF checks below.

## The allowlist

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

`ipl` refuses anything that is not one of the two forms above: an
address (`1.2.3.4`), a bare `.d` (Squid's own form, which silently covers
the apex too), a hand-written regex, a single label, or anything carrying a
scheme, port or path. An address-form entry is exactly what `http_access
deny ip_literal` exists to refuse — this policy allowlists by name and
never by address ([findings.md](findings.md) §5).

AI provider domains (OpenAI, Anthropic, …) are intentionally absent: AI API
traffic goes through Agentgateway, not this proxy.

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
* rejected destinations are logged by the engine.

Two of these are not equally true on every engine. Smokescreen allows a
name that resolves to one public and one private address, and the three
engines defend against rebinding by two different mechanisms — both
measured, both in [findings.md](findings.md) §2 and §3. Where the engines
differ in *how* a rule is enforced rather than whether it is,
[findings.md](findings.md) §4 has it.

## What is generated and what is not

Domains, and one on/off switch, are generated. Everything else in the
three engine configs — Squid's deny floors and their order,
`cache deny all`, `deny_info`, Pipelock's `sni_verification` /
`sni_require_tls`, Smokescreen's `action: enforce` — is literal text in
`data/templates/*.j2`, unparameterized and unreachable from `config.toml`.
Changing a rule means editing a template and reviewing that diff, which is
the same review it needed before.

The one switch is `[policy].tls_interception` (default `false`): opt-in
TLS interception for Pipelock and Squid, off by default — see
[tls-interception.md](tls-interception.md) before turning it on. It is
still not a parameter in the sense the allowlist is: the generator picks
between exactly two fixed, literal recipes per engine rather than filling
in a value. The template tests cover both recipes.

One file is neither generated nor templated: `config/smokescreen.conf.yaml`
holds `allow_missing_role: true`, the Smokescreen *daemon* setting (as
opposed to the egress policy in `config/smokescreen.yaml`, passed
separately via `--egress-acl-file`). It exists only because
`allow_missing_role` has no CLI equivalent. v1 runs no client TLS, so every
request carries no role; without this, Smokescreen rejects each one before
the ACL is even consulted (`"Unable to get role for request"`) and the
`default` service is never reached. This does not weaken the policy — a
missing role resolves to the empty role, which matches no named service and
falls through to the `default enforce` rule.

## Changing the policy

1. Edit `[policy].allow` in `config.toml`.
2. Run `ipl up` to regenerate configs and start the proxy.
3. Review the diff to `config/*` — that is the change that ships.
4. Commit `config.toml` and the generated files together.
5. `ipl check` to confirm the live proxy behaves as intended.

Removing a domain is the same loop. Nothing caches policy: `up` recreates
the container, and Squid additionally runs `cache deny all`, so a response
nobody re-authorized cannot be served.
