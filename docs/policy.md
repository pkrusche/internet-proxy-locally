# Internet policy

One logical policy, expressed twice: `config/pipelock.yaml` and
`config/smokescreen.yaml` are the source of truth. `./run.py setup` (and
every `up`) validates both files and warns when their allowlists drift
apart.

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

## Rules (both engines)

* allowlist, never denylist;
* reject private IPv4 (RFC1918), loopback, link-local;
* reject cloud metadata addresses (`169.254.169.254` is covered by
  link-local blocking; both engines also check it explicitly);
* reject private/link-local/loopback IPv6;
* validate the destination **after** DNS resolution — a public hostname
  resolving to a private address is rejected;
* protect against DNS rebinding (validation applies to the address the
  proxy actually connects to);
* rejected destinations are logged by the engine (see docs/pipelock.md and
  docs/smokescreen.md for what each log contains).

## Changing the policy

1. Edit **both** `config/pipelock.yaml` and `config/smokescreen.yaml`
   (and the `.test.yaml` variants, which must stay a strict superset that
   only adds the DNS fixture domains).
2. `./run.py setup` — validates the files and the cross-engine sync.
3. `./run.py up` — recreates the container with the new policy.
4. `./run.py check --quick` — confirms allow/deny behavior.
5. Commit the change. `project-sandbox --extra-domain` never mutates these
   files; there is no dynamic policy channel by design.

## Test policy

`config/*.test.yaml` additionally allowlist `*.nip.io`, `*.sslip.io` and
`*.rbndr.us` — wildcard DNS services whose hostnames resolve to
attacker-chosen IPs. They exist **only** so `./run.py check --full` can
prove that the IP-layer SSRF floors hold even for allowlisted hostnames.
Start them with `./run.py up --test-policy`; a normal `./run.py up`
returns to the real policy.
