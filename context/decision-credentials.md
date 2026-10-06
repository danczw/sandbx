# Decision: where a credential comes from

Three tiers were designed; tier 1 is the one the code reads.

| Tier | Source | Where |
|---|---|---|
| 1 | `ANTHROPIC_API_KEY` from the environment, via `anthropic_api_key` | `sandbx-providers/src/credentials.rs`, wrapped in `secrecy::SecretString` |
| 2 | OS keyring | #109 |
| 3 | `~/.config/sandbx/credentials.toml` at `0600` | #109 |

Tiers 2 and 3 belong with `sandbx auth login` (#109). The argument for them is
that `agent-run` reads tier 1 alone, so a user with no `ANTHROPIC_API_KEY`
exported has no way to authenticate at all — an argument that did not exist
before the turn loop had a caller.

## What this covers, and what it does not

This is the *harness's own* provider call — sandbx authenticating to Anthropic. It
says nothing about a credential a **sandboxed tool** needs, which is a different
problem with a different answer:

- A sandboxed command no longer inherits the harness's environment (#98). The
  policy names what crosses, so a key in sandbx's environment is not in the
  child's. See [decision-environment-allowlist.md](decision-environment-allowlist.md).
- Handing a tool a credential it legitimately needs — `bash` running `gh` — is
  #41. The shape sketched there is an opaque placeholder plus a TLS-terminating
  proxy that resolves the real value per request, so the secret never enters the
  child's memory. It waits on a tool needing one.

The ordering matters: #41 could not be designed while the environment was shared
wholesale, which is why #98 landed first and separately.
