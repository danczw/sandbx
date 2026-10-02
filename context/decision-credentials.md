# Decision: where a credential comes from

Three tiers were planned. **Only tier 1 exists.**

| Tier | Source | State |
|---|---|---|
| 1 | `ANTHROPIC_API_KEY` from the environment, via `resolve_api_key` | shipped, wrapped in `secrecy::SecretString` |
| 2 | OS keyring | deferred |
| 3 | `~/.config/sandbx/credentials.toml` at `0600` | deferred |

Tiers 2 and 3 are deferred to whichever phase builds `sandbx auth login`. Neither
is a prerequisite for anything shipped: no subcommand reads a credential today, so
a missing keyring costs nothing yet.

## What this covers, and what it does not

This is the *harness's own* provider call — sandbx authenticating to Anthropic. It
says nothing about a credential a **sandboxed tool** needs, which is a different
problem with a different answer:

- A sandboxed command no longer inherits the harness's environment (#98). The
  policy names what crosses, so a key in sandbx's environment is not in the
  child's. See [decision-environment-allowlist.md](decision-environment-allowlist.md).
- Handing a tool a credential it legitimately needs — `bash` running `gh` — has no
  design yet (#41). The shape under consideration is an opaque placeholder plus a
  TLS-terminating proxy that resolves the real value per request, so the secret
  never enters the child's memory. Deliberately undecided until a tool needs it.

The ordering matters: #41 could not be designed while the environment was shared
wholesale, which is why #98 landed first and separately.
