# Logging and the audit trail

Two streams on one `tracing` pipeline, separated by target.

```
diagnostics   ──► default targets      ──► for whoever is debugging sandbx
audit trail   ──► "sandbx::audit"      ──► for whoever asks "what did the agent do to my machine"
```

`AUDIT_TARGET = "sandbx::audit"`. Filter on it to split the two.

## What is built

`AuditEvent` in `sandbx-core/src/audit.rs` — four variants, all emitted at
`INFO`:

| Variant | `decision` | Fields |
|---|---|---|
| `Allowed` | `allowed` | `tool`, `subject` |
| `Denied` | `denied` | `tool`, `subject`, `reason` |
| `Degraded` | `degraded` | `mechanism`, `detail` |
| `Spawned` | `spawned` | `program`, `readable`, `writable`, `executable`, `network`, `unix_sockets` |

**`INFO`, not `DEBUG`** — at `DEBUG` the trail would be absent for everyone who
did not opt in, which is exactly when a record matters. `tests/audit.rs` pins
this, and it is the one property to defend: the two `Degraded` sites previously
used a raw `tracing::debug!` on the audit target, so a sandbox could silently
weaken and the record of it reached nobody.

**Metadata only, never output.** That a tool read a file is a different
proposition from storing what the file contained; output is where secrets live.
`Spawned` records *counts, not paths* for the same reason — and derives them
through an exhaustive `match` on `Axis::ALL`, so a new axis fails to compile
rather than going silently uncounted (#51).

**Denials always carry a reason.** `Denied.reason` is non-optional; "denied"
alone is not actionable.

## What is not built

| Missing | Consequence |
|---|---|
| any subscriber in `sandbx-cli` | **audit events are emitted and discarded.** `tracing-subscriber` is a dev-dependency of `sandbx-core`; the binary installs nothing (#89) |
| emitters outside `sandbx-core` | `tracing` is a dependency of `sandbx-core` alone. Zero emission sites in tools, agent, providers, tui, session |
| timestamps, session ids | no field carries either. A timestamp would come from a subscriber formatter; there is no session concept in the workspace |
| JSON-lines writer, rotation, `--no-audit` | nothing. No `tracing-appender`, no XDG path resolution anywhere in `crates/` |

Libraries emit and never choose a sink — no emission site touches a file or a
terminal. That part of the design holds; it is the sink that is absent.

## Secrets

`SecretString` wraps the API key (`secrecy`, in `sandbx-providers`).

> **It does implement `Debug`** — printing a redaction, which is the entire
> reason the key is wrapped in it, and why `AnthropicClient` can derive `Debug`
> at all. `Display` is not implemented, so `{}` is a compile error.
>
> So the no-leak guarantee rests on a **runtime test**
> (`the_client_does_not_leak_the_api_key_in_debug_output`), not on the compiler.
> Do not assume `{:?}` is checked for you.

The derive is deliberate over a hand-written impl: it picks up any field added
later, where a hand-written one would silently omit it.
