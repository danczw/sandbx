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
this, and it is the one property to defend: the two `Degraded` sites once used a
raw `tracing::debug!` on the audit target, so a hardening step could go missing
below the default filter. The level was the first half of the fix; getting the
record out of the helper at all was the second (see below).

What a missing step costs depends on which one it was, so `mechanism` carries
that rather than `Degraded` implying a single answer. A bounding set left as
inherited is a weaker sandbox; an unmapped identity costs only uid fidelity and
is, if anything, more restrictive.

**Metadata only, never output.** That a tool read a file is a different
proposition from storing what the file contained; output is where secrets live.
`Spawned` records *counts, not paths* for the same reason — and derives them
through an exhaustive `match` on `Axis::ALL`, so a new axis fails to compile
rather than going silently uncounted (#51).

**Denials always carry a reason.** `Denied.reason` is non-optional; "denied"
alone is not actionable.

## The sink

`sandbx-cli/src/logging.rs` — the one subscriber the binary installs (#89).
`subscriber(writer)` builds it; `init()` pins stderr and goes global.

```
registry()
  .with(fmt::layer().with_writer(stderr).with_ansi(false))
  .with(Targets::new().with_target(AUDIT_TARGET, INFO))
```

**Stderr, not stdout** — `SandboxRun::execute` forwards the sandboxed command's
stdout verbatim, so a record there would corrupt a pipeline. The timestamp comes
from the formatter's default `SystemTime`, which is why no event field carries
one.

**Always on, no flag.** The audit trail is not opt-in diagnostics; a configurable
logging surface is worth designing once logging has a second consumer.

**The filter is both halves.** The target half keeps `sandbx-core`'s own `debug!`
out, so making the trail visible does not make the internals visible. The `INFO`
bound keeps anything that merely borrowed the target out of the record.

`init()` returns its error rather than panicking: a run that goes unrecorded
still beats a run that does not happen. Installed *inside* the
`with_helper_dispatch` closure — above it, the helper would write sandbx's own
records into the output of the command being sandboxed.

## The helper's degradations cross a channel

That placement leaves the helper with no subscriber at all, and both best-effort
hardening steps run there. Emitting `Degraded` in the helper recorded nothing,
whatever the level (#95).

So the helper does not emit. `helper/hardening.rs` *returns* what degraded,
stage 1 renders it as `label<TAB>detail` lines (`core/src/degradation.rs`) and
writes them to the pipe sandbx put in its **stdin** slot, and sandbx decodes the
bytes and emits the audit events itself. One subscriber in the process tree, one
timestamp source, and the command's own stdout and stderr stay byte-exact.

The stdin slot because fds 0/1/2 are the only descriptors `std` can hand a child
without `unsafe`, which the workspace forbids — and 1/2 are the command's output.
Stage 1 sets the inner stage's stdin to `Stdio::null()`, so the sandboxed command
has no handle on the channel; `decode` also accepts only a closed set of mechanism
labels, so nothing can name a mechanism sandbx did not define. Two costs are
accepted: the slot is claimed (no interactive stdin for a sandboxed command later),
and sandbx reads after waiting, so a `degraded` record is timestamped after
`spawned`. See `decision-helper-audit-channel.md`.

## What is not built

| Missing | Consequence |
|---|---|
| emitters outside `sandbx-core` | `tracing` is a dependency of `sandbx-core` alone. Zero emission sites in tools, agent, providers, tui, session |
| session ids | no field carries one; there is no session concept in the workspace |
| JSON-lines writer, rotation, `--no-audit` | nothing. No `tracing-appender`, no XDG path resolution anywhere in `crates/` |
| a terminal record | `Spawned` is emitted *before* the exec, so it appears for a command that then fails to start, and a `--timeout` kill records nothing. The record describes the policy, not the outcome |

Libraries emit and never choose a sink — no emission site touches a file or a
terminal. That part of the design holds; it is the sink that is absent.

## Secrets

`SecretString` wraps the API key (`secrecy`, in `sandbx-providers`).

> **It does implement `Debug`** — printing a redaction, which is the entire
> reason the key is wrapped in it, and why `AnthropicClient` can derive `Debug`
> at all. `Display` is not implemented, so `{}` is a compile error.
>
> So the no-leak guarantee rests on a **runtime test**
> (`debug_output_does_not_leak_the_api_key`), not on the compiler.
> Do not assume `{:?}` is checked for you.

The derive is deliberate over a hand-written impl: it picks up any field added
later, where a hand-written one would silently omit it.
