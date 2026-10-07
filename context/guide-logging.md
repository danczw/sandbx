# Logging and the audit trail

Two streams on one `tracing` pipeline, separated by target.

```
diagnostics   ──► default targets      ──► for whoever is debugging sandbx
audit trail   ──► "sandbx::audit"      ──► for whoever asks "what did the agent do to my machine"
```

`AUDIT_TARGET = "sandbx::audit"`. Filter on it to split the two.

## What is built

`AuditEvent` in `sandbx-core/src/audit.rs` — seven variants, all emitted at
`INFO`:

| Variant | `decision` | Fields |
|---|---|---|
| `Allowed` | `allowed` | `tool`, `subject` |
| `Absent` | `absent` | `tool`, `subject` |
| `Denied` | `denied` | `tool`, `subject`, `reason` |
| `Degraded` | `degraded` | `mechanism`, `detail` |
| `Spawned` | `spawned` | `program`, `readable`, `writable`, `executable`, `network`, `network_ports`, `unix_sockets`, `env`, `dns_over_tcp`, `pinned` |
| `Exited` | `exited` | `program`, `code` |
| `Failed` | `failed` | `program`, `reason` |

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

`Spawned.pinned` is the one field not derived from the policy, a digest not being
policy (`decision-pinned-entry-point.md`), so `spawned` takes it as a parameter.
It is there because a matching pin is otherwise invisible: the run proceeds as any
unpinned run does, and a trail that omitted the boolean could not tell an
`--pin-sha256` run from one that named no digest at all. The boolean and not the
digest — the digest crosses on argv already, and a record of fixed width is one a
filter can rely on (#146).

**Denials always carry a reason.** `Denied.reason` is non-optional; "denied"
alone is not actionable.

**`decision=` records the access, not the verdict** (#182, #187). So `allowed` is
emitted *after* the open, the walk or the `read_dir` succeeds, and the trail
answers "what did the agent see" rather than "what did the policy decide". The
reasoning, and what the verdict reading would have cost, is in
`decision-audit-records-access.md`.

Three consequences a reader of the trail depends on:

- **A check that performs no access records nothing.** `check_read` and
  `check_write` emit a refusal and no pass; the `allowed` belongs to whichever
  entry point goes on to hold a handle. A bare check succeeding is not an event.
- **An absence is its own value.** `absent` is a path that names nothing inside a
  root the policy already grants — a model guessing filenames leaves these, and
  nothing else on the trail would show the guesses. It carries no `reason`:
  nothing refused it, so there is no refusal to explain. It still reaches the
  model as a `Failed`, so the next move is to fix the name rather than widen the
  grant (#180).
- **`absent` never escapes a grant.** A path missing *outside* every root stays a
  `denied`, indistinguishable from any other refusal. Naming the absence there
  would hand back over the trail exactly what the refusal conceals.

What separates the two is `names_nothing` — ENOENT, ENOTDIR, ENAMETOOLONG — with
one errno read the other way. On the leaf of a directory read, ENOTDIR says the
leaf *is* a regular file, which the gate had just resolved, so `listed_nothing`
drops it: `ls` on a file records a refusal, not an absence.

A refusal past the gate carries one of two reasons, the policy having already
allowed the path. `path does not resolve` is the resolution failure — an EACCES
parent, or the `ELOOP` of a leaf swapped between the check and the open — and
reads the same whether the gate caught it or the access did. `access did not
complete` is everything else: a full disk, a read-only mount, a directory opened
as a file. An operator counting refusals reads the first as a traversal attempt,
which is why a full disk may not borrow it.

One record per operation, with one exception: a `grep` leaves one `allowed` for
the walk, naming the directory, and then one more per file it actually opens. All
of them are true, which is the point of recording the access.

**A run is two records** (#96). `Spawned` is the policy, settled before the exec,
so it stands for an attempt — including one that never starts. Exactly one
`Exited` or `Failed` closes it, emitted by `SandboxedCommand::output` and nowhere
else. Per run, in order: `spawned`, then zero or more `degraded`, then the one
terminal record, then the command's own stdout and stderr — which come last
because `output()` collects the command in full and `SandboxRun::execute`
forwards the streams only after it returns.

`Exited.code` is `exit_code`'s encoding, 128 + n for a signal, so the number on
the trail is the number `sandbx` exits with rather than a second encoding of the
same status. `Failed.reason` comes from `SandboxError::label` — exhaustive, so a
new error variant has to decide what a trail calls it, and the trail cannot name
a reason the error type does not define.

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

## What the helper cannot see crosses a channel

That placement leaves the helper with no subscriber at all, and both best-effort
hardening steps run there. Emitting `Degraded` in the helper recorded nothing,
whatever the level (#95).

So the helper does not emit. `helper/hardening.rs` *returns* what degraded,
stage 1 renders it as `label<TAB>detail` lines (`sandbx-core/src/degradation.rs`) and
writes them to the pipe sandbx put in its **stdin** slot, and sandbx decodes the
bytes and emits the audit events itself. One subscriber in the process tree, one
timestamp source, and the command's own stdout and stderr stay byte-exact.

A stage that refused rather than reaching the command crosses the same channel, as
its `SandboxError::label` — `exec_failed` for a command that does not exist,
`namespace_setup_failed` for a supervisor already gone, `bad_helper_args` for an argv
stage 1 would not decode, `inner_stage_failed` for a stage 2 it could not start — and
that becomes the run's terminal record. It has to: the helper's exit status is
relayed on the command's behalf, so the parent sees one indistinguishable from a
command that ran and exited 1 (#96, #157, #160). Each stage reports only from above
the next stage's existence, so one refusal crosses and the more specific one is never
displaced; the two paths that leaves silent are in
`context/decision-helper-audit-channel.md`.

The stdin slot because fds 0/1/2 are the only descriptors `std` can hand a child
without `unsafe`, which the workspace forbids — and 1/2 are the command's output.
Stage 2 takes the channel off fd 0 into a close-on-exec duplicate and puts
`/dev/null` in the slot before it becomes the command, so the sandboxed command
has no handle on the channel and a successful `exec` closes the duplicate;
`decode` also accepts only a closed set of labels, so nothing can name a
mechanism sandbx did not define. Two costs are accepted: the slot is claimed (no
interactive stdin for a sandboxed command later), and sandbx reads after waiting,
so `degraded` and the terminal record are both timestamped after `spawned`. See
`decision-helper-audit-channel.md`.

## What is not built

| Missing | Consequence |
|---|---|
| emitters outside `sandbx-core` | `tracing` is a dependency of `sandbx-core` alone. Zero emission sites in tools, agent, providers, tui, session |
| session ids | nothing ties a spawn to its outcome but `program`. `SessionId` now exists (`sandbx-session`) and reaches no `tracing` field, so a correlation id is buildable rather than built; see #96 |
| JSON-lines writer, rotation, `--no-audit` | nothing. No `tracing-appender`. XDG resolution exists but not for a log: `sandbx-session/src/paths.rs` is what a sink would reuse |

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
