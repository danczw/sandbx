# Tools

The seven built-ins, and the shape of the layer around them.

## The set

| Tool | Input | Confined by |
|---|---|---|
| `read` | `{ path }` | `FsGuard::open_read` |
| `write` | `{ path, content }` | `FsGuard::open_write` |
| `edit` | `{ path, old, new }` | `open_read` + `open_write` |
| `ls` | `{ path }` | `FsGuard::check_read` |
| `grep` | `{ path, pattern }` | `open_read` + `walk_readable` |
| `find` | `{ path, name }` | `walk_readable` |
| `bash` | `{ command }` | the helper — Landlock + seccomp + netns |

`bash` is the only tool that spawns. The other six run in-process.

## Dispatch: an enum, not a trait object

```rust
pub enum BuiltinTool { Read, Write, Edit, Ls, Grep, Find, Bash }  // fieldless, Copy
pub const ALL: [Self; 7] = [..];                                   // this is the registry
```

No `Tool` trait, no `ToolRegistry` type, no `dyn`. The set is closed at compile
time and nothing picks a tool at runtime that is not in it, so the flexibility a
trait object buys would be unused. `from_name` is exact-match —
`from_name("Read")` is `None`.

`name`, `description` and `input_schema` are three parallel seven-arm matches.
Two tests pin arm-to-variant correspondence:

- `tests/registry.rs` pins each `input_schema` arm to its own struct via
  schemars' `title`. This guards a real bug (#55): `Self::Ls => schema_for!(GrepInput)`
  compiled and passed.
- descriptions are pinned non-empty and mutually distinct.

Schemas are derived via `schema_for!`, never hand-written, and returned as
`serde_json::Value`.

## Paths: handles, not resolved paths

```rust
let file = ctx.guard().open_read(path)?;   // O_NOFOLLOW; fails if the leaf became a symlink
```

The guard hands back an **open handle**. A tool that took a resolved path and
opened it itself would reintroduce the TOCTOU window the handle closes — so
`check_read` is reserved for `ls`, where `read_dir` has no handle form.

Residual gap: a parent-directory swap mid-open. Closing it needs full
`openat`-chain resolution.

## The policy is private

`ExecutionContext` keeps `policy` private; `sandboxed_command` is the only route
to it, and it **spends** the policy rather than lending it. An accessor returning
`&SandboxPolicy` previously let a native tool read the path lists and bypass the
handles (#56) — the split was documented but nothing enforced it. Now the type
does.

## Errors say which kind of wrong

| Variant | Means | The agent should |
|---|---|---|
| `Denied { subject, reason }` | policy refused it | not retry — ask, or pick another path |
| `BadInput { detail }` | arguments did not parse | fix the arguments |
| `Failed { subject, detail }` | it ran and did not work | read the detail |
| `TimedOut { subject, after }` | ran past its limit, killed | narrow it, or ask for longer |

`TimedOut` is split from `Failed` deliberately: a command that failed will fail
again, while one that ran out of time might succeed if narrowed.

## What bounds a tool call

**Time bounds the spawned command only.** `ExecutionContext::timeout` (90 s
default) applies to `bash`. The six in-process tools have no clock on them at
all — they are bounded by *work*:

| Knob | Phase | Default | Bounds |
|---|---|---|---|
| `max_entries` | output | 200 | result lines returned |
| `max_bytes` | output | 256 KiB | bytes returned |
| `max_files_scanned` | input | 10,000 | files visited by a search |
| `max_bytes_scanned` | input | 64 MiB | bytes read, **across** the whole search |
| `MAX_FILE_BYTES` | input | 2 MiB | per file in `grep`; hardcoded, not a knob |

See `bounding-tool-work.md` for why input bounds and output bounds are different
things, and for the one path still uncapped (`read`/`edit` allocate a whole file
before `max_bytes` trims what is returned).

## `ToolOutput` invariants

Two things a contributor can break silently:

1. **An empty result is unrepresentable.** The field is private, `new` is the only
   way in, and whitespace-only content becomes `"(no output)"` — the Messages API
   rejects an empty `tool_result` and would end the turn with a provider error.
2. **The truncation marker is appended *after* the entry cap**, so the cap cannot
   trim away the notice that the results are incomplete.

A complete-but-empty listing returns `"no matches"`, which is a different
proposition from "stopped early".

## Sync, and staying that way

Tools are synchronous. `run_turn` is the sole `spawn_blocking` site, which keeps
the async boundary in one place instead of spreading `async` through seven tool
bodies that do blocking I/O anyway.

| Property | State |
|---|---|
| bounded in time | `bash` only |
| bounded in work | all six in-process searches |
| cancellable from outside | **partly** — the turn can be abandoned; the running tool still completes (#26) |
| approval gate | **none exists.** Nothing sits between the model asking and the tool running |

## The split that matters

A `FsGuard` change is a change to six tools at once, because they all go through
it. That is the point — and since #56, the private `policy` field is what
enforces it rather than leaving it to convention.
