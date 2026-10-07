# Tools

The seven built-ins, and the shape of the layer around them.

## The set

| Tool | Input | Confined by | Risk |
|---|---|---|---|
| `read` | `{ path }` | `FsGuard::open_read` | `ReadOnly` |
| `write` | `{ path, content }` | `FsGuard::open_write` | `Writes` |
| `edit` | `{ path, old, new }` | `open_read` + `open_write` | `Writes` |
| `ls` | `{ path }` | `FsGuard::check_read` | `ReadOnly` |
| `grep` | `{ path, pattern }` | `open_read` + `walk_readable` | `ReadOnly` |
| `find` | `{ path, name }` | `walk_readable` | `ReadOnly` |
| `bash` | `{ command }` | the helper — Landlock + seccomp + netns | `Executes` |

`bash` is the only tool that spawns. The other six run in-process.

`RiskLevel` is what a gate deciding by category reads, and it is `Ord` so a
caller can admit everything at or below a level. It is a field of each tool's own
`SPEC` rather than a table here: a new tool declares its level or fails to
compile, where a denylist would have been silently missing it.

## Dispatch: an enum, not a trait object

```rust
pub enum BuiltinTool { Read, Write, Bash, Edit, Ls, Grep, Find }  // fieldless, Copy
pub const ALL: [Self; 7] = [..];                                   // this is the registry
struct ToolSpec { name, description, risk, schema, run }           // one per tool, in its module
```

No `Tool` trait, no `ToolRegistry` type, no `dyn`. The set is closed at compile
time and nothing picks a tool at runtime that is not in it, so the flexibility a
trait object buys would be unused. `from_name` is exact-match —
`from_name("Read")` is `None`. `ToolSpec` is two `&'static str`s, a `RiskLevel`
and two fn pointers reached only through an exhaustive match on that closed enum:
a table, not a vtable with an open set behind it.

`name`, `description`, `risk`, `input_schema` and the executor are **one `SPEC`
per tool**, in the tool's own module beside its input struct and its `execute`.
`BuiltinTool` reaches them through a single match, so a transposed arm relabels a
variant consistently instead of handing the model one tool's name with another's
schema (#54, #55, #88). Folding the executor in also puts the parse behind a
type: each module's `run` parses into that module's own input struct, so a
filesystem path that skips the parse is unwritable.

Five tests in `tests/registry.rs` pin what co-location cannot:

- `every_tool_is_named_after_its_variant` — `name()` is `{variant:?}` lowercased.
  A symmetric swap of two names stays unique and still round-trips through
  `from_name`; that is how #88 went unnoticed through a whole green suite.
- `every_tool_advertises_its_own_input_struct` — each tool's schema names its own
  module's struct, via schemars' `title`. Guards a real bug (#55):
  `Self::Ls => schema_for!(GrepInput)` compiled and passed.
- `every_tool_describes_itself_distinctly` — descriptions non-empty and mutually
  distinct. A deliberate swap of two descriptions is the one transposition
  nothing catches: no content heuristic relates "List a directory's entries" to
  `ls`, and the obvious one — a description names its own tool — is false for
  `bash`, `edit`, `ls` and `grep`. Co-location is the whole mitigation.
- `the_risk_each_tool_carries_is_documented` — a hard-coded match naming each
  variant's expected level. Read off `risk()` it would assert only
  self-consistency, and a `bash` reclassified as read-only would still pass.
- `the_risk_levels_order_least_to_most` — the `Ord` derive is what lets a gate
  admit everything at or below a level, which makes the variant order
  load-bearing: alphabetising the enum would keep the rest of the suite green
  while inverting the meaning of every `<=`.

Schemas are derived via `schema_for!`, never hand-written, and returned as
`serde_json::Value`. The schema is a fn pointer rather than a value in the `SPEC`
because `schema_for!` allocates and so cannot be a `const`.

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

So no tool can tell the model what its roots are, and no refusal does either:
`conceal_unless_granted` has to keep one outside every root indistinguishable, or
a sequence of probes reads back as a map of the host. `agent-run` names the roots
in the system prompt instead, above the tool boundary, where the policy is still
the operator's own text rather than something a `tool_result` carries back. A run
that refuses a tool names the set it approved in the same place, for the cost
rather than the concealment: a refusal already carries that set back to the model,
one tool and one round at a time (#197). A run that approves all seven names none
— there is no boundary to describe, and the request already carries every schema.

## Errors say which kind of wrong

| Variant | Means | The agent should |
|---|---|---|
| `Denied { subject, reason }` | policy refused it | not retry — ask, or pick another path |
| `BadInput { detail }` | arguments did not parse | fix the arguments |
| `Failed { subject, detail }` | it ran and did not work | read the detail |
| `TimedOut { subject, after }` | ran past its limit, killed | narrow it, or ask for longer |

`TimedOut` is split from `Failed` deliberately: a command that failed will fail
again, while one that ran out of time might succeed if narrowed.

`SandboxError::NotFound` is the one guard verdict that becomes a `Failed` rather
than a `Denied`: a path missing inside a root the policy already grants was
refused by nothing, so the agent's move is to fix the name, not to ask for a
wider grant (#180). `crate::guard_error` is where that is decided, once, for all
six tools that reach the guard. Everything else a guard hands back is a refusal.

`bash` reaches no guard, so its axis is the helper's instead, decided in
`bash::sandbox_error` (#185). A program pin is the one `Denied`: policy naming
exact bytes, and the next attempt is refused identically. Every other refusal a
helper stage reports — a ruleset the kernel would not take, a filter that would
not install, a malformed argv — is a `Failed`, `Denied` reading as "refused by
the sandbox policy" and that being false about a kernel that would not unshare.
What separates those from a command that ran and exited non-zero is the
`subject`: ``sandbox `cmd` `` against ``run `cmd` ``. A `Landlock` detail may
name a path out of the policy, which the rule below permits only because
`agent-run` already names its roots in the system prompt.

A `reason` or `detail` travels back inside a `tool_result`, which a
prompt-injected model relays, so neither may name a grant the caller does not
already hold — the refusal for a path outside every root stays indistinguishable
from any other.

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

See `decision-bounding-tool-work.md` for why input bounds and output bounds are different
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
| bounded in work | the two searches — not `read`/`edit`, which allocate a whole file |
| cancellable from outside | **partly** — the turn can be abandoned; the running tool still completes (#26) |
| approval gate | **per tool per run** — `run_turn`'s `approve` closure, asked before the spawn; no per-call prompt (#165) |

## The split that matters

A `FsGuard` change is a change to six tools at once, because they all go through
it. That is the point — and since #56, the private `policy` field is what
enforces it rather than leaving it to convention.
