# The turn loop

One streamed turn: send a request, rebuild the assistant message from deltas,
run any tools it asked for, and go round again until it stops asking.

## The seam

```rust
pub async fn run_turn<F, O>(open: F, turn: Turn<'_>, ctx: &ExecutionContext, observe: O)
    -> Result<Vec<RequestMessage>, TurnError>
where
    F: AsyncFnMut(MessagesRequest) -> Result<EventStream, ProviderError>,
    O: FnMut(&AgentEvent),
```

Generic over a **closure that opens a stream**, not over a provider. So the loop
is parameterised by what a request becomes, not by who produced it: no trait, no
`dyn`, and no test double in anyone's public API.

`AsyncFnMut` rather than a separate `Fut` parameter, so the returned future stays
unnamed. The cost: a *generic* wrapper around `run_turn` cannot add its own `Send`
bound, since there is no stable way to name that future. Concrete callers are
unaffected — `the_documented_call_shape_compiles_and_stays_spawnable` pins that
the future is still `Send`.

`observe` stays generic for the mirror reason: `dyn FnMut` is not `Send`, so
taking one would make the whole future non-`Send`.

## Round structure

```
┌─ round (max_rounds = 8) ────────────────────────────────────┐
│  open(request)                     ◄── per-round timeout    │
│  consume stream ──► flush text before ToolUse               │
│  no ToolUse blocks?  ──► return produced                    │
│  answer_calls (sequential, spawn_blocking)                  │
└─ loop ──────────────────────────────────────────────────────┘
```

Re-entry is decided by the **presence of `ToolUse` blocks**, not by
`StopReason::ToolUse` — the blocks are what have to be answered, and trusting the
stop reason would mean trusting the provider to label its own output correctly.

`Thinking` and `Usage` are observed but dropped from the rebuilt history.

## The three traps

| Trap | Why | What the loop does |
|---|---|---|
| text deltas | content arrives as increments, not whole blocks | reassemble, and flush accumulated text *before* each `ToolUse` so ordering survives |
| empty round, nothing pending | the API rejects an empty content array | append nothing, return `Ok(produced)` |
| empty round, `tool_result` unanswered | a caller appends its own user message, and the API rejects two consecutive user turns | **discard the turn — `EndedMidToolUse`** |

The last one breaks the request *after* the one that went wrong, which is why it
is an error rather than a short turn. An empty *first* round is not this: nothing
is unanswered behind it, so it comes back as an empty turn.

## A tool failure is not a turn failure

A failing tool comes back as a `tool_result` marked `is_error`, which is what
lets the model try something else. An unknown tool name likewise —
`unknown tool: {name}` with `is_error`.

`TurnError` is only for what *ends* the turn:

| Variant | Transcript |
|---|---|
| `Provider` | — |
| `RoundLimit` | discarded |
| `EndedMidToolUse` | discarded |
| `TimedOut` | discarded |
| `StreamEndedWithoutStop` | — |
| `ToolPanicked { name }` | — |

## What bounds what

| Layer | Bound | Default |
|---|---|---|
| `TurnLimits::max_rounds` | rounds per turn | 8 |
| `TurnLimits::stream_timeout` | wall clock, **per round** | 300 s |
| `ExecutionContext::timeout` | the spawned command, `bash` only | 90 s |
| `ToolLimits` | in-process tool *work* — files and bytes scanned | 10,000 / 64 MiB |

**There is no total wall-clock bound on a turn to state.** The in-process tools
are bounded by work, not time, so no product of the above is a worst case. A
broad `grep` terminates because of the scan budget; a single `read` on a stalled
filesystem still does not.

> **`stream_timeout` carries a runtime precondition.** It is
> `tokio::time::timeout`, which panics *"there is no timer running"* on the first
> round if the runtime has no time driver. `#[tokio::main]` and
> `Builder::new_*().enable_all()` enable it; `new_current_thread().enable_io().build()`
> does not. The runtime flavour stays the binary's choice — the crate needs `rt`,
> never `rt-multi-thread`.

## The blocking boundary

Tools are synchronous. `run_turn` is the sole `spawn_blocking` site, which keeps
the sync/async boundary in one place rather than spreading `async` through seven
tool bodies that do blocking I/O anyway. `answer_calls` runs them sequentially.

**A cancelled turn still runs its tool.** Dropping the `run_turn` future drops the
`JoinHandle` while the blocking task runs to completion — so a turn abandoned
mid-tool (a TUI cancel, a losing `select!` branch, an outer deadline) still
applies the `write`, or lets `bash` run out its timeout, after the caller stopped
waiting. The transcript naming that call goes with the dropped future; only the
audit trail records the side effect.

This is why an outer deadline is not a substitute for real cancellation (#26).

## Test suite

`tests/turn_loop.rs` drives the loop through the closure seam with a local
`Script`, deliberately **not** `MockProvider`: that double's whole body is the
`stream::iter(..).fuse()` in `canned`, and reaching for it would mean a `mock`
feature here, a `required-features` target, and a CI command naming both — three
coordinated parts, one a silent failure if forgotten, to borrow one line.
Recording requests has to live locally either way, since `MockProvider` discards
its own.
