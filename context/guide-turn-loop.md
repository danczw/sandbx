# The turn loop

One streamed turn: send a request, rebuild the assistant message from deltas,
run any tools it asked for, and go round again until it stops asking.

## The seam

```rust
pub async fn run_turn<F, O>(open: F, turn: Turn<'_>, ctx: &ExecutionContext, observe: O)
    -> Result<TurnOutcome, TurnError>
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
│  request = history[cut..] ++ produced                       │
│    cut: set on the first over-budget round, then frozen     │
│  open(request)                     ◄── per-round timeout    │
│  consume stream ──► flush text before ToolUse, keep Usage   │
│  no ToolUse blocks?  ──► return TurnOutcome                 │
│  answer_calls (sequential, spawn_blocking)                  │
└─ loop ──────────────────────────────────────────────────────┘
```

Re-entry is decided by the **presence of `ToolUse` blocks**, not by
`StopReason::ToolUse` — the blocks are what have to be answered, and trusting the
stop reason would mean trusting the provider to label its own output correctly.

Neither `Thinking` nor `Usage` enters the rebuilt history, but only one of them is
thrown away. `Thinking` is observed and lost: no `ContentBlock` can carry it and the
signature needed to replay it is discarded upstream (#85). `Usage` is observed **and
kept** — the latest round's prompt counters come back as `TurnOutcome::usage`, which
a caller threads into the next turn's `Turn::observed` with
`observed = outcome.usage.or(observed)`. That is the loop compaction runs on.

## The three traps

| Trap | Why | What the loop does |
|---|---|---|
| text deltas | content arrives as increments, not whole blocks | reassemble, and flush accumulated text *before* each `ToolUse` so ordering survives |
| empty round, nothing pending | the API rejects an empty content array | append nothing, return `Ok(produced)` |
| empty round, `tool_result` unanswered | a caller appends its own user message, and the API rejects two consecutive user turns | **discard the turn — `EndedMidToolUse`** |

The last one breaks the request *after* the one that went wrong, which is why it
is an error rather than a short turn. An empty *first* round is not this: nothing
is unanswered behind it, so it comes back as an empty turn.

## Compaction (opt-in)

Set `TurnLimits::compaction` and a turn whose *last measured* prompt went over
`budget_tokens` leaves its oldest history out of the request. The measurement is
`input_tokens + cache_read_input_tokens + cache_creation_input_tokens` of the request
that already went out — a cache read is a real prompt token, so counting `input_tokens`
alone under-reads a long cached conversation badly. An unreported counter sums as zero;
the API omits the cache fields entirely when no cache was involved, and reading that as
"unknown" would switch compaction off for every uncached request. No measurement at all
means no compaction, so it can never fire on a conversation's first turn.

**The cut points are not arbitrary.** Dropping a prefix can only break the conversation
at its new front, so the whole question is three conditions on what becomes the first
message: it must be a `Role::User` turn, carry no `ToolResult` block (its `ToolUse` is in
the message being dropped, and an orphan is rejected), and have non-empty content. The
consequence worth internalising:

> In a tool-heavy transcript the legal cut points are exactly the human prose turns —
> one per exchange, not one per message.

When nothing legal is deep enough, three rungs:

| | |
|---|---|
| a legal cut at or after the target | take it; `keep_recent` honoured |
| none that deep, one shallower | take the deepest earlier one — shed less than asked rather than nothing |
| none at all | **send it uncompacted** |

The last rung is deliberate. Erroring would turn an opt-in optimisation into a
turn-killer, and cutting anyway converts a request that *might* be too long into one the
API is certain to reject, surfacing as an opaque `TurnError::Provider`. So the provider's
own context-length error stays the real backstop — which is the honest limit of
compaction this naive: it sheds whole exchanges, so one enormous exchange cannot be shed
at all.

Three properties that are easier to state than to infer:

- **A view, not a mutation.** `TurnOutcome::messages` is always the complete turn. A
  caller appends it to its own history, and anything compaction had removed from *that*
  would be gone for good, compounding every turn.
- **It never reaches `produced`.** The planner is handed the count of the turn's own
  messages, not the messages, so no cut can withhold the tool result the model is waiting
  on. `TurnOutcome::withheld` reports what the last request left out.
- **The cut is frozen** once set, for the whole turn. Re-deciding per round would let it
  move as the measurement crossed the budget — invalidating the request's cached prefix
  every round and re-showing the model history it had already lost.

`EndedMidToolUse` is unaffected: it reads `produced`, which compaction cannot reach. The
coupling runs the other way — withholding history is one of the things that can confuse a
model into an empty round, and that is where it lands.

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

A discarding variant discards the turn's `usage` with it, so a caller's `observed` keeps
the figure from the last request that actually completed.

## What bounds what

| Layer | Bound | Default |
|---|---|---|
| `TurnLimits::compaction` | oldest *history* withheld from the request | `None` — **off** |
| `TurnLimits::max_rounds` | rounds per turn | 8 |
| `TurnLimits::stream_timeout` | wall clock, **per round** | 300 s |
| `ExecutionContext::timeout` | the spawned command, `bash` only | 90 s |
| `ToolLimits` | in-process tool *work* — files and bytes scanned | 10,000 / 64 MiB |

Compaction is the only one of these that is **off by default**, because it is the only
one that is lossy — the others refuse to go on, which announces itself, where this one
quietly sends the model less than it was given. And its right value is not the crate's
to guess: `Turn::model` is a freeform string with no context-window table behind it.

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

Split by visibility, as the workspace splits everywhere: `compact.rs`'s planner is
private, so its cut-point algebra is a `#[cfg(test)] mod tests` beside it, while
`tests/turn_loop.rs` covers the public surface — including that what reaches the API
after compaction is still a conversation it would accept, which is asserted on
`Script::sent` rather than on the return value.

`tests/turn_loop.rs` drives the loop through the closure seam with a local
`Script`, deliberately **not** `MockProvider`: that double's whole body is the
`stream::iter(..).fuse()` in `canned`, and reaching for it would mean a `mock`
feature here, a `required-features` target, and a CI command naming both — three
coordinated parts, one a silent failure if forgotten, to borrow one line.
Recording requests has to live locally either way, since `MockProvider` discards
its own.
