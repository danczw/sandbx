# The turn loop

One streamed turn: send a request, rebuild the assistant message from deltas,
run any tools it asked for, and go round again until it stops asking.

## The seam

```rust
pub async fn run_turn<F, O, G>(
    open: F, turn: Turn<'_>, ctx: &ExecutionContext, observe: O, approve: G,
) -> Result<TurnOutcome, TurnError>
where
    F: AsyncFnMut(MessagesRequest) -> Result<EventStream, ProviderError>,
    O: FnMut(&AgentEvent),
    G: FnMut(ToolCall<'_>) -> ApprovalDecision,
```

Generic over a **closure that opens a stream**, not over a provider. So the loop
is parameterised by what a request becomes, not by who produced it: no trait, no
`dyn`, and no test double in anyone's public API.

`AsyncFnMut` rather than a separate `Fut` parameter, so the returned future stays
unnamed. The cost: a *generic* wrapper around `run_turn` cannot add its own `Send`
bound, since there is no stable way to name that future. Concrete callers are
unaffected — `documented_call_shape_stays_spawnable` pins that
the future is still `Send`, and `sandbx-cli`'s `agent-run` is that concrete
caller, passing `|request| client.stream_chat(request)` exactly as the test shape
predicts.

`observe` stays generic for the mirror reason: `dyn FnMut` is not `Send`, so
taking one would make the whole future non-`Send`.

`approve` is the third closure for the same two reasons, plus a third: it is
mandatory, so a caller cannot acquire a gate-less loop by omitting an argument.
See `decision-approval-gate.md` for why it is not a trait.

## Round structure

```
┌─ round (max_rounds = 8) ────────────────────────────────────┐
│  request = history[cut..] ++ produced                       │
│    cut: ≥ last turn's; deepens, never reverses              │
│  open(request)                     ◄── per-round timeout    │
│  consume stream ──► flush text before ToolUse, keep Usage   │
│  no ToolUse blocks?  ──► return TurnOutcome                 │
│  answer_calls (sequential)                                  │
│    resolve name ──► approve(call) ──► spawn_blocking        │
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
`observed = outcome.usage.or(observed)`. That is half of the loop compaction runs on;
`withheld = outcome.withheld` is the other half, and neither works alone.

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
means no compaction, so it can never fire on a turn's *first round* — see the third
property below for why that is a weaker claim than "a conversation's first turn".

**Both halves have to be threaded back, not just the usage.** `TurnOutcome::withheld`
goes into the next `Turn::withheld`, where it is the *floor* for the next cut: this turn
may withhold more, never less — unless the count has stopped naming a legal cut point, the
one case below. Without that the mechanism bounds nothing, and the bug is not obvious from
one turn:

| | request sent | measured | this turn reads |
|---|---|---|---|
| turn N | cut, ~30k | 30k | ~150k — over budget |
| turn N+1, usage only | **whole history, ~160k** | 160k | 30k — under budget |
| turn N+1, with the floor | cut held, ~45k | 45k | 30k — under budget |

`usage` measures the request that was *already* compacted, so the turn after a successful
compaction reads comfortably under budget and puts the whole, now-longer history back —
sending more than the turn that triggered. Compaction fires on alternate turns while the
uncompacted leg grows without limit, which is the failure the whole feature exists to
prevent. Carrying the count forward is safe only because a caller *appends* to history:
appending does not move the indices of a prefix, so last turn's count still names the same
messages. A caller that rewrites history instead is absorbed by the second rung below,
which cuts to the deepest boundary under the floor rather than dropping it.

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
| none that deep, one shallower | take the deepest one below the target — shed less than asked rather than nothing |
| no legal cut anywhere | **send it uncompacted** |

The target is `max(total - keep_recent, floor)`, so a `keep_recent` asking for a
shallower cut than the floor is overruled rather than honoured. Within budget there is no
target at all and the floor is the whole answer.

The second rung scans down from the target rather than from the floor, which is the one
place the floor gives way: a floor that is not itself a legal boundary — a caller rewrote
its history — is met from below, at the deepest boundary under it. The alternative is
dropping the floor and sending the history whole, which hands the caller `withheld: 0` and
restarts compaction from zero. Such a floor also pushes the target past every boundary, so
the cut can keep less than `keep_recent` asked for; the floor outranks it by design.

A floor at or past the *end* of the history is the one that is dropped rather than met.
No cut ever reaches that far, so only a rewrite produces one, and the count describes a
history that no longer exists. Meeting it from below would withhold all but the newest
exchange — and permanently, since that cut becomes the next turn's floor.

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
- **The cut only ever deepens.** Within a turn it moves at most once per round that
  reported a figure, and only downward — never back toward history it has already
  withheld, however the measurement moves after that. Across turns the previous cut is the
  floor. So the model is never re-shown history it had lost.

  Once per *measured* round, not once per round: a round that reports no `Usage` leaves the
  cut where it is rather than deepening again on a figure already acted on. Each deepening
  costs twice — it withholds context the turn cannot get back, and it replaces the
  request's leading prefix, so whatever prompt cache sits behind the provider seam has to
  be written again rather than read. Withholding history mid-tool-chain is also one of the
  things that confuses a model into the empty round below. The trade is taken because
  bounding the request is the point: a turn that cannot shed dies on the provider's
  context-length error, and a cache write costs less than a turn.

  This is the only in-turn bound there is — `produced` grows the request as the turn goes
  round — and it holds whatever was threaded in: a turn compacts on its own figure from
  round two whether it was handed a floor or not. "No measurement means no compaction"
  therefore bounds a turn's **first round**, not the whole turn.

`EndedMidToolUse` is unaffected: it reads `produced`, which compaction cannot reach. The
coupling runs the other way — withholding history is one of the things that can confuse a
model into an empty round, and that is where it lands.

## A tool failure is not a turn failure

A failing tool comes back as a `tool_result` marked `is_error`, which is what
lets the model try something else. An unknown tool name likewise —
`unknown tool: {name}` with `is_error` — and so does a gate's
`ApprovalDecision::Deny`, carrying its `reason` as the text. A refusal is
therefore recoverable within `max_rounds`, which is also what bounds a model that
keeps retrying one.

`TurnError` is only for what *ends* the turn:

| Variant | Transcript |
|---|---|
| `Provider` | — |
| `RoundLimit` | discarded |
| `EndedMidToolUse` | discarded |
| `TimedOut` | discarded |
| `StreamEndedWithoutStop` | — |
| `ToolPanicked { name }` | — |

A discarding variant discards the turn's `usage` and `withheld` with it, so a caller's
`observed` and `withheld` both keep what the last request that actually completed set.

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
>
> `sandbx-cli` makes that choice as `new_current_thread().enable_all()`:
> `spawn_blocking` is all the loop asks of the scheduler, and `enable_all` rather
> than `enable_time` because the provider's connector needs the IO driver too.

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

This is why an outer deadline is not a substitute for real cancellation (#26),
and why `approve` is asked **before** the spawn rather than racing it: a decision
that arrived late would not stop the call it refused.

## Test suite

Split by visibility, as the workspace splits everywhere: `compact.rs`'s planner is
private, so its cut-point algebra lives in `src/compact/tests.rs` beside it, while
`tests/` covers the public surface. That half splits again by subject —
`turn_loop.rs` for what one streamed turn becomes, `turn_compaction.rs` for
compaction's wiring, including that what reaches the API after a cut is still a
conversation it would accept, which is asserted on `Script::sent` rather than on
the return value.

Both drive the loop through the closure seam with the `Script` in
`tests/support/mod.rs`, deliberately **not** `MockProvider`: that double's whole body is the
`stream::iter(..).fuse()` in `canned`, and reaching for it would mean a `mock`
feature here, a `required-features` target, and a CI command naming both — three
coordinated parts, one a silent failure if forgotten, to borrow one line.
Recording requests has to live locally either way, since `MockProvider` discards
its own.
