# The smallest crate holds the control flow

`sandbx-agent` is eight source files and about fifteen hundred lines, and it is
the box [04 — the architecture](04-the-architecture.md) draws twice: in View 2
the round that opens a stream, consumes it and answers what the model asked for,
in View 3 **the gate** — "`CallGate`, two methods, `run_turn`'s mandatory fifth
parameter".

[13 — nothing runs until the gate has answered](13-turn-loop-and-gate.md) is
this crate's chapter in the read-through, and the longest in the set. Read it
first. Nothing in it is re-argued here: not the two refusals above the gate, the
three verdicts and the exhaustive `match` that keeps them three, `approve`
preceding `spawn_blocking`, the adversary at the prompt, the round limit, or the
exit code an abort earns. The round loop from first principles — why re-entry
keys on the *presence* of `ToolUse` blocks and never on a `StopReason` — is
[02](02-what-a-harness-is.md), and [guide-turn-loop.md](../guide-turn-loop.md)
is the authority for both the loop and compaction. What is left is the module
map, the signature a caller meets, and `compact.rs`.

## The module map

```
src/lib.rs          13 re-exports and four private modules; nothing else
   turn.rs          run_turn, and the public types it is driven by
      accumulate.rs one round's assistant message, rebuilt from deltas
      tools.rs      the offered set, the gate call, one spawn_blocking
   approval.rs      what a gate is asked and what it is told; no policy
   compact.rs       which prefix of a history may be withheld
      tests.rs      the cut-point algebra, as unit tests
   error.rs         TurnError — only what ends a turn in failure
tests/
   turn_loop.rs       what one streamed turn becomes
   turn_compaction.rs compaction's wiring, asserted on what was sent
   audit_trail.rs     one model-issued call, through to a decision= field
   support/mod.rs     the Script provider double and the request builders
```

Three things to read off that shape. **The deepest path is two levels**, and
`turn.rs`'s two children are the two halves of a round: rebuilding what arrived,
running what it asked for. **`turn.rs` is the one file over the module budget**,
which its own doc says outright, because a new way for a turn to stop is one
edit to `TurnStop`, one to the loop that chooses it and one to the outcome that
carries it. **The test tree is larger than `src/`**, about 2,500 lines against
1,500 — the last section is why.

Of four runtime dependencies, one carries its constraint in a comment:

```toml
# Not `rt-multi-thread`: the runtime flavour is the binary's call. `time` is not
# optional — `run_turn` panics on the first round without a timer.
tokio = { version = "1.53.1", default-features = false, features = ["rt", "time"] }
```

The other three are `sandbx-providers`, `sandbx-tools` and `serde_json`.
`sandbx-core` is missing on purpose: it is a **dev**-dependency, the only one of
its kind in the workspace, so `sandbx_core` cannot be named anywhere in `src/`
and the crate deciding which tool calls happen cannot form an opinion about a
`SandboxPolicy`. [05](05-seven-crates.md) spends a section on the argument.

## `lib.rs` is thirteen names, and that is the whole API

[`lib.rs`](../../crates/sandbx-agent/src/lib.rs) is fifteen lines: four private
`mod` declarations and three `pub use` lines. The re-export list *is* the public
surface, so group it by what each name is for:

| group | names |
|---|---|
| what you call | `run_turn` |
| what you pass in | `Turn`, `TurnLimits`, `Compaction` |
| what you must implement | `CallGate` |
| what your implementation is handed | `ToolCall`, `Settled`, `Outcome` |
| what it answers with | `ApprovalDecision` |
| what you get back | `TurnOutcome`, `TurnStop`, `PromptUsage`, `TurnError` |

The minimum set to call `run_turn` once is smaller than thirteen: a `Turn`
(needing `TurnLimits`, which has a `Default`), a `CallGate` impl (dragging in
`ToolCall`, `Settled` and `ApprovalDecision` to write the two bodies), and
`TurnOutcome` or `TurnError` to handle. `Compaction` and `PromptUsage` are for a
caller threading token counts between turns, `TurnStop` for one distinguishing
how a turn ended — which `agent-run` does, its exit code depending on it.

Two types a caller also needs are *not* here, and their absence is the seam:
`ExecutionContext` and `BuiltinTool` are `sandbx-tools`', `RequestMessage`,
`Prompt`, `AgentEvent` and `StopReason` are `sandbx-providers`'. Neither set is
re-exported, so a caller imports from all three.

## `turn.rs` — the signature before the body

[`turn.rs`](../../crates/sandbx-agent/src/turn.rs) exports one async function
and the five types that drive it. Read the signature before the loop:

```rust
pub async fn run_turn<F, O, G>(
    mut open: F,
    turn: Turn<'_>,
    ctx: &ExecutionContext,
    mut observe: O,
    mut gate: G,
) -> Result<TurnOutcome, TurnError>
where
    F: AsyncFnMut(Prompt) -> Result<EventStream, ProviderError>,
    O: FnMut(&AgentEvent),
    G: CallGate,
{
```

Three of the five parameters are generic, and the first is the crate's most
consequential choice: **the loop is generic over a closure that opens a stream,
not over a provider trait.** No `Provider` to implement, no `dyn` in the path,
no test double in anybody's public API. A closure returning a canned
`EventStream` is a complete provider as far as `run_turn` is concerned, which is
what `tests/support/mod.rs`'s `Script` exploits: the whole loop runs with no
network and no API key.

`AsyncFnMut` rather than a separate future parameter leaves that future unnamed,
so a *generic* wrapper cannot add its own `Send` bound;
`documented_call_shape_stays_spawnable` pins that a real caller's future is
still `Send`. `observe` is generic for the mirror reason, `dyn FnMut` not being
`Send`. `gate` being mandatory rather than an `Option` is
[13](13-turn-loop-and-gate.md)'s opening point.

The body is a `for` over `max_rounds` with seven mutable locals above it, three
there only for compaction, and exactly one place a `TurnOutcome` is built: a
private `outcome` helper whose first act is to strip every reasoning block, per
[decision-thinking-replay.md](../decision-thinking-replay.md).

## `turn/accumulate.rs` — a round's message, rebuilt

[`turn/accumulate.rs`](../../crates/sandbx-agent/src/turn/accumulate.rs) drains
one `EventStream` into the blocks it describes, plus the round's token counts
and stop reason, as a crate-private `Round`. Text deltas accumulate into a
`String` flushed immediately before any `ToolUse` or reasoning block, the API
reading a content array in order. Counts are last-one-wins rather than summed,
which makes `Usage` having to arrive *before* `Stop` an ordering dependency
whose breakage would be silent: counts always `None`, compaction never firing.

**Two files in this repo are named `accumulate.rs`, doing different jobs**, and
a reader grepping the name hits both:

| file | what it folds |
|---|---|
| [`providers/src/anthropic/wire/accumulate.rs`](../../crates/sandbx-providers/src/anthropic/wire/accumulate.rs) | raw SSE frames into vendor-neutral `AgentEvent`s |
| [`agent/src/turn/accumulate.rs`](../../crates/sandbx-agent/src/turn/accumulate.rs) | `AgentEvent`s into one replayable `RequestMessage` |

The provider's sits below the vendor boundary and knows `content_block_start`
from `message_delta`; this crate's sits above it and has never heard of SSE. See
[20 — the providers crate](20-crate-providers.md) for the lower half.

## `turn/tools.rs` — the offered set, the gate, and the one blocking site

[`turn/tools.rs`](../../crates/sandbx-agent/src/turn/tools.rs) holds
`answer_calls`, which [13](13-turn-loop-and-gate.md) takes apart decision by
decision. Two things here are the module's own. The smaller is `definition`, a
seven-line bridge from a `BuiltinTool` to the `ToolDefinition` a request
carries; it keeps no table, name and description and schema coming from one
`SPEC` per tool in `sandbx-tools`, and `run_turn` builds the whole `Vec` once
before the first round.

The larger is the **only `spawn_blocking` call site in the harness**:

```rust
        // Cloned because `spawn_blocking` needs `'static`, once per call since the closure
        // consumes it; an `Arc` would only pay off past a few path lists.
        let arguments = input.clone();
        let context = ctx.clone();
        let outcome = tokio::task::spawn_blocking(move || tool.execute(arguments, &context))
            .await
            .map_err(|_| TurnError::ToolPanicked {
                name: name.to_string(),
            })?;
```

Why a tool call has to leave the executor: the seven built-ins are
*synchronous*, and on the current-thread runtime `sandbx` uses, a 90-second
`bash` inline would freeze every other task for 90 seconds. The module doc gives
that as the reason the file exists: the boundary lives here "rather than spread
through seven tool bodies".

What #26 records is the cost. **A blocking task cannot be cancelled** — dropping
the `JoinHandle`, which is what dropping the `run_turn` future does, leaves it
running to completion. One kernel fact, four consequences in four crates: a turn
abandoned mid-tool still applies the `write`; the audit trail is then the only
record, the transcript having gone with the dropped future; an outer deadline is
no substitute, which is why `TurnLimits` bounds a round's *streaming* and not
the turn; and `approve` precedes the spawn rather than racing it. The last is
[13](13-turn-loop-and-gate.md)'s, the first is why [01](01-what-sandbx-is.md)
says `tui` can stop a turn but not a tool. A `JoinError` becomes
`TurnError::ToolPanicked { name }`, approximate by its own admission —
"almost always a panic in the tool, though a runtime shut down mid-flight looks
the same".

## `approval.rs` — the shapes, not the policy

[`approval.rs`](../../crates/sandbx-agent/src/approval.rs) is 110 lines holding
four types and the trait, and no policy at all: no risk table, no allowlist, no
default verdict. Every judgement is the caller's gate's, which for the shipped
binary is `ArgvGate` in `sandbx-cli`; [13](13-turn-loop-and-gate.md) is the
chapter for what that one decides and in which order. Here are the shapes.

**What a gate is asked.** `ToolCall` is three fields: the resolved `tool`, the
`id` the answer must carry back, and `input` as the model sent it, unparsed,
because each tool parses its own. `Copy`, and borrowed.

**The three answers.** `ApprovalDecision` is a closed enum whose third variant
must not be collapsed into the second:

| variant | the call | the turn |
|---|---|---|
| `Allow` | runs | continues |
| `Deny { reason }` | comes back as a `tool_result` marked `is_error` | continues, bounded by `max_rounds` |
| `Abort { reason }` | the same, and every call behind it in the round is refused unasked | ends, as `TurnStop::GateAborted` |

`Abort` is for a gate that can no longer be *asked* — a consent channel that
went away — not one that decided no, and
[decision-approval-gate.md](../decision-approval-gate.md) has why it had to be
public rather than a latch in the CLI.

**What a gate is told.** `Settled` carries the name the model used, the id, the
resolved tool or `None`, the input, and an `Outcome`:

| outcome | reached when |
|---|---|
| `Unknown` | no built-in answers to the name the model used |
| `NotOffered` | a real tool, but not one this turn's `Turn::tools` offered |
| `Denied { reason }` | the gate refused it, or an earlier `Abort` refused it unasked |
| `Ran` | it executed and returned output |
| `Errored(&ToolError)` | it executed and the policy or the tool refused it |

Five rather than two is #169's point: three of those never reach `approve`, so a
gate reporting only its own verdicts would account for neither the refusals
above it nor what an approved tool went on to do. `settled` is called exactly
once per `tool_use` block, whatever became of it.

- **Worth questioning:** `Outcome` cannot distinguish a verdict the gate gave
  from one the loop gave on its behalf. A call refused unasked behind an `Abort`
  latch arrives as `Denied { reason }` carrying the abort's reason, identical in
  shape to a call the gate decided, and `sandbx-cli`'s `report` renders both as
  "refused: …". [decision-approval-gate.md](../decision-approval-gate.md) makes
  that distinction load-bearing one section earlier — the calls behind an abort
  "are refused *unasked* rather than allowed on the strength of a verdict nobody
  gave" — and the enum then spends a variant on telling a policy refusal from a
  gate refusal, the same class of distinction, and nothing on this one. The
  record prices the variants it has, "whichever of the five outcomes it
  reached", not the one it lacks; a sixth, or a flag on `Denied`, costs one
  `match` arm in one renderer.

**The trait, and the blanket impl.** `CallGate` has two required methods and no
provided one: a reporter a caller acquires by omitting an argument is one nobody
chose. Both run on the async task, so neither may wait on anything *the runtime
drives* — a tokio primitive, a channel, a lock a task holds — which on a
current-thread runtime deadlocks the turn being decided. A descriptor no task
feeds is outside that class, which is what lets `sandbx-cli` read `/dev/tty`
inside `approve`. The file's last lines are the piece a caller trips over:

```rust
/// So a caller that keeps its gate can lend it, `run_turn` taking one by value.
impl<G: CallGate + ?Sized> CallGate for &mut G {
```

`run_turn` takes `gate: G` by value, so without that impl a caller would lose
its gate to the turn. With it, `&mut my_gate` is itself a `CallGate` and the
caller still holds it afterwards to read what it recorded.

## `compact.rs` — a cut-point algebra, not a line of arithmetic

The module no other chapter covers. The problem is
[02](02-what-a-harness-is.md)'s: every round resends everything, so a long
conversation eventually dies on the provider's context-length error.
[`compact.rs`](../../crates/sandbx-agent/src/compact.rs)'s answer, in its module
doc's words, is "naive compaction: withhold the oldest history from a request
that has grown past a caller's token budget… No summarisation model, just a
bounded window."

**It is opt-in, and `None` is the default.** `TurnLimits::compaction` is an
`Option<Compaction>` the default leaves empty, and the field's doc states the
asymmetry: it is "the only bound here that is lossy: the others refuse to go on
when hit, where this one quietly sends the model less". The crate will not pick
a value, the right one depending on a model and `Turn::model` being a freeform
string with no context-window table behind it. `Compaction` is two fields and no
methods — `budget_tokens`, the figure a *measured* prompt must exceed, and
`keep_recent`, how many of the newest messages to aim to keep. Both are targets.

### Measured, never predicted

`over_budget` is a two-line predicate over `Option<PromptUsage>`, and the
`Option` is the whole of it: a `None` measurement never fires, because guessing
would compact a conversation that may be two messages long. `prompt_tokens` sums
all three prompt-side counters of the last `AgentEvent::Usage` a turn saw —
`input_tokens`, `cache_read_tokens`, `cache_write_tokens` — in `u64`, three
saturated `u32`s overflowing one; a cache read is a real prompt token charged
against the window.

The consequence to get right: compaction cannot fire on the first round of a
*conversation*, there being no figure yet — but it can fire on the first round
of a later turn, on the figure the caller threaded in through `Turn::observed`.
Within a turn the `measured` flag allows at most one re-plan per round that
reported a figure:

```rust
        if measured && let Some(policy) = turn.limits.compaction {
            // Within budget asks only to hold the floor; `None` would undo the cut already
            // paid for.
            let keep_recent =
                compact::over_budget(observed, policy.budget_tokens).then_some(policy.keep_recent);
            // A plan always contains the previous cut, so `unwrap_or` stops a declined plan
            // from restoring history.
            cut =
                compact::plan_cut(turn.history, produced.len(), keep_recent, floor).unwrap_or(cut);
            floor = cut;
            measured = false;
        }
```

Both halves of the thread-back are required, and threading one is a bug
invisible from a single turn: `usage` measures the *already compacted* request,
so the turn after a successful compaction reads comfortably under budget and
puts the whole, now-longer history back. `TurnOutcome::withheld` into the next
`Turn::withheld` prevents it — a floor the next cut may deepen and never
reverse. [guide-turn-loop.md](../guide-turn-loop.md) has the table that makes
the failure concrete.

### Which prefix may be withheld, and which may never be

The API rejects anything but a user-turn opener, so only a *prefix* may drop,
and whatever becomes the new first message must be something it accepts.
`opens_a_request` is that predicate and the whole of the law:

```rust
fn opens_a_request(history: &[RequestMessage], cut: usize) -> bool {
    cut > 0
        && history.get(cut).is_some_and(|first| {
            matches!(first.role, Role::User)
                && !first.content.is_empty()
                && !first
                    .content
                    .iter()
                    .any(|block| matches!(block, ContentBlock::ToolResult { .. }))
        })
}
```

Three conditions, each with a distinct failure behind it. A cut onto an
assistant message strands `tool_use` blocks whose answers would become a second
user turn. A cut onto a message carrying a `ToolResult` orphans it, its
`ToolUse` sitting in the message just withheld — the clause that makes an
arbitrary index illegal. Empty content the API rejects outright. Hence the
conclusion worth memorising: **in a tool-heavy transcript the legal cut points
are exactly the human prose turns** — one per exchange, not one per message.

`plan_cut` is the planner over that predicate, and its doc commits to being
"pure and total: every lookup goes through `get`, every subtraction guarded, so
it cannot panic, diverge, or return an invalid or empty cut". Four guarantees
`run_turn` leans on:

- **Every `Some` satisfies `opens_a_request`** — never a cut the API rejects.
- **`produced` is a *count*, not a slice**, so no cut can reach this turn's own
  messages and no turn withholds the tool result the model waits on.
- **The cut only deepens.** A plan always contains the previous cut, and
  `run_turn` applies it with `unwrap_or(cut)`, so a declined plan cannot restore
  withheld history.
- **A legal `floor` is met exactly**; an *illegal* one, which only a caller that
  rewrote its own history produces, is met from below.

When nothing legal is deep enough there are three rungs, ending in "send it
uncompacted"; the reasoning for each is the guide's.

### What is lost

- **Whole exchanges of conversation**, oldest first, invisibly to the model, and
  with them **the prompt cache's leading prefix** — written again rather than
  read, the request no longer starting where it did. This is the one bound in
  the loop that does not announce itself.
- **Every reasoning block already sent this turn.** A signature is valid only
  against the messages preceding it, so deepening the cut invalidates all of
  them; `run_turn` strips them when `withheld` moves, dropping the oldest
  reasoning being the one edit the provider's check permits, where a *gap* is
  not.
- **Nothing from stored history.** `TurnOutcome::messages` is always the
  complete turn: compaction narrows the *request*, never the transcript, a loss
  there compounding every turn — `compaction_never_shortens_the_transcript`.

One enormous exchange cannot be shed at all, so the provider's own
context-length error stays the real backstop. A cut landing *inside* a message
is #208, which a single `withheld` index cannot express. And the one rewrite the
CLI performs — merging a run of user messages into one (#188) — means the prompt
resuming a round-limited turn carries a `ToolResult` and is not a boundary, so a
session that caps on every turn can run out of cut points.

### `compact/tests.rs` — why the algebra has its own test module

[`compact/tests.rs`](../../crates/sandbx-agent/src/compact/tests.rs) is 484
lines against the module's 117, the largest test-to-code ratio in the crate, and
a unit module rather than an integration target because `plan_cut` and
`opens_a_request` are `pub(crate)` and private. Its shape is worth copying: five
constructors build the vocabulary — `user_text` ("the only shape that is a legal
cut point"), `assistant_call`, `user_result`, `empty_user` ("a shape `run_turn`
never produces, but a caller editing its own history can") and `exchange`, one
complete quartet — `shapes()` returns five histories spanning the interesting
cases, and two tests sweep the whole product of history, `produced`, `floor` and
`keep_recent` against the postconditions:

```rust
/// The postcondition `run_turn`'s monotonicity rests on, whatever floor it was given.
#[test]
fn every_plan_opens_a_request() {
    for history in shapes() {
        for produced in 0..4 {
            for floor in [0, 1, 2, 3, 4, 5, 99] {
                for keep_recent in [None, Some(0), Some(1), Some(2), Some(3)] {
                    if let Some(cut) = plan_cut(&history, produced, keep_recent, floor) {
```

Four `for` loops and no framework, which is the right tool here: the
postconditions are universally quantified and the input space small enough to
enumerate. The other thirty-odd tests are named after single facts —
`an_illegal_floor_falls_back_below_itself` — so a failure says which rule broke.

### Nothing in the shipped binary turns it on

Verified in this worktree rather than inferred. The two places that build a
`TurnLimits` — `AgentRun::execute` in
[`cli/src/agent.rs`](../../crates/sandbx-cli/src/agent.rs) and the TUI's in
[`cli/src/agent/tui.rs`](../../crates/sandbx-cli/src/agent/tui.rs) — both write
`max_rounds: …, ..TurnLimits::default()`, and the wrap-up round copies what it
was handed. `max_rounds` has a flag; compaction has none, so the feature is
reachable only by a library caller. [02](02-what-a-harness-is.md) raises that as
a design question and [17](17-gaps-and-open-questions.md) collects it. Even so,
[decision-on-disk-state.md](../decision-on-disk-state.md) has `agent-run` store
`observed` and `withheld` in every transcript, recoverable as they are only at
the moment the turn produces them — "Do not delete it as dead weight."

- **Worth questioning:** compaction's correctness condition is "the API would
  still accept this request", and no test in the repo can check it.
  `opens_a_request` is the repo's *model* of what the API rejects, and
  [guide-turn-loop.md](../guide-turn-loop.md)'s test-suite section names the
  strongest assertion available — that what reaches the API after a cut "is
  still a conversation it would accept, which is asserted on `Script::sent`
  rather than on the return value". But `Script` accepts every request handed to
  it and replays a canned round regardless, so that assertion checks the rules
  against themselves. With the paragraph above, no request this module shaped
  has ever been sent to Anthropic from the shipped binary. That is a different
  objection from "there is no flag": a flag would also be the first thing that
  could *falsify* `opens_a_request`. The cheap version is not a flag at all —
  one recorded live run through a library caller, with the request bodies kept.

## `error.rs` — only what ends a turn in failure

[`error.rs`](../../crates/sandbx-agent/src/error.rs) is one enum, a `Display`
impl, and an `Error` impl whose `source` is `Some` for exactly one variant. The
type's doc states what belongs in it — "a tool that fails is not an error here:
a refused or malformed call goes back to the model as a `tool_result` marked
`is_error`, the turn still healthy."

| variant | cause |
|---|---|
| `Provider(ProviderError)` | the stream failed to open, or failed partway |
| `StreamEndedWithoutStop` | it ended without ever saying the turn was over |
| `EndedMidToolUse` | the model produced nothing with a `tool_result` unanswered |
| `TimedOut { after }` | one round outran `stream_timeout` |
| `ToolPanicked { name }` | a tool's blocking task returned no result |

`Provider` is carried rather than flattened, so a caller can reach
`ProviderError::is_retryable` and `retry_after`. `EndedMidToolUse` is a *choice*
rather than a fault: returning `Ok` would hand back a transcript ending on an
unanswered `tool_result`, breaking the request *after* the one that went wrong,
so the turn is discarded instead.

**`TurnError` and `TurnStop` are the two halves of "how did this end", and they
do not overlap.** `TurnError` is the `Err` side, five ways a turn failed;
`TurnStop` is a field of `TurnOutcome` on the `Ok` side, three ways a turn
finished without failing — `Answered`, `RoundLimit { rounds }`, `GateAborted` —
running out of rounds and losing the operator being deliberately not errors,
because the model did real work first. `TurnOutcome::round_stop` is a third
thing and orthogonal to both: the provider's own `StopReason` for the last
round, reported and never branched on.

## The test suite fakes the provider and runs the real tools

Four files, divided by subject rather than by module:

| target | subject |
|---|---|
| [`tests/turn_loop.rs`](../../crates/sandbx-agent/tests/turn_loop.rs) | what one streamed turn becomes: deltas, reasoning replay, the gate, the traps, both bounds |
| [`tests/turn_compaction.rs`](../../crates/sandbx-agent/tests/turn_compaction.rs) | compaction's wiring, asserted on what the provider *received* |
| [`tests/audit_trail.rs`](../../crates/sandbx-agent/tests/audit_trail.rs) | one model-issued call end to end, through to a `decision=` field |
| [`tests/support/mod.rs`](../../crates/sandbx-agent/tests/support/mod.rs) | the `Script` double and the request builders both halves share |

`audit_trail.rs` is its own binary for a reason worth knowing before writing any
`tracing` test in this repo: the subscriber has to be the *global* one, because
tools run on `spawn_blocking` and a thread-local subscriber is not installed on
the thread that emits. [14](14-audit-sessions-credentials.md) is the trail
itself.

`Script` is the double: two fields, two methods.

```rust
    pub(crate) async fn open(&mut self, prompt: Prompt) -> Result<EventStream, ProviderError> {
        self.sent.push(prompt.clone());
        // Not `unwrap_or_default`: an empty round surfaces as `StreamEndedWithoutStop`,
        // so a miscounted script would fail with a misleading cause.
        let events = self
            .rounds
            .pop_front()
```

A `VecDeque` of canned rounds popped one per call, and a `Vec<Prompt>` of what
was asked — that second field being what makes the compaction suite possible, a
cut showing only in the *request*. Deliberately not `sandbx-providers`'
`MockProvider`, which would cost a `mock` feature and a `required-features`
target to borrow one line.

**The provider is fake; the tools are real.** `AllowAll` approves everything and
reports nothing — "for the tests whose subject is not the gate: the policy in
`ctx` scopes those" — and `ctx` builds a genuine `ExecutionContext` from a
genuine `SandboxPolicy` over a `tempfile::tempdir()`, each grant pinned by
`vetted` to the object it names (#212). So `BuiltinTool::execute` runs for real:
a `write` writes, an `ls` on a missing path produces the real `ToolError`, and
`FsGuard` makes the real decision and emits the real trail line. What that tests
and a mocked tool would not:

- **That dispatch and the tool contract actually meet.** A mocked tool is built
  to the test's model of `execute`; the real one fails when the contract drifts.
- **That a policy refusal reaches the model in the right shape**, as a
  `tool_result` marked `is_error` carrying the guard's own reason, and that the
  access is recorded with the decision the rules imply — which
  `a_model_issued_call_records_its_access` asserts as `allowed` then `absent`
  across two calls of one turn, in that order.
- **That the sync/async boundary holds**, the tools really running on
  `spawn_blocking`, which is what forces the global subscriber above.

And what it therefore cannot test:

- **Anything about the real wire.** `Script` never serialises a `Prompt` and
  never parses SSE. Whether a request this loop built is one Anthropic accepts
  is `sandbx-providers`' question, and for compaction specifically nobody's.
- **Anything about the real kernel boundary.** `bash` is the one tool needing
  Landlock, seccomp and namespaces, and those suites live in `sandbx-core` — so
  a turn-loop test on a kernel with no sandbox support is still meaningful.
- **Anything about a real operator.** `AllowAll` is not `ArgvGate`; the
  terminal, the typeahead flush and the consent prompt are `sandbx-cli`'s.
- **Concurrency between two tool calls**, there being none: `answer_calls` is
  sequential until the ordering semantics of two tools sharing one
  `ExecutionContext` are settled (#242).

## You should now be able to explain

- Which box of 04's request path this crate is, and which chapter owns the gate
  it contains.
- The minimum set of re-exported types needed to call `run_turn` once, and which
  of the thirteen a caller threading no token counts never touches.
- What being generic over a stream-opening closure buys, and what `AsyncFnMut`
  costs a generic wrapper.
- Why a tool call is the one thing in this async program that has to leave the
  executor, and the four consequences #26 records of its being uncancellable.
- The three answers a gate may give and which ends the turn, plus the five
  outcomes a call may be reported to have reached.
- Why the legal cut points of a tool-heavy transcript are exactly the human
  prose turns, and the three conditions `opens_a_request` checks to say so.
- Why compaction fires on a measured figure and never a predicted one, why both
  `usage` and `withheld` have to be threaded back, and what it loses.
- The difference between `TurnError`, `TurnStop` and `TurnOutcome::round_stop`.
- Why the agent suite fakes the provider and not the tools, and three things
  that choice cannot test.

## Next

[22 — the session crate](22-crate-session.md): where the `TurnOutcome` this
crate hands back goes on disk, how a resumed conversation gets its `observed`
and `withheld` figures back, and the predicates deciding which orders of
messages a stored transcript may legally carry.
