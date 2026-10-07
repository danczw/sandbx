# The approval gate

What sits between the model asking for a tool and `sandbx-tools` running it, and
how much it actually claims. Four decisions, one per section.

## A closure, not a trait

```rust
G: FnMut(ToolCall<'_>) -> ApprovalDecision
```

`run_turn`'s fifth parameter, beside the two closure seams already there. The
alternative was an `ApprovalGate` trait with an `async fn`, which is what the
`async_trait` dependency in the original phase-5 sketch existed for; it is absent
from the workspace and from `Cargo.lock`, and a closure keeps it absent.

| | |
|---|---|
| Why not `dyn` | `dyn FnMut` is not `Send`, so taking one makes the whole future unspawnable. `observe` is generic for the same reason — see `guide-turn-loop.md` |
| Why not a trait | one implementation exists; a closed enum or a closure is the default to beat. A trait buys dispatch over a set that is not open |
| Why not async | the decision is a caller's, and a caller that needs to await one owns the runtime. An `async` bound here would re-introduce the unnamed-future problem on the gate as well as on `open` |
| Why mandatory | a defaulted gate is one a caller acquires gate-less by omitting an argument. There is no `run_turn_unchecked` |
| Why by value | three small fields, one of them `Copy`. A `FnMut(&ToolCall)` bound makes an un-annotated closure hit an HRTB inference edge |

`ToolCall` carries the resolved `BuiltinTool`, the call `id` and the `input` the
model sent, unparsed. `BuiltinTool::risk()` is reachable from the tool, so a gate
deciding by category needs nothing else; the `input` is there because a gate blind
to the arguments could never show an operator what the call would do.

## Asked before the spawn, never racing it

In `answer_calls`, between resolving the name and `spawn_blocking`.

A blocking task cannot be cancelled (#26): dropping the `JoinHandle` leaves the
task running to completion. So a gate consulted *concurrently* with the call —
`select!` on a decision and a `JoinHandle` — would answer "denied" about a `write`
that had already landed. Before the spawn is the only position where a refusal
means anything.

Two refusals sit *above* the gate, so a caller's closure never sees either and
never has to invent a verdict for one:

| | |
|---|---|
| a name no tool answers to | `from_name` is exact-match, so a miss is a prompt or schema bug |
| a tool `Turn::tools` did not offer | `from_name` resolves against every built-in, not against this turn's set |

The second matters more than it looks. The offered set is the caller's declaration
of what may run, and resolving alone would hand the gate a call that was never on
the table — which an allow-all gate would then run. A caller offering `[Read, Ls]`
would have had an injected `bash` execute. `an_unknown_name_never_reaches_the_gate`
and `an_un_offered_tool_never_reaches_the_gate` pin both.

**`approve` must not wait.** It is called on the async task, with no
`spawn_blocking` of its own. A gate that waits — on an operator, a channel, a lock
— stalls every other task on the runtime, and on the current-thread runtime
`sandbx-cli` builds it deadlocks the turn it is deciding. A bounded write is not
that: `AgentRun::gate` prints a line with `eprintln!`, as `Render` already writes
stdout from `observe`. The rule is about an unbounded wait, not about touching a
file descriptor. This is the sharp edge on
#165: a per-call prompt cannot be a blocking read from inside the gate, because the
escape hatch in the table above ("a caller that needs to await one owns the
runtime") means *before* `run_turn` is entered, not inside it. `Handle::block_on`
panics in a runtime thread and `blocking_recv` panics in async context, so neither
is the way out.

## A refusal is a `tool_result`, not a `TurnError`

`ApprovalDecision::Deny { reason }` comes back as a `tool_result` marked
`is_error`, carrying `reason` as its text — the same shape a policy refusal and an
unresolvable name already use.

So the model is told, and may answer in prose or ask for a tool the gate allows;
`max_rounds` is what bounds one that keeps retrying. `TurnError` gained no variant
and `agent-run` gained no exit code, because a refused call is a healthy turn, not
a failed one. A gate that wants to *end* a turn can still do it — deny every call
and the round limit arrives, which `agent-run` reports as an answer a bound cut
short rather than as a failure.

No audit record either. `AuditEvent::Denied` records what the sandbox refused to
let a *running* tool touch; a call that never ran touched nothing. The operator's
record is the stderr line and the transcript's is the `tool_result`.

The stderr line covers the gate's own verdict and nothing after it: a call the gate
approves and the *policy* then refuses reads on stderr as a call that ran, and the
two refusals above the gate reach stderr not at all. #169 holds that gap, which
needs a seam `observe` does not currently have.

## Deny by default, and the honest claim

`agent-run` is non-interactive, which forces the question a TUI would have hidden:
what a gate does when there is no operator to prompt. It answers from argv, before
the first request goes out.

| argv | effect |
|---|---|
| absent | the four `ReadOnly` tools run; `write`, `edit` and `bash` come back refused |
| `--allow-tool write` | + that tool. Repeatable |
| bare `--allow-tool` | every tool |

Three states from `Option<Vec<BuiltinTool>>`, exactly as `--allow-network`, and
with the same fail-closed reading of the mixed form: the bare flag beside a named
one narrows to the named one. An unknown name is refused loudly rather than
approving nothing quietly — `BuiltinTool::from_name` is exact-match, so
`--allow-tool shell` would otherwise exit 0 having approved nothing while whoever
typed it believed `bash` was allowed. Same reasoning as `--allow-env`'s
`variable_name`.

`agent-run` still offers the model all seven, and lets the gate do the narrowing.
The offered set would have been a second, independent refusal — `answer_calls`
enforces it above the gate — so declining it means one mistake in `approves` or in
a tool's declared `RiskLevel` is enough for a `bash` to run. Taken deliberately:
the refusal is what tells the operator which flag to pass, which a tool the model
was never offered cannot do. A live run is the evidence — asked to write a file
with no flag, the model tried `bash`, read the refusal, and switched to `write`.
That round is no longer the price of it: the system prompt names the approved set
before the first request (#197), so the refusal stays the operator's signal
without being the model's only route to the list.

Narrowing the offered set buys defence in depth and costs that signal, so the trade
is worth revisiting if a second caller appears; `the_risk_each_tool_carries_is_documented`
is what currently holds the classification a mistake would have to get past.

`RiskLevel` is a field of each tool's own `SPEC` rather than a table in the gate,
so a new tool declares its level or fails to compile. A denylist in the CLI would
have been silently missing it — which is the failure mode the level exists to
prevent. `tests/registry.rs` spells the expected levels out by hand: derived from
`risk()` the test would assert only self-consistency, and a `bash` reclassified as
read-only would pass.

**What this is not.** It is a decision per tool per run, not per call. Once
`--allow-tool bash` is passed, every command the model chooses to run in that turn
runs, including one a prompt injection induced. That keeps `SECURITY.md`'s standing
commitment true — a tool call you approve runs; sandbx bounds what it can reach, it
does not decide whether it should run — and leaves the per-call operator prompt to
the interactive surface, where there is somewhere to render it (#165, #133).
