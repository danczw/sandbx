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

In `answer_calls`, between `BuiltinTool::from_name` and `spawn_blocking`.

A blocking task cannot be cancelled (#26): dropping the `JoinHandle` leaves the
task running to completion. So a gate consulted *concurrently* with the call —
`select!` on a decision and a `JoinHandle` — would answer "denied" about a `write`
that had already landed. Before the spawn is the only position where a refusal
means anything.

The consequence worth knowing: a name no tool answers to is refused above the
gate, so a caller's closure never sees one and never has to invent a verdict for
it. `an_unknown_name_never_reaches_the_gate` pins that.

## A refusal is a `tool_result`, not a `TurnError`

`ApprovalDecision::Deny { reason }` comes back as a `tool_result` marked
`is_error`, carrying `reason` as its text — the same shape a policy refusal and an
unresolvable name already use.

So the model is told, and may answer in prose or ask for a tool the gate allows;
`max_rounds` is what bounds one that keeps retrying. `TurnError` gained no variant
and `agent-run` gained no exit code, because a refused call is a healthy turn, not
a failed one. A gate that wants to *end* a turn can still do it — deny every call
and the round limit arrives.

No audit record either. `AuditEvent::Denied` records what the sandbox refused to
let a *running* tool touch; a call that never ran touched nothing. The operator's
record is the stderr line and the transcript's is the `tool_result`.

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
