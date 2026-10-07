# The approval gate

What sits between the model asking for a tool and `sandbx-tools` running it, and
how much it actually claims. Five decisions, one per section.

## A trait, not a closure

```rust
pub trait CallGate {
    fn approve(&mut self, call: ToolCall<'_>) -> ApprovalDecision;
    fn settled(&mut self, call: Settled<'_>);
}
```

Still `run_turn`'s fifth parameter and still one generic. It was a bare
`FnMut(ToolCall<'_>) -> ApprovalDecision`; what made it a trait is that a verdict
is only half of what a gate has to know, the other half being what became of the
call it approved (#169). Two methods on one type rather than a sixth parameter,
which a caller could take the verdict from and leave the report behind. The
alternative was an `ApprovalGate` trait with an `async fn`, which the
`async_trait` dependency in the original phase-5 sketch existed for; it is absent
from the workspace and from `Cargo.lock`, and a sync trait keeps it absent.

| | |
|---|---|
| Why not `dyn` | `dyn FnMut` is not `Send`, so taking one makes the whole future unspawnable. `observe` is generic for the same reason — see `guide-turn-loop.md` |
| Why not a new `AgentEvent` | #169 declines one. A settling is not a stream event, and an event would arrive at `observe`, which is the renderer and has no verdict to correlate it against |
| Why not async | the decision is a caller's, and a caller that needs to await one owns the runtime. An `async` bound here would re-introduce the unnamed-future problem on the gate as well as on `open` |
| Why both methods required | a defaulted reporter is one a caller acquires silently by omitting it — the argument that already made the gate mandatory. There is no `run_turn_unchecked` |
| Why `ToolCall` by value | three small fields, one of them `Copy`. A `FnMut(&ToolCall)` bound makes an un-annotated closure hit an HRTB inference edge |
| Why the gate by value | a caller that keeps its own gate lends it instead: `&mut G` has a blanket impl, so the records survive the turn |

`ToolCall` carries the resolved `BuiltinTool`, the call `id` and the `input` the
model sent, unparsed. `BuiltinTool::risk()` is reachable from the tool, so a gate
deciding by category needs nothing else; the `input` is there because a gate blind
to the arguments could never show an operator what the call would do.

`Settled` carries the same `id` and `input` with an `Outcome` — `Unknown`,
`NotOffered`, `Denied`, `Ran` or `Errored` — and a `name` that is present even
when nothing resolved it. Three of the five never reach `approve`, which is why
the report cannot be built from the verdict. It carries the `input` rather than
expecting the gate to have remembered the call by id, and `Errored` borrows the
`ToolError` rather than flattening it: the five arms read differently to an
operator, and a `Display` string would have to be re-parsed to tell a policy
refusal from a timeout.

`settled` is not called for the one failure that ends the turn. A panicking tool
is a `TurnError::ToolPanicked` and the round has no result to report.

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

**Neither method may wait on the runtime.** Both are called on the async task,
with no `spawn_blocking` of their own. A gate that waits on anything the runtime
itself has to drive — a tokio primitive, a channel a task feeds, a lock a task
holds — stalls every other task on it, and on the current-thread runtime
`sandbx-cli` builds it deadlocks the turn it is deciding. `Handle::block_on`
panics in a runtime thread and `blocking_recv` panics in async context, so neither
is the way out.

A descriptor no task feeds is not that class, which is the narrower rule #165
needed. `ArgvGate` writes its report with `eprintln!`, as `Render` already writes
stdout from `observe`, and under `--approve call` it reads the operator's answer
from `/dev/tty` inside `approve` — unbounded in time, bounded in scheduling.
During that read nothing else is in flight in `agent-run`: the round's stream has
ended, its timeout is dropped, and `answer_calls` is sequential. Staying sync is
what keeps `run_turn`'s future `Send` (`documented_call_shape_stays_spawnable`)
and keeps RPITIT off the trait. The limit is a precondition on the caller, so
#133, which drives a UI from the same runtime, has to meet it again rather than
inherit it.

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

That stderr line is `settled`'s, not `approve`'s, so it covers what became of a
call rather than only what the gate said about it: a call the gate approves and
the *policy* then refuses reads as a refusal rather than as one that ran, and the
two refusals above the gate reach stderr at all (#169). One line per `tool_use`
block, whichever of the five outcomes it reached.

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

## The operator is the floor, argv the ceiling

Argv alone is a decision per tool per run: once `--allow-tool bash` is passed,
every command the model chooses to run in that turn runs, including one a prompt
injection induced (#165). `--approve call` adds a second answer below the first —
one per call, asked on `/dev/tty`, for the tools that write or run a program.

| | |
|---|---|
| asked in that order | argv first. A prompt that could only ever be refused is fatigue with no decision in it, and it teaches an operator to answer `y` |
| why not stdin | stdout carries the model's answer and is piped, and `agent-run`'s prompt comes from argv. `/dev/tty` is the one channel the operator still holds |
| why read-only is never asked | the twenty-prompt turn #165 describes is what this and the `a` answer exist to avoid, and a `read` has no answer worth taking |
| why `a` is per tool | an operator who has judged one `write` has judged the tool for the run; carrying it across tools would make a single `a` a bare `--allow-tool` |
| why the arguments are capped and stripped | they are model-chosen, and a `path` carrying ANSI escapes rewrites the question being answered. Shared with the report, so one strip covers both — and it covers the whole line, a policy refusal's own text included, since `SandboxError`'s `Display` writes the path back |
| why a newline is spelled, not replaced | a heredoc shown as a row of U+FFFD is a command consented to unread, which the cap exists to avoid |
| why the subject is keyed off the tool | no input type refuses an unknown field, so a `bash` call carrying a decoy `path` beside its `command` would be named by the path in both the question and the report |

**No consent channel, no consent.** `--approve call` with no `/dev/tty` refuses
before the first request rather than taking the argv answer. Falling back is
fail-closed against the default and fail-**open** against the request: an operator
who passed the flag chose a decision per call, and quietly serving them one per
run hands the run a weaker regime than they asked for. The refusal names the flag
to drop, since dropping it is the whole remedy.

**The model's answer shares that terminal.** stdout is usually the same device,
and it streams before the gate asks, so the model can leave an SGR state behind
or print text that reads like a question. The question is written after a
`\x1b[0m` reset for the first of those. For the second the bound is positional
rather than visual: the read happens inside `approve`, so an answer applies to
the call being decided whatever else is on screen, and a counterfeit question
cannot consume it. A counterfeit that makes the real one *look* already answered
is not covered — stripping the model's own prose would mangle the answer the
operator asked for.

**What this is not.** Neither mode decides whether a call *should* happen, only
whether it may. `SECURITY.md`'s standing commitment holds under both — a tool call
you approve runs; sandbx bounds what it can reach, it does not judge the intent
behind it — and an operator answering `y` to a question whose arguments they did
not read has approved it as surely as a flag would have. #133 is where the same
question gets a surface with somewhere to render it.
