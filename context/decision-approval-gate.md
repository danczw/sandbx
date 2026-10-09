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
ended, its timeout is dropped, and `answer_calls` is sequential, which #242
records as a constraint rather than a design choice. Staying sync is what keeps
`run_turn`'s future `Send` (`documented_call_shape_stays_spawnable`) and keeps
RPITIT off the trait. The limit is a precondition on the caller, so
#133, which drives a UI from the same runtime, has to meet it again rather than
inherit it.

## A refusal is a `tool_result`, not a `TurnError`

`ApprovalDecision::Deny { reason }` comes back as a `tool_result` marked
`is_error`, carrying `reason` as its text — the same shape a policy refusal and an
unresolvable name already use.

So the model is told, and may answer in prose or ask for a tool the gate allows;
`max_rounds` is what bounds one that keeps retrying. `TurnError` gained no
variant, because a refused call is a healthy turn, not a failed one. A gate that
wants to *end* a turn says so instead, which is the section below.

No audit record either. `AuditEvent::Denied` records what the sandbox refused to
let a *running* tool touch; a call that never ran touched nothing. The operator's
record is the one line per call and the transcript's is the `tool_result`.

That line is `settled`'s, not `approve`'s, so it covers what became of a call
rather than only what the gate said about it: a call the gate approves and the
*policy* then refuses reads as a refusal rather than as one that ran, and the two
refusals above the gate are reported at all (#169). One line per `tool_use`
block, whichever of the five outcomes it reached.

**It goes where the question went.** stderr by default; the terminal under
`--approve call`, which is the same reason the question is not on stderr either.
Both directions on one channel or neither: `2> run.log` would otherwise leave an
operator answering call N+1 having not seen what call N did, which is consent
given with the evidence redirected away.

## A lost channel is a third verdict

A gate that can no longer be *asked* is not a gate that said no.
`ApprovalDecision::Abort { reason }` answers the call as a `Deny` would, refuses
every call behind it in the round without asking, and ends the turn as
`TurnStop::GateAborted`. `agent-run` exits 3 for it.

#218 filed two defects against the old behaviour, and only the pair of them
justifies a public variant. A hung-up terminal already refused correctly and
promptly — but the turn went round again and opened another provider stream,
paid for with nobody at the other end, and the process exited 0, so an
unattended caller read a vanished operator as success.

**The trigger is the CLI's; the mechanism cannot be.** Distinguishing a channel
failure from an operator's `n` is `prompt.rs`'s alone — it is the only layer that
can tell them apart without guessing at intent, and `--allow-tool`'s own refusal
stays a `Deny` because a tool no flag approved is a decision. But a CLI-confined
fix has no lever on the cost: `Deny` is recoverable by design, so the round loop
still iterates `max_rounds` times opening a stream each time. A latch read after
`run_turn` returned would have closed "exits 0" and left "keeps paying" exactly
as filed.

- **Fail-closed, both ways.** The abort refuses the call it landed on; it never
  lets one through, which is the one way a fix here could be worse than the bug.
  And the calls behind it are refused *unasked* rather than allowed on the
  strength of a verdict nobody gave. A tool already blanket-approved with `a`
  goes with them, the latch being read before `approve`: the `a` was a judgement
  about the tool, not a standing permission to run it with nobody watching.
- **The round is answered in full.** A `tool_use` with no matching `tool_result`
  is a transcript no provider takes back, and this one is stored and resumed.
- **A `TurnStop`, not a `TurnError`.** An error variant would discard the turn's
  messages, usage and `withheld`, losing work already done to a channel that
  failed after it — and skipping the `--session` append, so the operator would
  lose the record at the moment they most need it.
- **No payload on the variant.** `TurnStop` stays `Copy`, and the reason is
  already in the last `tool_result` and in the gate's own `settled` line.
- **No sixth `Outcome`.** The aborting call reports `Outcome::Denied` carrying
  the channel reason verbatim, which the per-call line already renders.
- **The wrap-up round is skipped**, `--no-wrap-up` being irrelevant on this path:
  that request is precisely the one there is no longer anyone to have asked for.
- **Exit 3, not 2.** `2` means a bound the operator chose cut the turn short; a
  lost operator is neither bound nor anything they configured, and the two can
  co-occur. Reusing it would leave the defect distinguishable only by grepping
  stderr. `3` wins over a `max_tokens` cut, a bound being recoverable by raising
  a flag where this is not. The same argument moved a usage error off 2 and onto
  64: clap's default collided with the bound, so a mistyped flag and a cut round
  were one number (#265). A code a caller has to grep stderr to read is not a
  code.

One typed `VEOF` ends the turn with it, which is a real behaviour change: `read`
returns 0 for a bare close and for an end of input alike, and both mean nobody is
answering. Probing with a write afterwards *would* separate them — a device that
still accepts one is still there — but it is extra mechanism for a case where
both readings point the same way.

So three things record the refusal durably, none of which needs a live terminal:
the exit code, the stderr line `Render` writes before it checks stdout at all,
and the `tool_result` in the session. The code is the one of the three another
failure can take — a run whose stdout could not be written exits 1 for that
instead, the line and the transcript still saying why it stopped, which is why
the line is written ahead of that check rather than after it. That is what lets
"No audit record either" above stand as a claim rather than as a gap.

Only the *result* channel may take the code, which is what separates the two
subcommands. Under `agent-run` stdout carries the answer, so an answer that could
not be written is a run with nothing to show and 1 is the honest report. Under
`tui` the screen is not where the refusal was recorded: the line naming the lost
operator goes to stderr from `reported`, and the latch is read after the code is
already decided — so a draw that stopped partway leaves that line standing and
the earned 3 with it. Taking the code there reported a lost operator as a generic
failure, which was the whole of #257.

Two of the three durable things are thinner under `tui`, which is worth naming
here rather than leaving to be discovered. The per-call `settled` line is *drawn*
and not written, the alternate screen neither redirecting stderr nor giving it
back (#224), so a latched screen loses it; and `--session` is off unless asked
for, so the `tool_result` may not be stored at all. The stderr account and the
exit code are what survive unconditionally, which is why neither may be taken by
a failure of the screen. [guide-tui.md](guide-tui.md) states the same where it
specifies the codes.

All three survive the hangup *because* consent is a third device. With the
question on `/dev/tty`, stdout and stderr can both be redirected to files
without breaking the exchange — so the status and the account outlive the
terminal, and a revoked one can be observed end to end. Asked on stdin the same
run would lose every record with the device it was asked on, and the failure
this section is about would not be checkable at all.

### The rule covers a second surface, where nothing was being asked

"A lost operator is neither a bound nor anything they configured" is about
consent, but it does not depend on a question being in flight. Under `tui` no
call is waiting on an answer — the gate decided from argv before the first
request — and yet a terminal that hangs up mid-turn is the same event: the turn
goes on with nobody watching what it does, and the per-call account is drawn to a
screen that no longer exists. So `tui` ends the turn on a hangup and exits 3 on
this rule rather than on one of its own (#264).

Three differences follow from there being no question to refuse:

- **The stop is the whole of it.** There is no call to deny and no `tool_result`
  to write, so of the three durable records only two remain: the exit code and
  the stderr line. Both are written after the screen is given back, which is what
  makes them survive the device that died.
- **It is detected, not returned.** `--approve call` learns of the hangup from a
  read that failed; `tui` has to go looking, because crossterm answers a hung-up
  pty with zero bytes forever instead of an error —
  [guide-tui.md](guide-tui.md) has the mechanism.
- **The watched descriptor is not the asked-on one.** Consent is deliberately a
  third device so the account outlives the terminal; `tui` has no third device,
  so the hangup it must notice is on standard output and standard input both.

It also keeps less. The abort is a `TurnStop`, so the turn returns and its
messages, usage and `withheld` are stored; `tui` races the turn with a `select!`
and drops the future, so there is no outcome to append and the turn is stored
nowhere. That is the existing cost of the interrupt rather than a choice made
here — ending on a hangup makes a lost turn no worse than an interrupted one, and
the account says so where the operator can read it. A tool call already running
finishes unseen (#26) on both surfaces alike.

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
to drop, since dropping it is the whole remedy. The same rule holds for a channel
lost *mid*-run: falling back to the argv answer there would be the identical
fail-open one request later, so the turn ends instead.

**The model's answer shares that terminal.** stdout is usually the same device,
and the whole round's text streams before the gate asks anything, so the model
can leave an SGR state behind or print prose that reads like a question. The
reset covers the first, and is written before the account as well as before the
question — concealing the record of what ran is the same attack one line later —
including on stderr when stderr is a terminal, which a redirected one is not. The second is worse than it looks: a counterfeit question
cannot *consume* an answer, since only `approve` ever reads, but canonical mode
queues a finished line until something reads it, so a `y` typed at the forgery
was still sitting in the kernel's input queue when the real question's read
arrived — and a round can hold the operator there, since a read-only call runs
unasked and takes as long as the tree it walks. The answer bound to a call the
operator never saw.

So the queue is discarded immediately before each question — `tcflush` for the
kernel's, and `BufReader`'s own buffer after it, one read being able to deliver
several lines. An answer cannot predate the question it answers. What that leaves
is a counterfeit that makes the real question *look* already answered, which no
flush reaches; stripping the model's own prose would mangle the answer the
operator asked for, so the terminal is shared and that is the cost of sharing it.

**What this is not.** Neither mode decides whether a call *should* happen, only
whether it may. `SECURITY.md`'s standing commitment holds under both — a tool call
you approve runs; sandbx bounds what it can reach, it does not judge the intent
behind it — and an operator answering `y` to a question whose arguments they did
not read has approved it as surely as a flag would have. #133 is where the same
question gets a surface with somewhere to render it.
