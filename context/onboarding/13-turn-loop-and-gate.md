# Nothing runs until the gate has answered

You are standing in **the gate** — the box
[04 — the architecture](04-the-architecture.md) names in View 3 as
[`agent/src/approval.rs`](../../crates/sandbx-agent/src/approval.rs),
"`CallGate`, two methods, `run_turn`'s mandatory fifth parameter". 04's View 2
draws the round in seven lines and marks one of them `approve`. This chapter is
that line, plus the two checks standing in front of it and the one verdict that
ends the turn.

Do not look for that round diagram again here; it is not redrawn. Read it there,
then read this as one step of it taken apart. It is also the chapter where
prompt injection stops being a hazard you can describe and becomes a sequence of
bytes arriving at a terminal you are typing into, so the adversary's view runs
through all of it: at every mechanism below, the question to hold is *what does
a model that has read a hostile file try here, and what stops it.*

[guide-turn-loop.md](../guide-turn-loop.md) owns the loop and
[decision-approval-gate.md](../decision-approval-gate.md) owns the gate. Neither
is restated; both are the authority for anything this chapter leaves out.

## The loop, one level down

[`turn.rs`](../../crates/sandbx-agent/src/turn.rs) exports one async function.
Its signature is the first security property in the file, and it is a property
of the *shape* rather than of any code:

- **`gate` is a parameter, not an `Option`, and not a field with a default.**
  There is no `run_turn_unchecked`. A caller cannot acquire a gate-less loop by
  omitting an argument, because omitting it does not compile.
- **It is generic over `G: CallGate`, so there is no `dyn` and no boxing**, and
  the trait has a blanket `impl` for `&mut G` — which is what lets a caller keep
  its gate after the turn to read what the gate recorded.

The loop runs at most `max_rounds` times. Each round opens a stream, consumes
it, and then asks one question: were there any `ToolUse` blocks? If not, the
turn is over. If so,
[`turn/tools.rs`](../../crates/sandbx-agent/src/turn/tools.rs) — see
`answer_calls` — answers every one of them, sequentially, in the order the model
asked.

Three facts about that loop matter here and are easy to get wrong:

- **Re-entry is keyed on the presence of blocks, never on the stop reason.** 04
  says why. The consequence for the gate is that the number of times it is
  consulted is decided by the model's output, not by a label the provider
  attached to it.
- **`answer_calls` is sequential.** Not for simplicity: two tools sharing one
  `ExecutionContext` have ordering semantics nobody has settled (#242). While
  the gate is reading an answer off `/dev/tty`, nothing else in `agent-run` is
  in flight — the round's stream has ended and its timeout is dropped.
- **A turn ends exactly three ways**, and the enum says so:

```rust
/// How a turn came to an end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnStop {
    /// The model stopped asking for tools, so the transcript ends on its reply.
    Answered,
```

`RoundLimit { rounds }` and `GateAborted` are the other two. `agent-run` matches
`TurnStop` exhaustively where it turns one into an exit code — on the pair
`(stop, outcome)` in [`cli/src/agent.rs`](../../crates/sandbx-cli/src/agent.rs),
with no `_` arm — so a fourth way for a turn to end cannot reach the code that
reports a clean one. `tui`'s own mapping is deliberately *not* exhaustive, for a
reason it states rather than leaves to be inferred: a stop it does not know
about is an answer it has no account of, so a variant documenting an exit code
"needs an arm above, or `tui` contradicts a code `agent-run` already claims".

## Two refusals a gate never sees

Before `approve` is called, `answer_calls` can already have refused the call —
twice, for two different reasons, and in both cases the gate is told what
happened through `settled` but never asked for a verdict.

| refusal | why it is above the gate |
|---|---|
| no tool answers to that name | `BuiltinTool::from_name` is exact-match, so a miss is a prompt or schema bug, not a near miss to normalise. Reported as `Outcome::Unknown` |
| the tool was not offered this turn | `from_name` resolves against **every** built-in, not against this turn's set. Reported as `Outcome::NotOffered` |

The second is the one worth sitting with, and it is the adversary's view in
miniature. The offered set is the caller's declaration of what may run.
Resolving a name alone would hand the gate a call that was never on the table —
and a permissive gate would then run it. A caller offering `[Read, Ls]` would
have had an injected `bash` execute. Two tests pin it by name:
`an_unknown_name_never_reaches_the_gate` and
`an_un_offered_tool_never_reaches_the_gate`.

As code both are a `continue` out of the per-block loop, which is the branch
worth seeing: the `let verdict = …` of the next section sits further down the
same loop body, and a refusal here never reaches it.

```rust
        if !offered.contains(&tool) {
            // `from_name` resolves against every built-in, so resolving alone would hand the
            // gate a call the caller never offered — which an allow-all gate then runs.
            gate.settled(Settled {
                name,
                id,
                tool: Some(tool),
                input,
                outcome: Outcome::NotOffered,
            });
            results.push(refused(id, format!("tool not offered this turn: {name}")));
            continue;
        }
```

The name miss above it is the same shape with `Outcome::Unknown` and its own
message. Both *answer* the block rather than dropping it — `refused` builds a
`tool_result` marked `is_error` — because a `tool_use` with no answer is a
transcript no provider takes back, and this one is stored and resumed.

This is also why `CallGate` has a second mandatory method. Its own doc says what
a gate watching only its own verdicts would miss:

> Three of these never reach [`CallGate::approve`], so a gate that reports only
> its own verdicts accounts for neither the refusals above it nor what the tool
> went on to do (#169).

`settled` is called for every block, whatever happened to it — the two refusals
above, a verdict the gate gave itself, a tool that ran, and a tool that returned
an error. `Outcome` has five variants for that reason.

## Three verdicts, and the match that keeps them three

`ApprovalDecision` has `Allow`, `Deny { reason }` and `Abort { reason }`. The
call site is not an `if let`, and the comment says why:

```rust
        // Exhaustive rather than `if let`, so a fourth verdict is a compile error, not approval.
        match verdict {
            ApprovalDecision::Allow => {}
```

This is the house pattern from 04 — a closed enum plus an exhaustive match is a
compile-time gate — applied where getting it wrong is worst. With an `if let
ApprovalDecision::Deny`, a fourth variant added later would fall through to the
`spawn_blocking` below and *run*. With the match, it is a build failure.

The distinction between the two refusals is the one piece of the gate's
semantics a caller has to internalise:

- **`Deny` is recoverable.** The call comes back as a `tool_result` marked
  `is_error`, the model reads the reason, and the turn continues — bounded by
  `max_rounds`. A refusal is deliberately *not* a `TurnError`: an error variant
  would discard the turn's messages, usage and `withheld`.
- **`Abort` is not.** It means the gate has lost whatever it decides with. It
  answers the call it landed on as a `Deny`, latches, and refuses every call
  behind it in the round **without asking**:

```rust
        let verdict = match &aborted {
            Some(reason) => ApprovalDecision::Deny {
                reason: reason.clone(),
            },
            None => gate.approve(ToolCall { tool, id, input }),
        };
```

The latch is read *before* `approve`, which has a consequence worth stating out
loud: a tool the operator had already blanket-approved with `a` goes with the
rest. The record's reasoning is that the `a` was a judgement about the tool, not
a standing permission to run it with nobody watching.

Then the position of the whole thing. `approve` is asked **before**
`spawn_blocking`, never concurrently with it:

```rust
        // Before `spawn_blocking`, never racing it: a blocking task cannot be cancelled, so
        // a late decision would not stop the call it refused (#26).
```

A blocking task cannot be cancelled: dropping the `JoinHandle` leaves it running
to completion. So a gate consulted in a `select!` against the call would be
answering "denied" about a `write` that had already landed. Before the spawn is
the only position where a refusal means anything, and that single fact explains
why `CallGate`'s methods are synchronous, why neither may wait on anything the
runtime drives, and why the trait has no `async fn`.

## Argv is the ceiling, and it is asked first

[`cli/src/agent/gate.rs`](../../crates/sandbx-cli/src/agent/gate.rs) holds the
only gate that ships — see `ArgvGate`. Its `approve` is three decisions in a
fixed order, and the order is the design.

**First, argv.** `--allow-tool` is the ceiling: a tool no flag approved is
refused without anybody being asked.

```rust
        // Argv is the ceiling, asked first: a prompt that could only ever be refused
        // teaches an operator to answer `y`.
```

`approves` derives three states from `Option<Vec<BuiltinTool>>`, the same shape
as `--allow-network`, with the same fail-closed reading of the mixed form: the
bare flag beside a named one narrows to the named one.

| argv | effect |
|---|---|
| absent | the four read-only tools run; `write`, `edit` and `bash` come back refused |
| `--allow-tool write` | that tool as well. Repeatable |
| bare `--allow-tool` | every tool |

**Second, risk level.** A read-only call is allowed without a question:

```rust
        // Never asked about: a `read` has no answer worth taking, and asking would be
        // #165's twenty-prompt turn.
```

`RiskLevel` is `ReadOnly`, `Writes`, `Executes`, ordered least to most so a gate
can admit everything at or below a level. It is a field of each tool's own
`SPEC`, not a table in the gate, so a new tool declares its own level or fails
to compile — and `tests/registry.rs` spells the expected levels out by hand,
because a test deriving them from `risk()` would assert only self-consistency
and a `bash` reclassified as read-only would pass.

**Third, the terminal — if there is one.** With `--approve call` the operator is
asked per call; without it, a tool argv approved runs. `--approve call` on a run
with no `/dev/tty` is refused *before the first request* rather than quietly
falling back to the argv answer, because falling back would hand the run a
weaker regime than the operator asked for. So `ArgvGate`'s `terminal` field is
`Some` under that flag alone — and never under `tui`, which refuses the flag
outright, the screen having taken the device the question wants (#225);
[15](15-tools-and-the-screen.md) has that end of it.

- **Worth questioning:** the refusal text for an unapproved tool names exactly
  one flag — "it runs only when sandbx is started with `--allow-tool bash`" —
  and never mentions `--approve call`.
  [decision-approval-gate.md](../decision-approval-gate.md)'s "Deny by default"
  section rests the whole decision to offer the model all seven tools on that
  message: "the refusal is what tells the operator which flag to pass, which a
  tool the model was never offered cannot do", with a live run as evidence. The
  record weighs whether the signal exists, not what it says. What it says is the
  least supervised of the two remedies, to an operator who has just been told a
  model wanted `bash`, and the record's own framing of `--allow-tool` alone is
  "a decision per tool per run: once `--allow-tool bash` is passed, every
  command the model chooses to run in that turn runs, including one a prompt
  injection induced (#165)". Naming both flags in the one sentence costs nothing
  the record priced.
- **Worth questioning:** a flag refusal repeats itself all the way to
  `max_rounds`. The same record's third-verdict section states the cost
  precisely — "`Deny` is recoverable by design, so the round loop still iterates
  `max_rounds` times opening a stream each time" — and treats it as the reason
  `Abort` had to become a public variant rather than a latch in the CLI. The
  argument is not applied to the flag case, where it is *more* decidable: argv
  is fixed for the run, so after the first refusal the harness already knows no
  later round can be approved either. The record's stated reason for keeping it
  a `Deny` is that "a tool no flag approved is a decision", which is a claim
  about the verdict's identity and not about repeating it seven more times.
  #218's "keeps paying" defect was filed against a turn that re-opened a stream
  with nobody to answer; this one re-opens up to seven with nothing that could
  change the answer.

## The operator is the floor

[`cli/src/agent/prompt.rs`](../../crates/sandbx-cli/src/agent/prompt.rs) is
where a human is actually asked. Three details carry weight.

**It is `/dev/tty`, not stdin.** stdout carries the model's answer and is
routinely piped, and `agent-run`'s own prompt arrives on argv, so stdin is not
reliably a person. `/dev/tty` is the one channel the operator still holds. It
also means the question, the account of what ran, the exit code and the session
transcript survive a run whose stdout and stderr are both redirected to files —
which is what makes a lost operator observable end to end rather than lost with
the device.

**A typo is not consent.** The answer loop recognises six strings and nothing
else:

```rust
            match answer.trim() {
                "y" | "yes" => return ApprovalDecision::Allow,
                "n" | "no" => return deny(REFUSED),
                "a" | "all" => {
                    self.blanket.push(call.tool);
                    return ApprovalDecision::Allow;
                }
                // Asked again rather than read as either answer: a typo is not consent.
                _ => {}
            }
```

`_ => {}` falls out of the `match` and back to the top of the `loop`, so the
question is asked again. Neither a default-allow nor a default-deny: an
unrecognised answer is *not an answer*, and the operator gets the question back.
`a` is per tool, because carrying it across tools would make a single `a` into a
bare `--allow-tool`.

**Losing the channel is not an `n`.** `read_line` returning `Ok(0)` — a closed
device — and any error other than an invalid-UTF-8 line both produce `Abort`,
not `Deny`. A revoked controlling terminal fails the read with a raw `EIO`; a
bare close returns 0; one typed `VEOF` is indistinguishable from the close and
goes with them. All of it means nobody is answering, which is a different fact
from "somebody said no".

The one error that is retried is the UTF-8 one, and it is safe only because
`read_line` consumed the line through its newline before its own check rejected
it: a reader that left the `\n` behind would hand the next read an empty line,
the typo arm, and a third question for one bad byte.
`a_byte_that_is_not_text_is_asked_about_again` asserts two questions and not
three, which is what pins that — and the comment names `BufReader<File>` as the
only reader this holds for, so substituting another means re-checking it.

## The adversary at the prompt

Now the attack this subsystem exists to survive, in order. The model has read a
hostile file. Its output streams to stdout, which is usually the same device the
gate will ask its question on.

1. **The model prints prose that looks like a consent prompt.** Nothing stops
   it: the round's text is flushed before any tool call is answered, and it is
   the operator's answer, so it cannot be stripped.
2. **The operator types `y` at the forgery.** The counterfeit cannot *consume*
   that answer — only `approve` ever reads the device — but the terminal is in
   canonical mode, and canonical mode queues a finished line until something
   reads it.
3. **A read-only call runs unasked**, taking as long as the tree it walks. The
   operator sits there. The `y` sits in the kernel's input queue.
4. **The real question is asked, and reads.** Without a defence it gets that
   queued `y` — an answer bound to a call the operator never saw.

The defence is to discard the queue immediately before each question, at both
layers. `discard_typeahead`'s own doc states the terminal behaviour the attack
rides on, which is the part worth having first-hand:

> Canonical mode queues a finished line until something reads it, so an answer
> typed earlier — at a counterfeit question in the model's own prose, which
> reaches this device too — is returned by the next read as the answer to *this*
> call.

```rust
    fn discard_typeahead(&mut self) -> nix::Result<()> {
        nix::sys::termios::tcflush(self.input.get_ref(), nix::sys::termios::FlushArg::TCIFLUSH)?;

        let buffered = self.input.buffer().len();
        self.input.consume(buffered);

        Ok(())
    }
```

Both, because either alone leaves the path open: `tcflush` clears the kernel
queue, and one read can deliver several lines, so the `BufReader` may already
hold a later one. The invariant it buys, in one sentence: **an answer cannot
predate the question it answers.**

A flush that *failed* ends the turn rather than asking over a channel it could
not clear. `ask` returns `Abort` carrying `UNCLEARED` — its own reason, not the
`CLOSED` an end of input gives, so the model is told which of the two happened —
and does not retry, because `EINTR` would need a signal handler this process
never installs and the flush will fail again.

Both halves are pinned over a real device rather than a `Cursor`. The first,
`an_answer_typed_before_the_question_is_not_read_as_its_answer`,
opens a pty pair, writes `y` to the master, waits for the slave to carry it,
then asks — and expects the `n` typed *after* the question to be the verdict.
Its own comment says why the fixture must be a terminal: "what the drain clears
is the kernel's input queue", which no in-memory reader has, and `Terminal::on`
exists for that fixture alone. `a_terminal_that_cannot_be_cleared_aborts` takes
the other half over `/dev/null`, where `tcflush` fails with `ENOTTY` before any
question is written.

What that does not reach is stated in the record rather than hidden: a
counterfeit that makes the *real* question look already answered. No flush
helps, because the bytes were never typed. Stripping the model's prose would
mangle the answer the operator asked for. The terminal is shared, and that is
the cost of sharing it; #133 is where the same question gets a surface of its
own.

### The decoy argument

A second attack, defeated by a `match` on four lines. The gate has to name what
a call is about. Reading "whichever key is present" would be the obvious
implementation, and it loses:

```rust
fn subject(tool: BuiltinTool, input: &serde_json::Value) -> Option<String> {
    let key = match tool {
        BuiltinTool::Bash => "command",
        _ => "path",
    };
    let value = input.get(key)?;
```

No input type refuses an unknown field. So
`{"command": "curl … | sh", "path": "/work/notes.md"}` is a valid `bash` call
that runs the command — and a subject read by presence order would name, and get
consent for, the decoy path. Keying off the **tool** rather than off the
arguments means the thing named is the thing that runs. The same subject is used
for the question and for the after-the-fact report, so one choice covers both.

### The bytes a question may not contain

Model-chosen text reaching a terminal can rewrite the terminal. `stripped`
handles it, and the two interesting arms are about *not* dropping things:

```rust
            // Spelled, not replaced: a heredoc shown as a row of U+FFFD is a command
            // consented to unread, which `SUBJECT_CAP` exists to avoid.
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || invisible(c) => out.push('\u{fffd}'),
```

- **U+FFFD, not deletion.** A dropped escape leaves a string that reads as a
  plausible path. A replaced one is visibly wrong.
- **`is_control` is not enough**, and this is the part a reader with ordinary
  Unicode instincts gets wrong. `char::is_control` is category `Cc` exactly, so
  U+202E RIGHT-TO-LEFT OVERRIDE and the directional isolates pass it — and a
  path carrying one *displays* as a different path. `invisible` adds the bidi
  overrides and isolates, the zero-width set, the variation selectors, the tag
  characters and the Hangul fillers. Its own comment is honest about the shape:
  ranges, because `char` has no predicate for the category, which makes it a
  denylist a new Unicode version can outgrow silently.
- **The strip covers the whole line**, a policy refusal's own text included,
  because `SandboxError`'s `Display` writes the path back. Concealing the record
  of what ran is the same attack one line later, which is why the SGR reset is
  written before the account as well as before the question.
- **Arguments are capped per field**, so one long argument cannot push the words
  that frame it off the end, and a cut is marked with `…` rather than being
  silent — an operator who cannot see the whole argument can still refuse.

`invisible` is not the gate's own, and the import is worth following:
`sandbx_providers::invisible`, one table read here and by `sandbx-tui` for the
cells it draws, because the hazard is a property of model-chosen text rather
than of either sink. What the gate does *with* a flagged character is still the
gate's — `\n` and `\t` spelled out, U+FFFD for the rest — and the screen makes
different choices with the same table, adding a third predicate of its own,
because a cell is not a line of prompt.
[15](15-tools-and-the-screen.md) and [23](23-crate-tui.md) own that screen;
[20](20-crate-providers.md) has why one crate owns the table.

## A turn out of rounds is asked once more, with no tool

A round is one request plus the tool calls its answer asked for. The loop keys
off the *presence* of `ToolUse` blocks and never off `StopReason` —
[02](02-what-a-harness-is.md) says why at the protocol level — so a round is a
unit of what the model produced, not of what the provider called it.

When the loop decides it has run out of them matters more than it looks. The
bound is the `for` loop's own range, and the last round's calls are answered and
pushed *before* it falls out of it:

```rust
    // Returned rather than dropped: every prefix ends unanswered too, so no truncation reads
    // as finished; `stop` says so.
    Ok(outcome(
        produced,
        usage,
        // `cut`: `withheld` is out of scope, but the two agree since a cut only deepens.
        cut,
        TurnStop::RoundLimit {
            rounds: turn.limits.max_rounds,
        },
        last_stop,
    ))
```

So `--max-rounds 1` is one request and one complete batch of tool calls: every
`write` that batch asked for has landed, with no round left to say anything
about it. The cap bounds how many times the model gets to choose again, not the
choices it already made. `round_cap` refuses `--max-rounds 0`, so the one cap
that opens no stream at all is reachable only by a library caller.

Three things it therefore does not bound:

- **Tokens.** `max_output_tokens` rides on every request, so `--max-tokens`
  bounds each round's reply; a turn of eight rounds may produce eight of them,
  and the wrap-up round below a ninth.
- **Wall-clock time.** `TurnLimits::stream_timeout` bounds one round's
  *consumption*, not the turn, and a tool call is bounded only by whatever
  timeout the tool itself carries — `spawn_blocking` cannot be cancelled (#26).
- **The work inside one round.** `answer_calls` answers every block the model
  asked for, so a round is any number of tool calls. An operator wanting a bound
  on how much a turn *does*, rather than on how many times it reconsiders, does
  not have one here; the flags that bound the damage are the policy flags.

**At the cap, the turn has a transcript and no answer.** It ends on a
`user(tool_result)` the model never answered, and so does every prefix of it.
The naive behaviour is to stop there, which hands the operator nothing — or,
with `--show-thinking` and a chatty model, a wall of output with no conclusion
in it. So `agent-run` spends one more request, purely to turn what was gathered
into prose. [decision-round-limit-answer.md](../decision-round-limit-answer.md)
is the record, and
[`agent/wrapup.rs`](../../crates/sandbx-cli/src/agent/wrapup.rs) — see
`Next::after` — is the mechanism: the first turn's model, system prompt, tools
and limits carried over, `max_rounds: 1`, and a suffix on the system prompt
telling the model it has no tool calls left. A suffix because the history ends
on a `tool_result` and a second user message is the consecutive-user-turn
rejection this whole area is about.

**That the round may call no tool is the load-bearing part.** A wrap-up round
that could call one would be a ninth round by another name, and the bound would
not be a bound: a model looping on the same call would get one more go at it
every time the cap arrived. Two mechanisms hold it, because the first is only a
request field. `Turn::tool_choice` is `Some(ToolChoice::None)` — the tool
*definitions* stay in the body, since the replayed history names them and the
API refuses a request carrying `tool_use` blocks without them. And the round
runs under a gate of its own, not under `ArgvGate`:

```rust
impl CallGate for RefuseAll {
    fn approve(&mut self, _: ToolCall<'_>) -> ApprovalDecision {
        ApprovalDecision::Deny {
            reason: REFUSED.to_owned(),
        }
    }
```

Which is this chapter's thesis applied to the harness's own request:
`tool_choice` bounds what the model is *asked* for, and the gate is still the
only thing between a call and `sandbx-tools` running it. A model that ignored
the nudge and the choice must not reach a tool on the strength of an
`--allow-tool` the operator typed for the turn before.

**What it costs is one request's tokens and latency on every capped turn**, and
a capped turn is already the expensive case — the wrap-up request carries the
whole turn's history, so it is the largest request the turn sends. The record
prices that and defaults to spending it anyway, because the alternative default
leaves the common case with tokens burnt, edits applied and nothing on stdout.
`--no-wrap-up` is the opt-out, and it refuses the request alone: the tool work
is stored and resumable either way (#188), and the exit code is 2 either way.

| the run | what stdout holds |
|---|---|
| a capped turn | what arrived before the cap, a blank line, then the summary |
| `--no-wrap-up` | what arrived before the cap — nothing at all if the model opened with a tool call |
| `tui` | the pane, and no wrap-up round is sent at all |

The blank line is *owed* rather than written: `Render::separate` sets a flag the
next text delta spends, so a wrap-up round that answers with nothing strands no
stray gap. The whole shape, with the line that names the bound:

```console
$ sandbx agent-run --allow-tool bash -- 'group every TODO by file'; echo "exit $?"
… whatever prose arrived before the cap …

I read 41 files and grouped what I found; three directories are unvisited.
sandbx: stopped after 8 rounds of tool calls; the answer above summarises what was found, and raising --max-rounds would let the turn go further
exit 2
```

Under `tui` the same cap ends on tool work and the screen says so;
[15](15-tools-and-the-screen.md) is the chapter for that surface, and for the
other way `tui` reaches 2.

**Two outcomes become one stored turn.** `merge` concatenates the messages, and
each of the four fields behind them is a decision:

```rust
pub(super) fn merge(first: TurnOutcome, second: TurnOutcome) -> TurnOutcome {
    let mut messages = first.messages;
    messages.extend(second.messages);

    TurnOutcome {
        messages,
        usage: second.usage.or(first.usage),
        withheld: second.withheld,
        stop: second.stop,
        round_stop: second.round_stop,
    }
}
```

`usage` is `.or`, because `PromptUsage` is a *measurement* of how large a
request was and the freshest one is the one the next turn should plan against —
not a bill to be summed. `stop` and `round_stop` are taken outright, because a
stop reason belongs to one round: the wrap-up round's prose is the answer, so a
summary cut at `--max-tokens` is named against the summary, and the first turn's
own cut is not inherited by it. `the_merged_turn_takes_the_wrap_ups_reason` pins
all three by failing three plausible wrong merges, `.or(first.round_stop)` — the
shape `usage` uses — among them. One turn and not two because the session's unit
is a prompt and what it produced, and there was one prompt; a second stored turn
would need a second one invented for it, which the API has no legal place for
either. [22](22-crate-session.md) is where the stored shapes live.

The exit code does not come out of the merge. `ending` is derived from the
*first* turn's `TurnStop::RoundLimit` before the second request is sent, so the
merged `stop: Answered` never reaches it, and `finish` returns `INCOMPLETE` for
any `ending` at all. The three cap variants — `CutShort`, `Summarised` and
`Discarded` — exit the same 2 and differ only in the stderr line they write,
which is the split the record chose deliberately: `2` means a bound cut the turn
short, not that anything failed, and the answer on stdout may be complete and
worth having. Nothing records the cap in the audit trail, which holds accesses
the kernel or `FsGuard` actually decided — the final round's tools ran, so their
accesses are in it like any others ([14](14-audit-sessions-credentials.md)).

- **Worth questioning:** a summarised cap leaves no durable trace that it was a
  cap. The merge takes the wrap-up round's `stop`, the batch ends on an
  assistant message, and a stored turn carries no stop reason at all — so a
  transcript where the model chose to answer and one where the harness made it
  answer are the same shape.
  [decision-round-limit-answer.md](../decision-round-limit-answer.md) prices the
  live channels only: its "The exit code stays 2" section accepts that a script
  cannot tell a cap that summarised from one that did not, because "stderr is
  what distinguishes them". Stderr is exactly what a session does not keep, and
  the record's storage section treats that half as settled by #188 — which made
  a capped turn storable, not recognisable. Under `--no-wrap-up` the unanswered
  `tool_result` is itself the record, and `pending_call` reads it; the default
  spends it for the answer, leaving a later resume only the summary's own prose
  for the fact that three directories were never visited.

## Losing the operator is its own ending

`Abort` latches in `answer_calls`, which hands `run_turn` an
`Answers { results, aborted }`. `run_turn` then ends the turn — after pushing
the round's results, so the transcript ends on them and is as legal to re-send
as a round-limited one:

```rust
        // After the push, so the transcript ends on this round's results, as `RoundLimit`
        // already hands back.
        if aborted {
```

There is a second read of the same latch, on the path where a round produced no
tool calls at all, and its comment names the hazard exactly: "this is the one
place one could be laundered into an answer."

**An abort also cancels the wrap-up round.** The same `(stop, outcome)` match
that derives `ending` sends that extra request for a `RoundLimit` only, and its
comment says why an abort is not merely treated as a cap: "Skipped rather than
refused by a flag: the wrap-up round is exactly the request there is no longer
anyone to have asked for (#218)." Which is what lets the stderr line claim,
truly, that no further request was sent — a lost operator stops the turn where
it stood, not just the call they were being asked about.

The last hop is the one a caller cannot learn any other way.
[`cli/src/agent/render.rs`](../../crates/sandbx-cli/src/agent/render.rs) — see
`finish` — converts the ending into a status, and the order of two checks is the
whole point:

```rust
        // Ahead of `INCOMPLETE`: a turn can hit a bound and lose its operator, and losing
        // the operator is the one a caller cannot find out any other way.
        if ending == Some(Unfinished::Aborted) {
            return Ok(NO_CONSENT);
        }
```

That sits **ahead** of the round-limit check that returns `INCOMPLETE`. A turn
can hit a bound *and* lose its operator; the two co-occur, and only one of them
is recoverable by raising a flag. From 01's table: `2` is a bound the operator
chose, `3` is an operator who could no longer be asked. Collapsing them would
leave the difference discoverable only by grepping stderr.

Two orderings around it are load-bearing in the same way:

- **The `Aborted` note is written to stderr before `finish` checks whether
  stdout failed.** If it were after, a run that lost both the terminal and
  stdout would exit 1 for the stdout failure with no line saying consent was the
  reason — the gate's own account of the call having gone to the device that
  went away.
- **`tui` repeats the decision rather than inheriting it.**
  [`cli/src/agent/tui.rs`](../../crates/sandbx-cli/src/agent/tui.rs) — see
  `ending` — maps `GateAborted` to the same code ahead of the bounds, and its
  comment points back at `render.rs` so the two cannot drift apart silently.

Three things record the refusal durably, and none of them needs a live terminal:
the exit code, the stderr line, and the `tool_result` in the session transcript.
That matters because a gate refusal gets **no audit record** — the audit trail
records accesses the kernel or `FsGuard` actually decided, and a call that never
ran performed none. Chapter 14 is that distinction.

## You should now be able to explain

- What `CallGate` being `run_turn`'s fifth parameter buys that an `Option` field
  would not.
- The two refusals that happen above the gate, and why a caller offering
  `[Read, Ls]` depends on the second one.
- Why `approve` must precede `spawn_blocking` rather than race it, in terms of
  what dropping a `JoinHandle` does.
- Why the verdict is handled by an exhaustive `match` and not an `if let`.
- The difference between `Deny` and `Abort`, and why a blanket `a` does not
  survive an abort.
- Why argv is consulted before the operator, and why a read-only call is never
  asked about.
- Why an unrecognised answer re-asks instead of refusing.
- The four steps of the queued-answer attack, and which two layers
  `discard_typeahead` clears.
- Why a flush that failed ends the turn instead of asking anyway, and why the
  test that pins the drain needs a real pty rather than a `Cursor`.
- Why `subject` is keyed off the tool rather than off whichever argument is
  present.
- Why `char::is_control` is insufficient for a consent prompt.
- What a round is, when the loop decides it has run out of them, and what
  `--max-rounds` therefore does not bound.
- Why the round a cap buys may call no tool, what the extra request costs, and
  why its outcome is merged into the capped turn rather than stored beside it.
- Why exit 3 is checked before exit 2, what a caller could not otherwise learn,
  and what an abort stops besides the call it landed on.

## Next

[14 — what is recorded, and who may read it](14-audit-sessions-credentials.md):
the audit trail a refused call does not appear in, the transcript this turn gets
appended to, and the key that paid for the round.
