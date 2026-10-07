# Answering a round limit

A turn that reaches `--max-rounds` has done real work and has nothing to show for
it. `agent-run` spends one more request to get an answer out of it.

## What the cap used to leave behind

`run_turn` returns `Ok` with `TurnStop::RoundLimit { rounds }` and every message
the turn produced. That transcript ends on a `user(tool_result)` the model never
answered, and so does every prefix of it — the alternative being a `tool_use`
with nothing answering it. So:

- stdout held whatever text arrived before the cap, which is nothing at all if
  the model opened with a tool call;
- `Session::append` refused the batch, because a stored transcript had to be
  empty or end on an assistant message;
- the exit was `2` with the bound named on stderr, and a second line saying the
  session was unchanged.

The tokens were spent, the `write` calls had already landed, and `--session`
gained nothing from either. The storage half of that is gone: a transcript may
now end on the results a turn ran out of rounds on, and the prompt that resumes
one is sent beside them (#188, `decision-on-disk-state.md`). What is left below
is why the request is still worth spending — stdout is the half no transcript
answers.

## One more request, with no tool call allowed

A second turn the model cannot spend on a tool replies in prose, so the batch ends
on an assistant message — which `append` already accepted when this landed. No
storage change, no transcript-format change, no new record kind.

### Why the tools are still sent

`Turn::tools` documents an empty slice as offering *none*, and an empty list is
omitted from the request body entirely. That is the obvious mechanism and it does
not work: the wrap-up round's history necessarily replays the `tool_use` and
`tool_result` blocks the first turn produced, and the Messages API refuses a
request carrying those without the definitions they name. Built that way, the
feature would 400 on every real run.

So the definitions stay and `tool_choice: {"type": "none"}` forbids the call —
the documented way to ask for a prose-only reply. `MessagesRequest::tool_choice`
and `Turn::tool_choice` are new for it, and the field is dropped on the way out
when `tools` is empty, the API refusing a choice over tools no request defined.

The round loop's contract is otherwise the same one: this is `agent-run` choosing
to call it twice. Anything else embedding `sandbx-agent` keeps the raw
`RoundLimit` and decides for itself.

### The gate still refuses

`tool_choice` bounds what the model is *asked* for, which is not a bound on what
runs. The wrap-up round therefore passes a gate that denies unconditionally,
rather than the run's own `--allow-tool` reading: a model that asks for a tool
despite the choice must not reach `sandbx-tools` on the strength of a flag the
operator typed for the first turn. Belt against a provider-side change, since
before `tool_choice` the empty `tools` list refused such a call above the gate.

## Where the nudge goes

The model is told it has no tool calls left as a **suffix on the system prompt**,
composed in `agent/wrapup.rs`:

- the history ends on a `user(tool_result)`, and a second user message in the
  request is exactly the consecutive-user-turn rejection this whole area is about
  — the merge that makes a *resumed* prompt legal there is the caller's, over a
  stored history, and the turn loop does not do it mid-turn;
- a text block appended to that trailing message would land in
  `TurnOutcome::messages`, be stored, and be replayed on every later resume. A
  system prompt is not stored.

## Default on, `--no-wrap-up` to refuse

The extra request costs tokens the operator did not ask for, so it is a flag. It
defaults to spending them because the alternative default leaves the common case
with nothing on stdout: tokens burnt, edits applied, and an answer the operator
has to ask for in a second run. `--no-wrap-up` is the opt-out. It no longer makes
the cap a dead end — the turn is stored and resumable either way — so what it
costs is the answer, not the conversation.

## The exit code stays 2

A summary is prose about work that was cut off, not a finished turn. `2` means a
bound ended the turn, and the bound did. A script branching on the status sees no
difference between a cap that summarised and one that did not; stderr is what
distinguishes them, the same split `--max-tokens` truncation uses.

Stdout gets one blank line between the pre-cap text and the summary, and no
marker: stdout is documented as holding the answer alone. The gap is *owed*
rather than written when asked for, so a wrap-up round that answers with nothing
strands no blank line.

A summary can hit `--max-tokens` of its own — prose about a long tool session is
exactly the reply that would — so both bounds are named when both were hit.
Describing a summary cut off mid-sentence as the answer to a round limit is
worse than naming one bound too many.

## When the wrap-up round itself fails

A provider error, or a reply with no content, or a `stop` that is not `Answered`:
the first turn's outcome is kept unchanged, stderr names what happened, and the
run falls back to the exit code and the stdout described above. Never
`?`-propagated — that would turn a turn that did real work into exit `1` with its
text already on stdout. The transcript is no longer part of that fallback: the
first turn's work is stored whichever way the second request went.

Stdout is the part that cannot be undone. A round that streams prose and *then*
asks for a tool has already written an answer that no transcript will hold: the
first turn is stored, that round is discarded, and its text is the one thing on
stdout with nothing behind it. The text stays — it was paid for, and only the
operator can judge it — but stderr says plainly that nothing on stdout is an
answer and that what followed the cap was not saved. It says "the cap" and not
"the gap": there is no gap when nothing arrived before the cap, which is the
common shape of a model that opened with a tool call. The alternative, the
ordinary round-limit line, tells the operator stdout holds only what arrived
before the cap while it visibly does not.
