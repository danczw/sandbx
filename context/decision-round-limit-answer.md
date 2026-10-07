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
- `Session::append` refused the batch, because a stored transcript must be empty
  or end on an assistant message (`decision-on-disk-state.md`);
- the exit was `2` with the bound named on stderr, and a second line saying the
  session was unchanged.

The tokens were spent, the `write` calls had already landed, and `--session`
gained nothing from either.

## One more request, with no tool call allowed

A second turn the model cannot spend on a tool replies in prose, so the batch ends
on an assistant message — which `append` already accepts. No storage change, no
transcript-format change, no new record kind.

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

- the history ends on a `user(tool_result)`, and a second user message is exactly
  the consecutive-user-turn rejection this whole area is about;
- a text block appended to that trailing message would land in
  `TurnOutcome::messages`, be stored, and be replayed on every later resume. A
  system prompt is not stored.

## Default on, `--no-wrap-up` to refuse

The extra request costs tokens the operator did not ask for, so it is a flag. It
defaults to spending them because the alternative default makes the common case a
dead end: tokens burnt, edits applied, nothing stored, nothing on stdout.
`--no-wrap-up` is the opt-out, and leaves exactly the behaviour described above.

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
run falls back to everything in "What the cap used to leave behind". Never
`?`-propagated — that would turn a turn that did real work into exit `1` with its
text already on stdout. That residue is #188.

Stdout is the part that cannot be undone. A round that streams prose and *then*
asks for a tool has already written an answer that no transcript will hold. The
text stays — it was paid for, and only the operator can judge it — but stderr says
plainly that none of stdout is an answer and none of it was saved. It does not
point at the gap: there is no gap when nothing arrived before the cap, which is
the common shape of a model that opened with a tool call. The alternative, the
ordinary round-limit line, tells
the operator stdout holds only what arrived before the cap while it visibly does
not.
