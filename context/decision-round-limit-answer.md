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

## One more request, with no tools offered

`Turn::tools` documents an empty slice as offering *none*, not all of them. A
second turn built that way cannot ask for a tool, so its reply is prose, so the
batch ends on an assistant message — which `append` already accepts. No storage
change, no transcript-format change, no new record kind.

`sandbx-agent` is untouched. The round loop's contract is the same one; this is
`agent-run` choosing to call it twice. Anything else embedding the crate keeps
the raw `RoundLimit` and decides for itself.

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
asks for a tool has already written an answer that no transcript will hold, and
the blank line above it is already out. The text stays — it was paid for, and
only the operator can judge it — but stderr says plainly that it is not an answer
and was not saved. The alternative, reporting the ordinary round-limit line, tells
the operator stdout holds only what arrived before the cap while it visibly does
not.
