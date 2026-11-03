# Decision: a reasoning block is replayed inside its turn and nowhere else

Extended thinking is **on by default** on every Claude 5 model, with no
`thinking` field in the request, at `display: "omitted"`: every assistant turn
carries a `thinking` block with an empty text and a real `signature`. Within a
tool-use turn those blocks must be passed back complete and unmodified, and a
mid-turn mismatch does not error — the API strips or disables thinking for that
request — so a broken replay costs reasoning continuity and a prompt cache
rewrite every tool round, with nothing in the output to say so (#217; it is also
why #85's premise was false). Observed against the published docs on 2026-10-07;
a model family that changes the default again changes this note.

## The prefix rule

A block is valid only while the top-level `system`, the `tools` set, and **every
message before it** are unchanged. Otherwise the request is a 400 by default. What
is permitted:

- removing thinking from the **start**, oldest first,
- removing it from the **end**,
- removing **all** of it,
- and once removed, leaving it removed.

What fails is a **gap**. `redacted_thinking` counts as reasoning on the same terms
— it carries an opaque `data` field instead of text and a signature, and filtering
on `type == "thinking"` alone drops it and opens exactly that gap.

## The four rules this implements

1. **Blocks live only inside the turn's own `produced`.** They are stripped from
   `TurnOutcome::messages`, so none reaches the caller, the transcript, or a later
   turn's `history`. Omitting prior turns' reasoning is explicitly allowed.
2. **`history` therefore never holds one**, so no cut can strand one.
3. **A deepened cut strips `produced` once**, and blocks produced afterwards replay
   against the new prefix (`drop_thinking`, in `sandbx-turn`).
4. **`sandbx-session-bridge` drops them again** on the way to storage.

The cost, stated rather than designed around: continuity is kept **within** a turn
— the case the API requires — and not across turns or across a mid-turn cut, both
cases it permits. The alternative is carrying a signature in the transcript and
hoping a resumed conversation reconstructs a byte-identical prefix; a 400 is the
good outcome of that bet.

## Why no beta header, and no `prefix_mismatch_behavior`

`prefix_mismatch_behavior` would let a mismatched request through with the
reasoning silently dropped. That is the failure sandbx already had, re-adopted as a
setting: it converts a rule being broken into nothing at all. Erroring is how a
future edit that opens a gap is found, and the rules above mean nothing sandbx does
can open one.

Visible reasoning (`display: "summarized"`) needs no beta header. `display:
"updates"` does, and would put raw reasoning rather than a summary in front of the
operator; neither is asked for.

## A signature is not transcript material

A signature is a provider replay token. It is of no use to a resumed conversation —
whose prefix is a rewrite, so the block is invalid anyway — and it is opaque, so
nothing downstream can read it. `stored_block` names the two variants as arms and
returns `None`, which is also what keeps `sandbx-session-message` from needing a
`Content` variant for them. Rule 1 means nothing reaches that function today; it
is the last edge before the file, and cheap to hold.

## Switching reasoning on

`Prompt::thinking` is `Option<Thinking>` with one variant, `Visible`, for
`ToolChoice`'s reason: an absent field already means the provider's default.
What `Visible` maps to, and what it costs on an older model, is
`body.rs`'s and the `--show-thinking` flag's to say. An unsigned block
is dropped before it is emitted, since replaying one is a 400.