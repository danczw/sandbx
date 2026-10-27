# Decision: the provider seam is `EventStream`, not a provider object

## No wrapper crate

This decision spans four crates: `sandbx-prompt` holds what is asked for,
`sandbx-event` what comes back, `sandbx-providers` the one adapter between them, and
`sandbx-turn` the loop driving it.

No `genai`, no `rig-core` — `sandbx-providers` is hand-rolled `reqwest` + `rustls`.
An early diagram said "wraps `genai`"; the decision not to is the one that held. The
cost of a wrapper is that every new capability waits on someone else's abstraction,
and SSE accumulation — the hard part — is where a generic wrapper helps least.

## There is no provider object to drive

`Provider` was a one-variant enum whose methods were pass-throughs. It has been
deleted (#90); `AnthropicClient::stream_chat` returns `EventStream` directly, and a
test double is a closure returning the same alias. `MockProvider`, a published
double, went too (#305): nothing consumed it once the loop's tests rolled their own.

The seam is the **return type**, not an enum or a trait:

```rust
F: AsyncFnMut(Prompt) -> Result<EventStream, ProviderError>
```

`run_turn` takes a closure, so it neither knows nor cares which side produced the
stream. One adapter plus a test double is two producers of `EventStream` and one of
`Provider` — the alias was always the real seam, and the enum only looked like one.

#90 asked for this to be settled *before* the loop was written. It was written
first; the loop happened to pick the right side, and deleting the enum afterwards
was cheap because nothing but a test had ever named it. Do not read that as
vindication of the ordering.

## Both flanks are sealed now

The seam used to be sealed on the way out and open on the way in: `MessagesRequest`
was Anthropic's Messages body behind a neutral name — `max_tokens`, `input_schema`,
a hand-written `Serialize` writing `stream: true` — and `StopReason::from_wire` and
`RETRYABLE_KINDS` matched vendor strings with no provider parameter. Boxing the
return type was meant to stop a second adapter from breaking `stream_chat`'s
signature, but the request parameter would have broken it anyway.

What #59 changed is **where the vendor's vocabulary stops**, not how many backends
there are:

- `Prompt` and its tree carry no `Serialize`. They are data, and `PartialEq` instead,
  which is what a test wants to compare. Since #364 they are also in a crate of their
  own, `sandbx-prompt`, which **states** this the way #365 states the `StopReason`
  half below: `serde` is not among that crate's dependencies, so the orphan rule
  leaves it the only place such an impl could be written at all. What was a
  discipline inside one crate is now a thing the compiler refuses.
- `anthropic/body.rs` owns the whole body: the key names, the omissions (`system`
  absent rather than null, `tools` dropped when empty, `tool_choice` only alongside
  them), and `stream: true`. Every one of its seven `Serialize` impls is on a local
  wrapper, which the orphan rule now requires rather than merely permitting — so an
  adapter cannot post a request shape without first naming every field of it. It is
  also `pub(super)`, which keeps the wrappers themselves inside `anthropic.rs`; that
  token is the narrower of the two guarantees now, and the one that would survive the
  types moving back.
- `StopReason` is a neutral enum with `Other(String)`; the string table is a
  free `stop_reason` in `anthropic/wire/`. Since #365 the two are in different
  crates — the enum is `sandbx-event`'s, the table stayed — which states the seam
  rather than weakening it: the only crate that can turn a wire string into a
  `StopReason` is the one that holds no public way to do it. `sandbx-turn` names
  the enum in its own public API, as `TurnOutcome::round_stop` (#190), and does
  not re-export it — one path to one type, and that path no longer runs through a
  crate that also hands out `AnthropicClient`. That is the test of the neutrality
  above, passed because nothing outside `anthropic/` can build one from a wire
  string.
- `ProviderError` classifies nothing as retryable. #59 settled that such a
  judgement belongs at the adapter's construction sites, not in shared code
  holding vendor strings; it did not settle that one must exist. No backoff layer
  reads one, so #306 removed `transient`, `is_retryable` and `RETRYABLE_KINDS`.
  Code that classifies retries belongs at those construction sites, as #59 said.

The weakness this leaves, stated rather than designed around: with one adapter the
neutral shape is informed by one wire format, so a second backend will still move
something. What it will not have to move is a vendor name out of a shared type, and
it has one worked example of where such a thing goes. No trait, no provider enum and
no capability negotiation was invented for a backend that does not exist — the
timing argument #59 made against doing this early was withdrawn, not satisfied.

`Prompt::thinking` is the one field whose presence is a capability claim rather than
a request shape, and the one place the split above leaves a claim about a provider in
`sandbx-prompt`; [decision-thinking-replay.md](decision-thinking-replay.md) is why it
is one variant, and what the loop does with what comes back.

See also [guide-turn-loop.md](guide-turn-loop.md).
