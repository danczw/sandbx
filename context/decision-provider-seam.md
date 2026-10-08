# Decision: the provider seam is `EventStream`, not a provider object

## No wrapper crate

No `genai`, no `rig-core` — `sandbx-providers` is hand-rolled `reqwest` + `rustls`.
An early diagram said "wraps `genai`"; the decision not to is the one that held. The
cost of a wrapper is that every new capability waits on someone else's abstraction,
and SSE accumulation — the hard part — is where a generic wrapper helps least.

## There is no provider object to drive

`Provider` was a one-variant enum whose methods were pass-throughs. It has been
deleted (#90); `AnthropicClient::stream_chat` returns `EventStream` directly, and
`MockProvider::stream_chat` returns the same alias.

The seam is the **return type**, not an enum or a trait:

```rust
F: AsyncFnMut(Prompt) -> Result<EventStream, ProviderError>
```

`run_turn` takes a closure, so it neither knows nor cares which side produced the
stream. One adapter plus a mock is two producers of `EventStream` and one of
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
  which is what a test wants to compare.
- `anthropic/body.rs` owns the whole body: the key names, the omissions (`system`
  absent rather than null, `tools` dropped when empty, `tool_choice` only alongside
  them), and `stream: true`. It is `pub(super)`, so nothing above `anthropic.rs` can
  post a neutral type to an API.
- `StopReason` is a neutral enum with `Other(String)`; the string table is a free
  `stop_reason` in `anthropic/wire/`. `sandbx-agent` names it in its own public API,
  as `TurnOutcome::round_stop` (#190), and does not re-export it — one path to one
  type. That is the test of the neutrality above, passed because nothing outside
  `anthropic/` can build one from a wire string.
- `ProviderError::ApiError` carries `transient: bool` and `is_retryable` reads only
  that. Which codes and statuses are worth retrying is per-adapter, and the two
  construction sites in `anthropic.rs` are what decide.

The weakness this leaves, stated rather than designed around: with one adapter the
neutral shape is informed by one wire format, so a second backend will still move
something. What it will not have to move is a vendor name out of a shared type, and
it has one worked example of where such a thing goes. No trait, no provider enum and
no capability negotiation was invented for a backend that does not exist — the
timing argument #59 made against doing this early was withdrawn, not satisfied.

`Prompt::thinking` is the one field whose presence is a capability claim rather than
a request shape; [decision-thinking-replay.md](decision-thinking-replay.md) is why it
is one variant, and what the loop does with what comes back.

See also [guide-turn-loop.md](guide-turn-loop.md).
