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
F: AsyncFnMut(MessagesRequest) -> Result<EventStream, ProviderError>
```

`run_turn` takes a closure, so it neither knows nor cares which side produced the
stream. One adapter plus a mock is two producers of `EventStream` and one of
`Provider` — the alias was always the real seam, and the enum only looked like one.

#90 asked for this to be settled *before* the loop was written. It was written
first; the loop happened to pick the right side, and deleting the enum afterwards
was cheap because nothing but a test had ever named it. Do not read that as
vindication of the ordering.

## The input flank is still vendor-shaped

`MessagesRequest` is Anthropic's wire schema behind a neutral name: `max_tokens`,
`system: Option<String>`, `input_schema`, `ToolResult` as a content block rather than a
message. `StopReason::from_wire` matches Anthropic strings with no provider
parameter, and `RETRYABLE_KINDS` holds vendor error codes.

Boxing the return type was meant to stop a second provider from breaking
`stream_chat`'s signature — but adding one changes that signature anyway, through
the request parameter. So the output flank is sealed and the input flank is not.

**Deliberately left open** (#59). With one adapter the neutral shape would be a
guess, and designing against a guess is how `sse.rs` would have gone wrong too —
it plugs into a second provider unchanged precisely because it was factored on a
real reuse axis. Neutralise the request type *while* writing provider two, not
before.

The same timing argument covers thinking-block replay (#85): `MessagesRequest` has
no `thinking` field, so no thinking block can be produced against a real provider,
so the replay path has no caller to be driven by.

See also [guide-turn-loop.md](guide-turn-loop.md).
