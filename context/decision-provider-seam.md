# Decision: the provider seam is `EventStream`, not a provider object

## No wrapper crate

This decision spans four crates: `sandbx-prompt` holds what is asked for,
`sandbx-event` what comes back, `sandbx-anthropic` the one adapter between them, and
`sandbx-turn` the loop driving it.

No `genai`, no `rig-core` — `sandbx-anthropic` is hand-rolled `reqwest` + `rustls`.
The cost of a wrapper is that every new capability waits on someone else's
abstraction, and SSE accumulation, the hard part, is where a generic wrapper
helps least.

## There is no provider object to drive

No `Provider` enum or trait: a one-variant enum whose methods were pass-throughs
was deleted (#90). `AnthropicClient::stream_chat` returns `EventStream`
directly, and a test double is a closure returning the same alias, so no
published double is needed either (#305).

The seam is the **return type**, not an enum or a trait:

```rust
F: AsyncFnMut(Prompt) -> Result<EventStream, ProviderError>
```

`run_turn` takes a closure, so it neither knows nor cares which side produced the
stream. One adapter plus a test double is two producers of `EventStream` and one of
`Provider` — the alias was always the real seam, and the enum only looked like one.

The alias and `ProviderError` are `sandbx-provider`, a crate of their own (#366),
so the seam is something a consumer can name without an edge to any client:
`sandbx-turn` and `sandbx-cli` both do, and neither has to reach
`AnthropicClient` to spell the closure's return type. The two items are
inseparable (the alias's `Item` is `Result<AgentEvent, ProviderError>`), which
is why one crate holds both.

The loop was written before #90 settled this, and happened to pick the right
side; deleting the enum afterwards was cheap only because nothing but a test had
named it. Do not read that as vindication of the ordering.

## Both flanks are sealed

Boxing the return type stops a second adapter from breaking `stream_chat`'s
signature, but a vendor-shaped request parameter would break it anyway (#59).
So what is fixed is **where the vendor's vocabulary stops**, not how many
backends there are:

- `Prompt` and its tree carry no `Serialize`. They are data, and `PartialEq`
  instead, which is what a test wants to compare. They live in `sandbx-prompt`
  (#364), which has no `serde` dependency, so the orphan rule leaves an adapter
  the only place such an impl could be written at all: the compiler refuses it,
  not a discipline.
- `body.rs` owns the whole body: the key names, the omissions (`system` absent
  rather than null, `tools` dropped when empty, `tool_choice` only alongside
  them), and `stream: true`. Every one of its seven `Serialize` impls is on a
  local wrapper, which the orphan rule requires, so an adapter cannot post a
  request shape without first naming every field of it. `Body` is also
  `pub(super)` and the rest private, keeping the wrappers inside `anthropic.rs`,
  the guarantee that would survive the types moving back into one crate. The wire
  payloads are `pub(super)` too, bar the two error envelopes at `pub(crate)`.
- What these rules confine is the vendor's *vocabulary*, never its name: the
  name is the crate's own (#368), carried by the package, the directory, the
  baseline, `deny.toml` and the `crate:anthropic` label, and no lint or grep
  could contain it if one wanted to.
- `StopReason` is a neutral enum with `Other(String)`, in `sandbx-event` (#365);
  the string table is a free `stop_reason` in `anthropic::wire::accumulate`.
  That states the seam rather than weakening it: the only crate that can turn a
  wire string into a `StopReason` is the one that holds no public way to do it.
  `sandbx-turn` names the enum in its own public API, as
  `TurnOutcome::round_stop` (#190), and does not re-export it: one path to one
  type, not running through a crate that also hands out `AnthropicClient`.
- `ProviderError` classifies nothing as retryable. Such a judgement belongs at
  the adapter's construction sites, not in shared code holding vendor strings
  (#59), and with no backoff layer to read one there is none (#306). The type
  holds no vendor *table* and nothing that turns a wire string into anything,
  the same test `StopReason` passes. It does carry vendor strings as prose and as
  test fixtures (`x-api-key`, `"invalid_request_error"`); what it has no way to
  do is match on one.

The weakness this leaves, stated rather than designed around: with one adapter the
neutral shape is informed by one wire format, so a second backend will still move
something. What it will not have to move is a vendor name out of a shared type, and
it has one worked example of where such a thing goes. No trait, no provider enum and
no capability negotiation was invented for a backend that does not exist.

`Prompt::thinking` is the one field whose presence is a capability claim rather than
a request shape, and the one place the split above leaves a claim about a provider in
`sandbx-prompt`; [decision-thinking-replay.md](decision-thinking-replay.md) is why it
is one variant, and what the loop does with what comes back.
