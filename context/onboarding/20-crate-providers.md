# The providers crate is a tree with a boundary in the middle

`sandbx-providers` is the box [04 — the architecture](04-the-architecture.md)
names twice in View 3: **the provider seam** at
[`lib.rs`](../../crates/sandbx-providers/src/lib.rs), and **the vendor
boundary** at [`anthropic.rs`](../../crates/sandbx-providers/src/anthropic.rs)
and below. In View 2 it is one line — `open(request)` at the top of every round.
In View 1 it is nowhere, because nothing in here spawns a process or installs a
kernel rule. It has no internal dependency, and it is the one crate that could
be lifted out of the workspace and still compile.

[02 — what a harness is](02-what-a-harness-is.md) is the on-ramp, and it owns
the protocol: the stateless `POST /v1/messages`, `tool_use`/`tool_result`
pairing, the streaming event sequence, reasoning that comes back signed. Read it
first. Nothing here re-derives any of that. This chapter is about the seventeen
files that implement it, what each one is allowed to know, and where its tests
are.

## The tree, and which half of it knows a vendor

The module tree *is* the boundary. There is no inner crate and no trait: the
line runs through one directory listing (#59).

```
crates/sandbx-providers/src/
  lib.rs           EventStream — the seam — plus every re-export
  prompt.rs        Prompt, RequestMessage, ContentBlock, Role,
                   ToolDefinition, ToolChoice, Thinking — data, no Serialize
  event.rs         AgentEvent, StopReason
  error.rs         ProviderError
  sse.rs           SSE framing, knowing no API's field names
  credentials.rs   resolve_api_key, anthropic_api_key
  mock.rs          MockProvider — behind the `mock` feature
  ─────────────────── below here, one API's vocabulary ───────────────────
  anthropic.rs     AnthropicClient, the base-URL rules, the HTTP client
    body.rs        Serialize for the Messages body, built from a &Prompt
    wire/mod.rs    pub(crate): event_stream, RawApiErrorEnvelope
      payload.rs      the Raw* frame shapes — Deserialize and nothing else
      accumulate.rs   the fold: frames in, AgentEvents out
      tests/          content, lifecycle, tool_use, usage
```

A reader who has met one boundary in this repo will immediately ask the right
question: what *stops* a vendor string from appearing in `prompt.rs`? Most of
the answer is a compiler rule, and one row of it is not.

| what stays at or below `anthropic.rs` | what keeps it there |
|---|---|
| the body — key names, omission rules, `stream: true` | `Body` is `pub(super)` inside a private `mod body`, and no neutral type has a `Serialize` at all, so there is no second way to turn one into JSON |
| the frame shapes | every `Raw*` in `payload.rs` is `pub(super)`; the two error shapes are `pub(crate)` so `anthropic.rs` can parse a non-2xx body, and none of them leaves the crate |
| the `stop_reason` string table | `stop_reason` is a private free function in `accumulate.rs`. `StopReason::Other(String)` is public, but nothing outside `anthropic/` can build one *from a wire string* |
| which failures are worth retrying | `ProviderError::ApiError`'s `transient` is decided at its two construction sites, and `is_retryable` reads only that bool |
| the vendor's **name** | nothing mechanical |

The first four rows are why the boundary holds. The last is worth stating
plainly, because the tree above is read as if it were absolute. `lib.rs` names
the module and re-exports `AnthropicClient`, which is unavoidable — the type has
to be reachable. `credentials.rs` sits *beside* `anthropic.rs` rather than below
it and holds both `anthropic_api_key` and the literal `"ANTHROPIC_API_KEY"`. And
the doc comments in `prompt.rs`, `event.rs` and `sse.rs` name Anthropic wherever
a neutral type's shape was decided by one API's behaviour — `Thinking` having
one variant, `Usage` being emitted once, the frame cap being "orders of
magnitude above any real Anthropic frame". None of that is checked by anything.

- **Worth questioning:** the neutral half of this crate is held by convention
  and review, not by a check.
  [decision-provider-seam.md](../decision-provider-seam.md) frames #59 as
  changing "where the vendor's vocabulary stops", and the four mechanisms it
  lists are each genuinely enforced by the compiler — that part is solid. What
  it does not price is that the *name* has no enforcement at all, while the
  claim about it is stated absolutely in two places a maintainer will reach for
  before reading the code. The repo already has the shape of the answer:
  `every_prose_copy_of_the_floor_is_current` is a Rust test that reads files in
  the tree and fails when prose drifts from code, and `context_docs.rs` is
  another. A third in the same style — the vendor's name appears in no
  `src/*.rs` above `anthropic.rs`, with an explicit exemption list for the
  re-export and the credential helper — would cost a few dozen lines and turn
  the boundary's last row from a habit into a build failure. The argument the
  record makes against inventing abstractions for a backend that does not exist
  does not reach this, because a grep is not an abstraction.

## `lib.rs` — the seam is a type, not an object

Forty-nine lines, and three of them are the crate's whole public abstraction:

```rust
pub type EventStream = std::pin::Pin<
    Box<dyn futures_util::stream::FusedStream<Item = Result<AgentEvent, ProviderError>> + Send>,
>;
```

[02](02-what-a-harness-is.md) unpacks what each of `Pin`, `dyn`, `FusedStream`
and `Send` is doing, and
[decision-provider-seam.md](../decision-provider-seam.md) is the record of
deleting the one-variant `Provider` enum that used to sit here (#90). What is
worth adding at the module level is the inverse question: what would a second
adapter actually have to produce?

- **One `async fn` returning `Result<EventStream, ProviderError>`.** Not an
  `impl` of anything. `AnthropicClient::stream_chat` and
  `MockProvider::stream_chat` share no declared relationship — they are two
  inherent methods that happen to return the same alias, and `run_turn` in
  `sandbx-agent` is generic over a closure, so it never names either.
- **A fold onto `AgentEvent` and `StopReason`.** Those are the vocabulary, and a
  second adapter maps its own frames onto them rather than extending them.
- **Its own body serializer over `&Prompt`,** since there is no shared one to
  reuse and no `Serialize` to derive from.
- **Its own `transient` judgement,** because `is_retryable` asks the adapter
  rather than deciding.

What it would *not* get for free is `ProviderError`, and the crate is honest
about this one being informed by a single implementation. `MissingCredential`
carries an `env_var`, assuming a key in an environment variable;
`InvalidBaseUrl` assumes there is a base URL at all; and `Transport` carries a
`reqwest::Error` in a public field, so a second adapter either uses reqwest or
reshapes the enum. The record states the weakness rather than designing around
it — "with one adapter the neutral shape is informed by one wire format, so a
second backend will still move something" — and this enum is where the moving
would be.

`lib.rs` also holds `ensure_crypto_provider_installed`, which is a rustls detail
and has its own section at the end.

## `prompt.rs` — data with no `Serialize`

[`prompt.rs`](../../crates/sandbx-providers/src/prompt.rs) is 140 lines of plain
structs and enums, and the load-bearing fact is a *missing* derive. Its module
doc says so first:

> Plain data: no `Serialize` anywhere below, because the body shape, its field
> names and its required-together rules belong to one API.

`Prompt` carries `model` (a freeform `String`, because "new model IDs ship
regularly"), `max_output_tokens`, an optional `system`, the `messages`, the
`tools`, an optional `tool_choice` and an optional `thinking`. `ToolChoice` and
`Thinking` have exactly one variant each, and both doc comments give the same
reason: an `Auto` variant would describe a request indistinguishable from
omitting the field.

`ContentBlock` is the one to read properly, because it is the type
`sandbx-agent` and `sandbx-cli` both build by hand. The derive line is part of
the design:

```rust
/// One block of a turn's content.
#[derive(Debug, Clone, PartialEq)]
pub enum ContentBlock {
    /// Prose, the only block kind a first user turn needs.
    Text {
        /// Sent as given.
        text: String,
    },
```

`PartialEq` and not `Serialize` is the whole point — equality is what a test
wants to compare, and serialization is what no caller may have. The five
variants:

| variant | fields | who builds one |
|---|---|---|
| `Text` | `text` | the CLI, from the user's prompt or a session replay |
| `Thinking` | `text`, `signature` | `sandbx-agent`, from an `AgentEvent::ThinkingBlock` |
| `RedactedThinking` | `data` | the same, from `AgentEvent::RedactedThinking` |
| `ToolUse` | `id`, `name`, `input` | `sandbx-agent`, replaying a call it answered |
| `ToolResult` | `tool_use_id`, `content`, `is_error` | `sandbx-agent`, after the gate and the tool |

The last one is where the pairing rule from [02](02-what-a-harness-is.md) lands:

```rust
    /// The outcome of running a tool call.
    ToolResult {
        /// The `id` of the [`ToolUse`](Self::ToolUse) block this answers.
        tool_use_id: String,
        /// The tool's output, or its error message when `is_error` is set.
        content: String,
        /// `Some(true)` marks the call as failed.
        is_error: Option<bool>,
    },
```

`is_error` is `Option<bool>` rather than `bool` so that a successful result
omits the key entirely rather than sending `false`, which is the omission rule
`body.rs` implements and a test pins.

What the missing `Serialize` buys, concretely: a top-level type cannot be posted
to any API by accident. There is no `serde_json::to_string(&prompt)` anywhere in
the workspace that could compile, so a second code path that wanted to send a
`Prompt` somewhere — a debug dump, a log line, a cache file — has to go through
`anthropic/body.rs`, which is `pub(super)` and therefore cannot be reached. The
one escape hatch is `Debug`, which is derived, and `Prompt` has no secret in it;
the key lives in the client, not the prompt.

`ToolDefinition::schema` is a `serde_json::Value` rather than a
`schemars::Schema`, with the reason in the field's own doc: "so this crate need
not depend on sandbx-tools". That is what keeps the dependency column in
[guide-repo-map.md](../guide-repo-map.md) empty for this crate.

Tests: `anthropic/body.rs`'s own `mod tests` is where every field of this tree
is pinned, because the only observable thing about a `Prompt` is what it
serializes to.

## `event.rs` — the vocabulary everything above speaks

Ninety-six lines, no logic, and it is the file to read before any of
`sandbx-agent`, `sandbx-tui` or the CLI's renderer. Seven events:

| event | emitted | carries |
|---|---|---|
| `Text` | per `text_delta` | `delta` — the new text, not the accumulation |
| `Thinking` | per `thinking_delta` | `delta`, for a renderer only |
| `ThinkingBlock` | at a signed block's close | `text`, `signature` — the replayable form |
| `RedactedThinking` | at `content_block_start` | `data`, already whole |
| `ToolCallRequested` | once per call, on close | `id`, `name`, parsed `input` |
| `Usage` | at most once per turn | four `Option<u32>` counters |
| `Stop` | at `message_stop` | `reason: StopReason` |

Three asymmetries in that table are each a decision, and all three are explained
in [02](02-what-a-harness-is.md): `Thinking` streams while `ThinkingBlock` is
whole, because a renderer and the replay need different things from one pass;
`Usage` is once because the counts are cumulative; `ThinkingBlock` is withheld
entirely when the signature never arrived.

`StopReason` has six variants — `EndTurn`, `ToolUse`, `MaxTokens`,
`StopSequence`, `Unspecified` and `Other(String)`. `Unspecified` exists because
`message_delta.stop_reason` is nullable on the wire; `Other` exists because new
reasons ship over time and, as its doc says, "which strings map here is an
adapter's business". `sandbx-agent` names this type in its own public API as
`TurnOutcome::round_stop` and does not re-export it (#190), so there is one path
to one type: a consumer that wants a `StopReason` depends on this crate.

**What happens to a wire event with no `AgentEvent`?** Nothing at all. It is
parsed into a catch-all variant and the arm that handles that variant is empty —
at all three levels, for an unknown `type`, an unknown `content_block` kind and
an unknown delta kind. The stream does not end, no error is produced, and
nothing is recorded, because this crate has no `tracing` dependency to record
with. That is upstream's own instruction followed literally, and
[02](02-what-a-harness-is.md) raises the cost of doing it silently; it is not
re-raised here.

## `sse.rs` — a byte stream becomes frames

[`sse.rs`](../../crates/sandbx-providers/src/sse.rs) is 315 lines, nearly half
of them tests, and it is the only code in this crate reading bytes straight off
the network. Its module doc draws the boundary — it "knows the SSE framing rules
and nothing about what any particular API puts in `data:`" — and its output is a
`RawSseEvent`, a `pub(crate)` struct of an optional `event` name and a `data`
string.

`tokenize` is a `futures_util::stream::unfold` over a `TokenizerState` holding
the source stream, a raw `Vec<u8>` buffer, a `scanned` cursor and a `done` flag.
The four corners worth knowing before you touch it:

- **A chunk can split a multi-byte character.** So bytes are buffered raw and
  decoded only once a range ends at a `\n` — safe mid-sequence because no UTF-8
  continuation or lead byte takes the value `0x0A`. A line that is not valid
  UTF-8 becomes `ProviderError::MalformedEvent`, not a panic.
- **`scanned` exists for complexity, not correctness.** Without it, every
  arriving chunk rescans the buffer from zero, which is quadratic in the length
  of one line — and a `data:` line carrying a kilobytes-long signature is
  exactly that case.
- **A partial frame at EOF is still a frame.** When the source stream ends, the
  tokenizer terminates whatever is left in the buffer rather than dropping it:

```rust
            None => {
                state.done = true;
                // Whatever sits after the last `\n` is a line the sender never
                // terminated, and the scan above only yields lines ending at one — so
                // without this it is dropped, commonly the `message_stop` frame.
                // Terminated here, not decoded separately, so one scan owns the UTF-8
                // decode, CR trim and cap check.
                if !state.buf.is_empty() {
                    state.buf.push(b'\n');
                }
            }
```

  Two tests pin it, and the second names the real-world shape:
  `a_trailing_event_with_no_blank_line_survives` and
  `an_unterminated_line_split_across_chunks_survives`, the latter documented as
  "the shape a connection reset produces".
- **Nothing is emitted after a terminal item.** `ended` sets `done` and clears
  the buffer, and the `done` check is the first thing `next_event` does:

```rust
    // Checked before anything is drained: `done` is set only just before a terminal
    // item, so draining what is buffered behind one would emit frames after the error
    // or EOF that ended the stream.
    if state.done {
        return None;
    }
```

Three more behaviours a caller depends on. A blank line with no pending lines is
a keep-alive and is skipped, so a heartbeat does not produce a phantom event.
`id:`, `retry:` and `:`-comment lines are ignored outright — this crate never
resumes a stream via `Last-Event-ID` — which means a comment-only frame yields
an *empty* `data`, something the layer above must tolerate rather than reject.
And one SSE event is capped at `MAX_EVENT_BYTES`; [02](02-what-a-harness-is.md)
quotes that constant and the OOM-with-no-diagnostic failure it exists to
prevent.

Tests live in the file's own `mod tests`, thirteen of them, each one chunk
sequence in and a `Vec<Result<RawSseEvent, _>>` out. They are the cheapest thing
in the crate to extend and the right place to reproduce any framing bug.

## `anthropic/wire/accumulate.rs` — one round, rebuilt from deltas

This is the subtlest file in the crate. 361 lines, no HTTP of its own — it reads
only the tokenizer's output — and it turns a flat sequence of frames back into
the blocks a round produced. Its module doc names
the two invariants: "an unmodeled tag is skipped rather than ending the stream,
and a turn ends exactly once".

The state is a `WireState` holding the pinned source stream, the open blocks, a
running `RawUsage`, a held `stop_reason`, a `VecDeque` of events ready to hand
out and an `ended` flag. Only two block kinds need accumulating:

```rust
enum OpenBlock {
    ToolUse {
        id: String,
        name: String,
        partial_json: String,
    },
    Thinking {
        text: String,
        /// `None` until the block's one `signature_delta` arrives. A block that
        /// closes still holding `None` is dropped rather than emitted.
        signature: Option<String>,
    },
}
```

Text needs no entry, because each of its deltas is useful on its own and goes
straight out. `redacted_thinking` needs none either: it arrives whole at
`content_block_start` and is emitted there.

**Why a map and not a vec.** Blocks arrive keyed by an integer index, and
nothing in the protocol promises those indices are contiguous, ordered, or that
every one that opens also closes. A `Vec` would need the index to be a position;
a map lets it be a name.

```rust
    /// Keyed by block index. A `BTreeMap`, not a `HashMap`: blocks still open when the
    /// turn ends flush in index order, which a randomized iteration order would make
    /// unreproducible.
    blocks: BTreeMap<u32, OpenBlock>,
```

So the choice is two decisions stacked: a map rather than a vec because an index
is a key, and *ordered* rather than hashed because the flush at the end of a
turn iterates it and the order is observable.

The four test modules under
[`wire/tests/`](../../crates/sandbx-providers/src/anthropic/wire/tests/mod.rs)
are the best available map of what can go wrong, and they are the right
structure for reading the fold. All four drive `event_stream` over canned frames
rather than poking a `Raw*` type, so they pin what a caller sees; they are unit
tests rather than integration tests because `event_stream` is `pub(crate)`.

- **`content`** — text and thinking, plus the frames that must produce *no*
  event rather than ending the turn. `ping`, an unknown event type, an unknown
  block or delta kind, and a payload-less heartbeat each have a test, and all
  four assert the turn continues. Two more are about the signature rule:
  `an_unsigned_thinking_block_is_dropped_without_an_error` and
  `an_empty_thinking_block_is_still_emitted_for_its_signature` — a block with
  empty text and a signature is replayable and so kept, a block with text and no
  signature is not and so dropped. `closed_block_event` is where both live, and
  an empty signature counts as none.
- **`lifecycle`** — how a turn ends. One `Stop` when `message_stop` arrives,
  including when no frame ever named a reason; `StreamEndedUnexpectedly` when it
  does not; an in-band SSE `error` event ending the stream as an `Err` item,
  with `transient` set from a two-string table rather than from an HTTP status
  the frame does not carry. The last test in the module,
  `the_stream_is_fused_and_survives_being_over_polled`, is the one that pins the
  `FusedStream` in the seam's type to an observable behaviour.
- **`tool_use`** — the one kind whose deltas must be buffered whole, and the
  ways a stream can leave that buffer odd. A call split across fragments; a
  zero-argument call, where an empty buffer means `{}` and not a parse failure;
  parallel calls accumulating independently by index; a block left open and
  flushed at `message_stop`; a block opened over an unclosed one, which
  *discards* the old one; and unparseable JSON becoming a `MalformedEvent`
  rather than a panic.
- **`usage`** — one `Usage` per turn carrying the last figure reported for each
  counter. `absorb` overlays a newer report field by field, so a `message_delta`
  restating `input_tokens` wins over `message_start` while a frame omitting a
  counter keeps the value held. A turn reporting nothing emits no event at all
  rather than four zeros, and `usage_survives_a_truncated_turn` pins that the
  counts still come out when the stream dies — the caller paid for them.

Two rules in the fold are each worth one reading, because both exist to protect
the pairing rule one layer up. The first is index reuse: a `content_block_start`
that does not accumulate still *clears* the index, because a stream that reused
index 0 for text after an unclosed `tool_use` would otherwise fold the text into
the abandoned call and emit a `ToolCallRequested` the model never asked for. The
second is which endings flush:

```rust
    /// Queue every block still open when the turn ended.
    ///
    /// From `message_stop` only, covering a turn that ends properly with a block whose
    /// `content_block_stop` went missing: dropping a tool call would leave
    /// `Stop { reason: ToolUse }` telling the caller to run a tool it never got. The
    /// paths that end without `message_stop` do not flush — a truncated block's JSON
    /// is incomplete, so flushing would put a `MalformedEvent` ahead of the honest
    /// [`ProviderError::StreamEndedUnexpectedly`].
```

- **Worth questioning:** the layer below this one caps a single frame precisely
  because an unbounded buffer is "OOM-killed with no diagnostic", and the fold
  that concatenates those frames has no cap at all. `partial_json` grows by
  `push_str` for every `input_json_delta`, a thinking block's `text` and
  `signature` the same, and `blocks` takes an entry per distinct `u32` index a
  `content_block_start` names. Each individual frame is bounded; their sum is
  not, so a gateway streaming valid, in-cap fragments forever allocates until
  the process dies, and the diagnostic `MAX_EVENT_BYTES` exists to preserve is
  lost one layer above where it was installed. What bounds it today is
  `TurnLimits::stream_timeout` in `sandbx-agent` — a wall-clock bound owned by a
  *different crate*, which a library caller using this one directly does not
  get. [`SECURITY.md`](../../SECURITY.md) claims no memory bound, so the claim
  is honest and only the mechanism is in question.
  [decision-provider-seam.md](../decision-provider-seam.md) names SSE
  accumulation as the hard part and closes by stating the one weakness it
  accepts — the one-adapter neutral shape — and a bound that stops at a layer
  boundary is not among them.

## `anthropic/body.rs` and `payload.rs` — the two halves of the wire

[`body.rs`](../../crates/sandbx-providers/src/anthropic/body.rs) is the outbound
half: 466 lines, more than half of them tests, and it is "the whole of what
`crate::prompt` refuses to know". Hand-written rather than derived because
several rules are conditional and serde's attributes cannot express them. The
entry point is a newtype and a destructuring `let`:

```rust
pub(super) struct Body<'a>(pub(super) &'a Prompt);

impl Serialize for Body<'_> {
    /// The destructuring `let` makes a field added to [`Prompt`] later fail to
    /// compile until it is written out here.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Prompt {
            model,
            max_output_tokens,
            system,
            messages,
            tools,
            tool_choice,
            thinking,
        } = self.0;
```

That is the same trick as the exhaustive match [04](04-the-architecture.md)
names: a field added upstream becomes a build failure rather than a key silently
missing from a request. Below `Body` sit six more wrappers — `Messages`,
`MessageBody`, `Blocks`, `BlockBody`, `Tools`, `ToolBody` — plus
`ToolChoiceBody` and `ThinkingBody`, each a private struct with one `Serialize`
impl. The renames and the omissions are [02](02-what-a-harness-is.md)'s subject;
what matters at the module level is that every one of these types is private,
`Body` is `pub(super)`, and `mod body` is itself private inside `anthropic.rs`.

[`payload.rs`](../../crates/sandbx-providers/src/anthropic/wire/payload.rs) is
the inbound half, and deliberately the dumbest file in the crate: "every type is
a record of a frame as the API sends it, with a catch-all variant beside the
tags it tolerates. Folding them is `accumulate`'s job." `RawStreamEvent`,
`RawContentBlockStart` and `RawDelta` are internally tagged on `type`, each
with:

```rust
    /// Any `type` this file does not model — `server_tool_use` results, MCP events.
    #[serde(other)]
    Unknown,
```

`RawUsage` is one type for both `message_start` and `message_delta`, with every
field an `Option` so that a frame omitting a counter cannot end the turn and
"not reported" stays distinguishable from a reported zero. The two error shapes,
`RawApiErrorBody` and the `RawApiErrorEnvelope` that wraps it, are the only
types here reaching past `pub(super)` to `pub(crate)`, because an HTTP error
response and an in-band SSE `error` event carry the same shape and it is
`anthropic.rs` that parses the former. Neither leaves the crate.

## `anthropic.rs` — one client, and four settings that are not defaults

221 lines. `AnthropicClient` holds a `reqwest::Client`, a `SecretString` and a
`String` base URL, and `Debug` is derived rather than hand-written so that the
derive picks up any field added later while `SecretString`'s own `Debug` prints
a redaction. `new` makes no network call, so every construction failure is
local.

`with_base_url` is `pub` and not `#[cfg(test)]`-gated, because it is also the
seam for a self-hosted Anthropic-compatible gateway. Everything it validates is
a credential rule, since the key travels in `x-api-key` on every request:

```rust
    match url.scheme() {
        "https" => Ok(Reachability::PublicHttps),
        "http" if url.host_str().is_some_and(is_loopback_host) => Ok(Reachability::LoopbackHttp),
        "http" => Err("http:// would send the API key in cleartext; use https://"),
        _ => Err("only https:// (or http:// to a loopback host) is supported"),
    }
```

A query string, a fragment and embedded userinfo are each refused before that
match, because `/v1/messages` is appended to the path and anything after it
would land mid-URL. The trailing `/` is trimmed by hand rather than via
`Url::as_str`, which would normalise `https://host` to `https://host/` and
double the slash. `is_loopback_host` strips the brackets an IPv6 literal keeps
and matches `localhost` by name, since it does not parse as an IP.

The `Reachability` that validation returns then decides two client settings:
`https_only(true)` for the public case as belt and braces, and `no_proxy()` for
the loopback case — because the `system-proxy` feature is on, so reqwest would
otherwise honour `HTTP_PROXY` and route an approved `http://127.0.0.1` request
off the machine with the key in cleartext. Two more settings are fixed:

```rust
        // reqwest's cross-host redirect scrubbing strips only the headers it knows
        // are credentials — `Authorization`, `Cookie`, `Proxy-Authorization` — never
        // `x-api-key`, so under the default policy a 3xx would replay the key, and
        // for 307/308 the conversation body, to whatever host `Location` names.
        .redirect(reqwest::redirect::Policy::none());
```

and a `read_timeout` rather than a `timeout`, because the latter bounds the
whole streamed body and would kill a long generation, while the former bounds
inactivity and resets on every chunk.

`stream_chat` is four statements: post the `Body`, take the status, return early
if it is not a success, and wrap `response.bytes_stream()` in `sse::tokenize`
and then `wire::event_stream`. The `Result` covers everything knowable before
the first event; anything later arrives as an `Err` *item* in the stream, which
is why a caller that may retry clones the prompt first. Non-2xx goes through
`map_error_response`: 429 becomes `RateLimited`, everything else `ApiError` with
`transient` set from whether the status is `500` or above, and `Retry-After` is
read on every status because Anthropic sends it with a 529 too.

Tests live in
[`tests/anthropic_client.rs`](../../crates/sandbx-providers/tests/anthropic_client.rs)
— real HTTP against a `wiremock` server on loopback, no key and no network. Two
are worth knowing about. `a_redirect_is_not_followed` mounts a second mock
server with `.expect(0)`, so the assertion is that the attacker's server was
never reached. And `client_future_stays_spawnable` is compiled but never run:

> The signature states the returned stream is `Send`; that the *future* is, it
> does not — that is inferred, so it can regress silently, and a non-`Send`
> future cannot be `tokio::spawn`ed.

## `credentials.rs` — a `SecretString` nothing re-exports

Twenty-nine lines, two functions. `resolve_api_key` takes the variable name and
an *injected* lookup closure, trims the value, treats blank as absent, and wraps
what is left in `secrecy::SecretString`. `anthropic_api_key` is the one-line
application of it to `ANTHROPIC_API_KEY`.

[14 — audit, sessions, credentials](14-audit-sessions-credentials.md) owns the
policy: which source wins, why the file is located only after the environment
comes up empty, what `SecretString` does and does not guarantee. Two
module-level facts it does not cover.

**The crate re-exports `secrecy` nowhere.** `AnthropicClient::new` takes a
`SecretString` in its public signature, but the type itself is not re-exported
from `lib.rs`, so a caller must name the dependency itself and resolve to the
*same* version — two `SecretString`s from two semver-incompatible `secrecy`
releases are different types. `sandbx-cli` pays that cost in a manifest comment:

```toml
# `sandbx-providers` does not re-export `secrecy`; keep this at the version it
# resolves, or `AnthropicClient::new` takes a different `SecretString`.
secrecy = "0.10.3"
```

What it buys is that the secret type is not part of this crate's API surface. A
re-export would make every `secrecy` major bump a breaking change here, and
would invite a caller to treat `sandbx_providers::SecretString` as the canonical
one — which is the same reasoning that keeps `sandbx-agent` from re-exporting
`StopReason` (#190): one path to one type.

**Only one of the two functions has a caller.** `sandbx-cli`'s `auth.rs` calls
`resolve_api_key` directly with its own `ENV_VAR` constant, so the
trim-and-blank rule has one home, while `anthropic_api_key` is reached only by
`AnthropicClient::from_env` — which in turn is used only by the live test. The
pair is the vendor's name appearing above `anthropic.rs`, discussed at the top.

Tests:
[`tests/credentials.rs`](../../crates/sandbx-providers/tests/credentials.rs),
seven of them, all driving the injected closure. None mutates a real
environment, because `set_var` is an `unsafe fn` under edition 2024 and the
workspace forbids `unsafe_code` in test binaries too.

## `mock.rs`, and a `[[test]]` target that is really a resolver-3 trap

[`mock.rs`](../../crates/sandbx-providers/src/mock.rs) is 31 lines behind the
`mock` feature: `MockProvider::new` for a canned all-success turn,
`with_results` for injecting an error at a chosen point, and a `stream_chat`
that takes `self` by value — throwaway per-test data, unlike the real client's
`&self`. It is interchangeable with `AnthropicClient` through the returned
`EventStream` alone, which is the seam's whole claim demonstrated in one file.

The interesting part is in the manifest, and [05](05-seven-crates.md) points at
it:

```toml
# Declared as a target rather than via a self dev-dependency on `features =
# ["mock"]`: resolver v3 unifies features per package, so that edge would turn
# `mock` on in the one rlib every consumer links, and production code touching
# `MockProvider` would pass clippy and the test suite before failing the release
# build.
[[test]]
name = "mock_provider"
required-features = ["mock"]
```

Worth walking once, because the obvious thing to write is the broken one. A
crate that wants its own feature-gated item in its own tests reaches for
`sandbx-providers = { path = ".", features = ["mock"] }` under
`[dev-dependencies]`. Resolver v3 unifies features *per package*, not per
dependency edge, so that turns `mock` on in the single rlib every consumer in
the workspace links against — and then `sandbx-cli` naming `MockProvider` in
production code compiles, passes clippy, passes `cargo test`, and fails only in
a release build with no dev-dependencies. A `[[test]]` with `required-features`
has no such edge: the target is skipped unless the feature is on, so a plain
workspace-wide `cargo test` reports zero tests here and CI names the feature
explicitly, as `--features sandbx-providers/mock`.

Nothing in the workspace consumes `MockProvider`. `sandbx-agent`'s own loop
tests roll a `Script` double instead, with a comment saying why: using this one
"would cost a `mock` feature, a `required-features` target and a CI command
naming both to borrow one line". So the only consumer of the feature is the
integration test that exercises it — which is consistent with the seam's
argument that a test double is a closure, not a published type.

`live-anthropic-tests` is the crate's other feature and
[`tests/live_anthropic.rs`](../../crates/sandbx-providers/tests/live_anthropic.rs)
is its only consumer: one test, a real key, real money, and a feature rather
than a runtime env-var check so that running without opting in "reports zero
tests here instead of a silently-passing no-op".

## `error.rs`, and the rustls detail behind the `crypto_provider` test

[`error.rs`](../../crates/sandbx-providers/src/error.rs) is `ProviderError`'s
seven variants, split by what a caller can do about them. `MissingCredential`
and `InvalidBaseUrl` are local, before any request; `Transport` is a failure
with no status or vendor body to report; `ApiError` and `RateLimited` are the
API answering; `MalformedEvent` and `StreamEndedUnexpectedly` are the stream.
`is_retryable` is the summary a backoff layer reads — true for transport and
rate limits, the adapter's `transient` bool for an API error, and `false` for a
truncated stream, because the turn was already partly delivered and re-sending
is the caller's judgement call. `retry_after` reads the same header out of
either carrying variant, so a caller need not know which it holds. Tests are in
[`tests/error.rs`](../../crates/sandbx-providers/tests/error.rs): every
variant's `Display`, and `source()` wired only on the one variant that carries
one.

That leaves the oddest test target in the crate, and the reason is a
supply-chain decision made in the manifest. `reqwest` is taken with
`rustls-no-provider` rather than `rustls`, because the latter auto-picks
`aws-lc-rs`, "which vendors and compiles C and assembly" — in a workspace that
sets `unsafe_code = "forbid"` and whose claims rest on review, that is a large
dependency to accept for a TLS backend. So no crypto provider is selected by the
HTTP stack, `rustls` becomes a *direct* dependency purely to select `ring`, and
one function closes the gap:

```rust
/// Install the `ring` crypto provider for `rustls`, once per process.
///
/// `rustls-no-provider` selects none and building any `reqwest::Client` panics
/// without one — hence `pub`, so an integration test, a separate compiled crate,
/// can install it too. Idempotent: `install_default` is a process-global set-once,
/// so a second call's `Err` means a provider is already installed.
pub fn ensure_crypto_provider_installed() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
```

The trap it defuses: with no provider enabled anywhere, building a
`ClientConfig` fails *at runtime*, not at compile time. `build_http` calls it
before every client is built, so the production path is safe; the `pub` exists
because the install is process-global and an integration test is a separate
compiled crate with its own process.
[`tests/crypto_provider.rs`](../../crates/sandbx-providers/tests/crypto_provider.rs)
is twenty-one lines and says so in its module doc: it lives there "rather than
in a `#[cfg(test)] mod tests` so it exercises the reason the function is `pub`".
Two assertions — that a second install does not panic, and that a provider
really is installed and usable.

## Where the tests are

| what | where |
|---|---|
| the body serializer, every field and omission | `src/anthropic/body.rs`, `mod tests` |
| SSE framing, chunk by chunk | `src/sse.rs`, `mod tests` |
| the fold, by what a turn is doing | `src/anthropic/wire/tests/` — `content`, `lifecycle`, `tool_use`, `usage` |
| the client over real HTTP, no key | `tests/anthropic_client.rs` |
| key resolution, through an injected lookup | `tests/credentials.rs` |
| `Display` and `source()` per variant | `tests/error.rs` |
| the `pub` crypto install, from another crate | `tests/crypto_provider.rs` |
| the mock double | `tests/mock_provider.rs`, needs `mock` |
| the real API | `tests/live_anthropic.rs`, needs `live-anthropic-tests` |

The pattern is the one [guide-module-layout.md](../guide-module-layout.md)
prescribes: a unit test where the thing under test is private, an integration
test where the point is the public contract — and `crypto_provider.rs` is the
case where *being a separate crate* is itself the thing asserted.

## You should now be able to explain

- Which four things the compiler keeps below `anthropic.rs`, and the one thing
  about the boundary that nothing checks.
- Why the seam is a type alias over a stream rather than a trait object with
  methods, and the four things a second adapter would have to produce.
- What the absence of `Serialize` on `Prompt` prevents, and which single module
  is allowed to supply it.
- Which of the seven `AgentEvent`s stream and which arrive whole, and why a
  thinking block with no signature never leaves the crate.
- What the tokenizer does with a frame that has no trailing blank line, and why
  nothing may be emitted after a terminal item.
- Why open blocks live in a `BTreeMap` keyed by index rather than in a `Vec`,
  and what reusing an index without closing it would otherwise cause.
- Why a flush happens at `message_stop` and not on the paths that end without
  one.
- What a caller pays for `secrecy` not being re-exported, and what that buys.
- Why `MockProvider` is reached through a `[[test]]` target with
  `required-features` rather than a self dev-dependency.
- Why `rustls` is a direct dependency of a crate that opens no TLS connection
  itself, and why the crypto test is an integration test.

## Next

[21 — the agent crate](21-crate-agent.md), which is the first consumer of
everything here: `run_turn` takes a closure that hands back an `EventStream`,
folds `AgentEvent`s into one round's message, and decides what a `ToolUse` block
becomes. The vocabulary this chapter described is the vocabulary that one
speaks.
