# A harness is a loop around a stateless API

Two boxes of [04 — the architecture](04-the-architecture.md) are this chapter's
subject: **the provider seam** and **the vendor boundary** from View 3, plus
**the round** from View 2. Everything here sits upstream of the sandbox. It is
the part of sandbx that would exist in any harness, confining or not — and it is
worth reading before the boundary chapters, because the shape of this loop is
what makes a boundary necessary at all.

Every claim about the API is linked to Anthropic's own documentation rather than
inferred from how this repo behaves. The docs are the authority on the protocol;
the code in this worktree is the authority on what sandbx does with it. The
links are collected at the end, and cited inline where each fact is used.

## Two facts, and the rest follows

- **The endpoint is stateless.** `POST /v1/messages` takes the entire
  conversation as its `messages` array on every single call ([the Messages API
  reference][messages]). There is no conversation object on the server, no ID to
  append a turn to, and no way to say "continue". A fifteen-round turn sends the
  first fourteen rounds again on the fifteenth request.
- **The model has no hands.** It emits tokens. When it wants a file read, what
  comes back is not a file — it is a structured *request* that some other
  program read the file and say what it found.

Put together, those two facts hand one program all of the state and all of the
doing. That program is the harness, and "harness" is the right word: the model
is an engine, and everything that lets it act on a machine is code someone
wrote around it. There is no part of this that the API does for you.

## A conversation is a list of blocks, not a list of strings

Each element of `messages` carries a `role` — `user` or `assistant`, and those
are the only two — and a `content`. Content is either a plain string or an array
of typed **content blocks** ([the Messages API reference][messages]). Once a
conversation involves tools it is always the array form, because the things that
have to be said no longer fit in a string.

sandbx models five block types, in `ContentBlock` in
[`prompt.rs`](../../crates/sandbx-providers/src/prompt.rs):

| block | who writes it | what it carries |
|---|---|---|
| `text` | either side | prose |
| `thinking` | the model | reasoning text and a signature |
| `redacted_thinking` | the model | an opaque blob in place of the reasoning |
| `tool_use` | the model | an `id`, a tool `name`, and an `input` object |
| `tool_result` | the harness | the `tool_use_id` it answers, `content`, and an optional `is_error` |

Two things in that table surprise people.

- **A `tool_result` is a *user* message.** There is no third role for a tool.
  The model's request and the harness's answer are two turns by the two
  available speakers, and the answer is attributed to the user because the user
  is whoever is on the other end of the conversation — which, for a tool call,
  is the harness.
- **The system prompt is not a message.** It is a top-level `system` parameter
  beside `messages`, not an element of it ([the Messages API
  reference][messages]). sandbx omits it entirely when there is none rather than
  sending `null`, and the comment in
  [`body.rs`](../../crates/sandbx-providers/src/anthropic/body.rs) says why:
  "the API rejects a null `system`".

`Prompt`, `RequestMessage` and `ContentBlock` are sandbx's own vocabulary, and
none of them knows a wire field name. The whole translation is one
hand-written `Serialize` implementation — see `Body` in `body.rs`, whose doc
notes that the destructuring `let` at the top "makes a field added to `Prompt`
later fail to compile until it is written out here". That file is also where
every conditional omission lives: `system` only when present, `tools` only when
non-empty, `tool_choice` only alongside a non-empty `tools`. Each rule has a
test next to it that pins it, and each rule is a request the API refuses.

## Tool use is two blocks and one pairing rule

The model asks with a `tool_use` block in an assistant message. You answer with
a `tool_result` block, in the next user message, carrying the same `id` under
the key `tool_use_id`. If the tool failed, you set `is_error: true` and put the
failure in `content` — there is no separate error channel.

The rule that makes a request valid is stricter than it first looks
([handling tool calls][tool-use]):

> Tool result blocks must immediately follow their corresponding tool use blocks
> in the message history. You cannot include any messages between the
> assistant's tool use message and the user's tool result message.

And within that user message, the `tool_result` blocks must come first in the
content array, with any text after all of them. Break either rule and the API
answers with an error naming `tool_use` ids "found without `tool_result` blocks
immediately after".

The consequence is the single most load-bearing fact about writing a harness:
**every requested call must be answered, including the ones that do not run.**
An unanswered `tool_use` is not a skipped call, it is a conversation the API
will not accept again. So all three ways a call can fail to run still produce a
`tool_result`, via `refused` in
[`turn/tools.rs`](../../crates/sandbx-agent/src/turn/tools.rs), each with
`is_error` set:

- a name no built-in matches, answered "unknown tool: …" — lookup is exact by
  design, because a miss is a prompt or schema bug rather than a near-miss to
  normalise;
- a tool the caller did not offer this turn, answered "tool not offered this
  turn: …";
- a call the gate denied or aborted, answered with the gate's own reason. The
  comment on the abort arm states the rule outright: "Answered, not skipped: a
  `tool_use` with no `tool_result` is a transcript no provider takes back, and
  this one is stored and resumed."

This is the first place the protocol and the security model touch. A refusal
cannot be silence. The model is told that the call did not happen and why, in a
block the next request can legally carry — which means a denial is a fact the
model can reason about, and the gate's decisions become part of the
conversation.

## Why there has to be a loop

A tool result is information the model has not seen, and the endpoint is
stateless, so the only way to let it act on that information is another request
carrying everything including the result. That is the round, and it is not a
design choice — it is what the two facts at the top add up to.

`run_turn` in [`turn.rs`](../../crates/sandbx-agent/src/turn.rs) is that loop.
Per round:

- the request is the surviving history plus everything this turn has produced so
  far, in order;
- the stream is consumed into a list of blocks;
- a round that produced nothing but reasoning ends the turn — reasoning is
  stripped on the way out, so keeping it would leave an empty content array the
  API rejects;
- otherwise `answer_calls` walks the blocks and answers every `tool_use` among
  them. If it comes back with no results at all, there were no tool calls, and
  the turn is over;
- otherwise the assistant message and the user message of results are both
  appended, and the loop goes round again.

**Nothing branches on the stop reason.** 04 names this as a decision; the reason
it matters at the protocol level is that `message_delta.stop_reason` is nullable
on the wire, which `StopReason::Unspecified` exists to represent. A harness that
re-entered on `stop_reason == "tool_use"` would be trusting the provider's
description of its own output over the output itself.

The loop is bounded — eight rounds by default, as the diagram in 04 shows — and
the exit is worth noting for its shape rather than its number. Hitting the bound
returns an outcome that says so, with the comment "Returned rather than dropped:
every prefix ends unanswered too, so no truncation reads as finished". That is
what exit code 2 in [01](01-what-sandbx-is.md) reports. The full account of the
loop and its three traps is [guide-turn-loop.md](../guide-turn-loop.md).

## Streaming is a byte stream you fold back into blocks

sandbx always streams. `body.rs` writes `stream` as a constant rather than
taking it from `Prompt`, with the comment "Not a `Prompt` field: this client has
no non-streaming path." Streaming costs two layers of machinery that a
blocking call would not need, and the two are kept strictly apart.

**Layer one is Server-Sent Events framing,** in
[`sse.rs`](../../crates/sandbx-providers/src/sse.rs), whose module doc draws the
line:

> Knows the SSE framing rules and nothing about what any particular API puts in
> `data:`, so a second SSE-based provider could reuse it unchanged.

Two details there are worth stopping on, because both are corners rather than
boilerplate. The first is an encoding corner. HTTP chunks arrive with no
relation to line boundaries, and a `data:` payload is UTF-8, so a chunk can
split a multi-byte character in half. `tokenize` therefore buffers raw bytes and
decodes only once a range ends at a newline — safe mid-sequence, as its doc
explains, "because no UTF-8 continuation or lead byte takes that value". The
second is a resource bound:

```rust
/// Cap on the bytes a single SSE event may occupy before it is rejected.
///
/// Without one, `buf` grows unbounded when the stream never produces the `\n` the
/// framing waits for — a gateway answering with a large non-SSE body — and the
/// process is OOM-killed with no diagnostic. 4 MiB is orders of magnitude above any
/// real Anthropic frame.
const MAX_EVENT_BYTES: usize = 4 * 1024 * 1024;
```

There is also a Rust corner in `tokenize`'s `.fuse()`. The stream is built from
`futures_util::stream::unfold`, which *panics* if polled after it has returned
`None`. `FusedStream` is the trait that promises polling past the end is
defined, and `.fuse()` is what supplies that promise, since a caller drives the
stream however it likes. Keep that in mind: it reappears below as the reason the
provider seam has the type it does.

**Layer two is the event sequence,** which is where the API's own vocabulary
starts ([streaming][streaming]):

| event | what it means |
|---|---|
| `message_start` | the message shell, with initial usage |
| `content_block_start` | a block opens at an integer index |
| `content_block_delta` | a fragment belonging to that index |
| `content_block_stop` | that block is complete |
| `message_delta` | top-level changes: the stop reason, and usage |
| `message_stop` | the end of the message |
| `ping` | nothing; any number may arrive |
| `error` | an in-band failure, carrying a `type` and no HTTP status |

The deltas are themselves tagged: `text_delta` and `thinking_delta` carry text,
`signature_delta` carries the reasoning signature, and `input_json_delta`
carries a `partial_json` fragment. A tool call's `input` is the concatenation of
those fragments, and the first one can be the empty string — which sandbx reads
as `{}` rather than as a parse failure.

Two instructions in the streaming docs are implemented literally here.

- **"New event types may be added, and your code should handle unknown event
  types gracefully."** Every tagged enum in
  [`payload.rs`](../../crates/sandbx-providers/src/anthropic/wire/payload.rs)
  has a `#[serde(other)]` catch-all variant, and the accumulator's arms for
  those variants do nothing at all.
- **"The token counts shown in the usage field of the `message_delta` event are
  cumulative."** So summing them double-counts. `AgentEvent::Usage` is emitted
  at most once, and its doc in
  [`event.rs`](../../crates/sandbx-providers/src/event.rs) carries the whole
  rule: "Anthropic restates the counts cumulatively on every `message_delta`, so
  summing them double-counts. `None` is 'not reported', not a reported zero."

The fold from that sequence back into blocks is the job of
[`accumulate.rs`](../../crates/sandbx-providers/src/anthropic/wire/accumulate.rs)
and its module doc names the two invariants: "an unmodeled tag is skipped rather
than ending the stream, and a turn ends exactly once". Open blocks are held in
a `BTreeMap` keyed by index rather than a `HashMap`, for a reason the comment
gives: blocks still open when the turn ends flush in index order.

One thing the fold deliberately loses, and it is honest about it:
`AgentEvent::Text`'s doc notes that "Block boundaries are not recoverable:
`content_block_stop` is surfaced only for a `tool_use` block, so a consumer
rebuilding content coalesces consecutive text blocks into one." Nothing
downstream needs the seam between two adjacent text blocks, so it is not
carried.

- **Worth questioning:** an unmodeled tag is dropped *silently*. The
  `RawStreamEvent::Unknown`, `RawDelta::Unknown` and `content_block_start`
  catch-all arms all evaluate to nothing, and `sandbx-providers` has no
  `tracing` dependency at all, so there is no emitter that could record the
  drop. Skipping is right, and upstream asks for exactly that; what neither
  record prices is skipping it with nothing recorded.
  [guide-logging.md](../guide-logging.md) does list "emitters outside
  `sandbx-core`" among what is not built, but as a uniform gap across five
  crates rather than a cost weighed here.
  [decision-provider-seam.md](../decision-provider-seam.md) is the record that
  chose to own this code, and it names "SSE accumulation — the hard part" as
  precisely where a wrapper crate would have helped least; it also ends by
  stating the weakness the one-adapter design leaves, "stated rather than
  designed around". A fold that can discard a block without saying so is a
  second weakness of that hard part, and it is not among the ones named. The
  consequence is concrete: a content-block type added later that carries real
  content would disappear from an assistant message sandbx stores and replays,
  so what goes back would differ from what the model produced — and per
  [preserved thinking][thinking] the prefix a reasoning signature is validated
  against includes every message before the block, which makes an edited
  earlier message exactly the class of change that check exists to catch. The
  failure would arrive with nothing pointing at its cause.

## Reasoning comes back signed

Newer Claude models return their reasoning as `thinking` blocks, and each one
carries a `signature`. Upstream states the purpose plainly: "Preserved thinking
is a property of newer Claude models that guards against distillation"
([preserved thinking][thinking]). The signature is checked on the way back in,
against a prefix made of the top-level system prompt, the set of tools, and
every message before the block.

That check, and one sentence about removal, decide everything sandbx does with
reasoning:

> You can remove thinking blocks from the start of the history (oldest first),
> from the end, or all of them. What fails is a gap: the thinking blocks you
> keep must be an unbroken run of the original sequence.

Three rules fall out of it.

- **An unsigned thinking block never leaves the provider crate.** It cannot be
  replayed, so `AgentEvent::ThinkingBlock` is, in its own words, "Only ever
  emitted for a block that carries a signature: one without is unreplayable, and
  passing it on would put a rejected request in a caller's history rather than
  lose one block".
  Losing one block is the cheaper failure, and it is chosen deliberately.
- **The signature must be concatenated, not assigned.** It arrives as its own
  `signature_delta` just before the block's `content_block_stop`. The
  accumulator appends with `push_str`, and the comment explains why one frame
  per block today is not enough to rely on: "a signature is kilobytes of base64
  arriving under a `_delta` tag, and keeping only the last fragment of a split
  one is a 400 on the next request".
- **The two reasoning kinds travel together.** `redacted_thinking` is reasoning
  the provider withheld, and dropping one kind while keeping the other leaves
  the gap the check looks for. That is a whole predicate in `prompt.rs`:

```rust
impl ContentBlock {
    /// Whether this is reasoning, either kind.
    ///
    /// The two travel together: a filter that keeps one and drops the other leaves a
    /// gap in the reasoning the provider checks for.
    pub fn is_thinking(&self) -> bool {
        matches!(self, Self::Thinking { .. } | Self::RedactedThinking { .. })
    }
}
```

Reasoning also has a lifetime, and it is exactly one turn. `outcome` is the one
exit from `run_turn` — the doc says so: "The one exit from `run_turn`, so no
path can return reasoning to a caller" — and the first thing it does is strip
every reasoning block. Rounds within a turn replay reasoning to each other
because the provider requires it inside a tool-use turn; nothing signed ever
reaches the caller, the screen or the session transcript. The signature is
treated as a secret on top of that: "Opaque. Never log, render or store it." The
reasoning behind the whole arrangement is
[decision-thinking-replay.md](../decision-thinking-replay.md).

On the request side, asking for thinking at all is a small object whose shape is
a moving target. `ThinkingBody` in `body.rs` sends `type: "adaptive"` with a
`display`, "never the `enabled`/`budget_tokens` form: that one is deprecated on
Claude 4.6 and a 400 on 4.7 and every Claude 5 model" — which
[extended thinking][extended] confirms. A test named
`budget_tokens_is_never_sent` holds the line.

## The context window is the one budget you cannot opt out of

Because every round resends everything, a tool-using turn's request grows
monotonically: each round adds an assistant message and a user message of
results, and none of it can be dropped from the middle. A long turn therefore
gets expensive and then gets refused.

sandbx's answer is **compaction**, and its own module doc calls it naive:
"No summarisation model, just a bounded window." It withholds the oldest
messages from the request. What makes it harder than a sliding window is the
pairing rule from earlier — because only a *prefix* can drop, and whatever
becomes the new first message has to be something the API accepts as an opener:
a user turn, non-empty, with no `tool_result` in it. `opens_a_request` in
[`compact.rs`](../../crates/sandbx-agent/src/compact.rs) is that predicate, and
the module doc draws the conclusion: "that makes the legal cut points exactly
the human prose turns."

Two properties are worth carrying away.

- **The cut only ever deepens.** `plan_cut` returns a plan that always contains
  the previous cut, and `run_turn` applies it with `unwrap_or(cut)` so that a
  declined plan cannot restore history that was already withheld. It also fires
  only on a *measured* figure — what the provider reported for a request already
  sent — never a predicted one, so it cannot fire on a turn's first round.
- **A deepened cut invalidates every reasoning block already sent,** because the
  prefix those signatures were checked against has just changed. Removing them
  is the one edit the provider's rule permits, and it has to take both kinds and
  any message left empty:

```rust
/// Drop every reasoning block, and any turn left with nothing else in it.
///
/// Both kinds go together, the provider checking for a gap rather than for a type: an
/// emptied turn can only be the last one, since a round producing only reasoning asks for
/// no tools and ends the loop, so removing it cannot leave two user turns adjacent.
fn drop_thinking(messages: &mut Vec<RequestMessage>) {
    for message in messages.iter_mut() {
        message.content.retain(|block| !block.is_thinking());
    }
    messages.retain(|message| !message.content.is_empty());
}
```

- **Worth questioning:** nothing in the shipped binary can switch compaction on.
  `TurnLimits::default()` sets `compaction: None`, and the two places that
  build one — `AgentRun::execute` in
  [`agent.rs`](../../crates/sandbx-cli/src/agent.rs) and the TUI's in
  [`agent/tui.rs`](../../crates/sandbx-cli/src/agent/tui.rs) — override
  `max_rounds` and take the rest of the default; the wrap-up round in
  [`agent/wrapup.rs`](../../crates/sandbx-cli/src/agent/wrapup.rs) copies
  whatever it was handed. `max_rounds` has a flag. Compaction does not.
  [guide-turn-loop.md](../guide-turn-loop.md) prices the *default* carefully:
  compaction is the only one of the loop's bounds that is lossy, and "its right
  value is not the crate's to guess", because `Turn::model` is a freeform string
  with no context-window table behind it. That argument is sound and it settles
  the default. It does not reach the absence of any way for an operator to state
  the value themselves — and the operator does have the missing fact, since they
  chose the model. As it stands the window is reachable only by a library
  caller, which leaves the hardest path in the loop — a deepening cut and the
  reasoning it invalidates — exercised by its own integration test and by
  nothing else.

## Prompt injection is the threat this shape creates

Look again at what a `tool_result` block is: model-facing input that the harness
did not write. `read` returns the contents of a file. `grep` returns lines out
of a repository. `bash` returns a command's standard output. All of it lands in
the next request as text the model reads, in the same array as the system prompt
and the user's question.

Upstream says this in as many words ([handling tool calls][tool-use]):

> Tool results often carry content from sources outside your control: web pages,
> inbound email, user uploads, third-party APIs. Treat that content as
> untrusted: an attacker who can influence it may embed instructions that try to
> redirect Claude (indirect prompt injection).

There is no privilege separation inside a request. The system prompt is a
distinguished *parameter*, but a sentence in a README that arrives as a
`tool_result` is tokens in the same context as everything else, and the model
has only convention to tell it which text is an instruction. The one structural
mitigation upstream names is to keep untrusted content inside `tool_result`
blocks rather than folding it into the system prompt or a plain user text block,
and that is what sandbx does: tool output and refusals alike go back as
`tool_result`, never as narration.

What that mitigation does *not* do is stop an injected instruction from being
followed, and [`SECURITY.md`](../../SECURITY.md) is the normative statement of
where sandbx stands. Its "Not vulnerabilities" section lists:

> An agent running a tool call the gate approved, including one a prompt
> injection induced — which, unless `--approve call` is passed, means any call
> to a tool approved for the run. What bounds it is the sandbox, not the asking
> — *Approval is not enforcement*.

So the defence is not the loop and not the asking. An injected instruction can
ask for anything, and what it gets is whatever the policy granted — which is why
chapter [01](01-what-sandbx-is.md)'s point about a no-flag `agent-run` deriving
write on the working directory is a security fact rather than a convenience.
Everything from here to the kernel exists because this section has no better
answer than "bound what the call can reach".

## All of it is hand-rolled

No vendor SDK. `reqwest` carries bytes and `rustls` encrypts them; above that,
every line is in this repo — the SSE framing, the event union, the accumulator,
the body serializer, the retry classification, the credential handling. The
case for it is [decision-provider-seam.md](../decision-provider-seam.md); what
follows is what it feels like to work in.

The seam itself is a type, and it is the whole of the abstraction:

```rust
/// The event stream every provider client returns: owned, boxed, and fused.
///
/// Boxed because each backend's stream is a different concrete type. `FusedStream`
/// because the `unfold` under it panics if polled past `None`; `Send` so the turn
/// built on it can be `tokio::spawn`ed.
pub type EventStream = std::pin::Pin<
    Box<dyn futures_util::stream::FusedStream<Item = Result<AgentEvent, ProviderError>> + Send>,
>;
```

Four Rust corners are packed into those three lines, and they are worth
unpacking once. `Box<dyn …>` because two backends' streams are two unrelated
concrete types that need one name. `Pin` because a stream cannot be polled
through a trait object without it — `poll_next` takes `Pin<&mut Self>`, and a
future or stream that may hold a reference into itself has to be promised not to
move. `FusedStream` is the `.fuse()` promise from the SSE section, now part of
the public type: a consumer may poll past the end. And `Send` so the turn built
on the stream can be handed to `tokio::spawn`.

What that buys is the thing to notice: there is **no provider trait.**
`run_turn` is generic over
`AsyncFnMut(Prompt) -> Result<EventStream, ProviderError>`, so a test double is
a closure rather than an implementation of a published trait, and no mock type
appears in anyone's public API. The module doc states the principle: "The seam
is the return type."

What hand-rolling costs:

- **Every wire rule is yours to discover.** The omission rules in `body.rs` are
  each a 400 that somebody hit once; the `adaptive` thinking shape is a
  deprecation somebody tracked. An SDK would have absorbed all of it silently.
- **The vocabulary is doubled.** `RawStreamEvent` beside `AgentEvent`,
  `ContentBlock` beside `BlockBody`. Every wire concept is named twice, once as
  it arrives and once as this repo thinks about it.
- **Upstream change arrives as a 400 or as silence,** not as a version bump with
  release notes — which is what the first `Worth questioning:` above is about.

What it buys:

- **The vendor boundary.** Every vendor *rule* and wire string sits at or below
  [`anthropic.rs`](../../crates/sandbx-providers/src/anthropic.rs), and `Prompt`
  has no `Serialize` at all, so the top-level types cannot be posted to any API
  by accident (#59). The *name* does appear higher up, and it is worth being
  precise about where: `lib.rs` re-exports `AnthropicClient`, `credentials.rs`
  holds `anthropic_api_key` and the variable it reads, and four more files name
  the vendor in doc comments. None of them carries a byte of the protocol, which
  is the half of the boundary the compiler holds.
- **The protocol is testable without a network.** The body is a
  `serde_json::Value` compared against a literal; the accumulator is fed a
  sequence of raw events. Both of those are unit tests on a machine with no
  credential.
- **No SDK's idea of retries, logging, or a client lifecycle.** The two
  retryable error strings are a three-line constant that says where they came
  from, not a policy inherited from a dependency.
- **The code that decides what to send is reviewable in an afternoon.** For a
  project whose claims rest on review rather than on reputation, that is the
  point.

## You should now be able to explain

- Why a harness needs a loop at all, in terms of what a `tool_use` block is and
  what a stateless endpoint does with one.
- Why a denied tool call still produces a `tool_result`, and what happens to a
  conversation containing a `tool_use` with no answer.
- Why a `tool_result` is a user message rather than a role of its own, and where
  the system prompt actually goes.
- What `signature_delta` is for, and why keeping only its last fragment would be
  a 400 on the next request.
- Why a deepened compaction cut has to drop every reasoning block already sent,
  and why it drops `redacted_thinking` with them.
- Why `content_block_stop` being surfaced only for `tool_use` blocks means a
  renderer coalesces adjacent text.
- Why prompt injection is a property of the request's shape rather than a bug in
  a tool, and which document says what bounds it.
- What the `EventStream` type alias buys that a `Provider` trait would not, and
  what each of `Pin`, `dyn`, `FusedStream` and `Send` is doing in it.

## Next

[03 — the landscape](03-the-landscape.md), which puts this same loop beside the
other harnesses that implement it, and compares them on where each one puts its
boundary. After that, the boundary chapters in the order on the
[index](README.md) — they are the answer to the section above that did not have
one.

[messages]: https://platform.claude.com/docs/en/api/messages
[streaming]: https://platform.claude.com/docs/en/build-with-claude/streaming
[thinking]: https://platform.claude.com/docs/en/build-with-claude/preserved-thinking
[extended]: https://platform.claude.com/docs/en/build-with-claude/extended-thinking
[tool-use]: https://platform.claude.com/docs/en/agents-and-tools/tool-use/handle-tool-calls
