use futures_util::StreamExt;
use sandbx_providers::{
    AgentEvent, ContentBlock, EventStream, MessagesRequest, ProviderError, RequestMessage, Role,
    ToolDefinition,
};
use sandbx_tools::{BuiltinTool, ExecutionContext};

use crate::{Compaction, TurnError, compact};

/// What to ask the model for.
///
/// Borrows the history: [`run_turn`] hands back the turns it produced rather than
/// appending to a caller's list.
pub struct Turn<'a> {
    /// The model to ask. A freeform string, as `MessagesRequest` takes it.
    pub model: String,
    /// The cap on the model's reply. This crate has no default opinion.
    pub max_tokens: u32,
    /// The system prompt, omitted from the request entirely when `None`.
    pub system: Option<String>,
    /// The built-ins to offer. An empty slice offers none, not all of them.
    pub tools: &'a [BuiltinTool],
    /// The conversation so far, oldest first.
    pub history: &'a [RequestMessage],
    /// The bounds this turn runs within.
    pub limits: TurnLimits,

    /// What the *previous* turn's request cost, as the provider measured it.
    ///
    /// Carried in rather than rediscovered because a turn's *first round* has to build
    /// its request before any figure for it exists, and that first round is precisely
    /// the one whose history has grown too large. So threading [`TurnOutcome::usage`]
    /// back here — `observed = outcome.usage.or(observed)` — is half of what makes
    /// [`TurnLimits::compaction`] do anything across a conversation. [`withheld`] is the
    /// other half, and neither works alone.
    ///
    /// `None` on a conversation's first turn, where there is genuinely nothing to know.
    /// It bounds only that turn's first round, not the whole turn: a turn given `None`
    /// still compacts from the round after it measures itself over budget, on its own
    /// figure. What `None` rules out is *guessing* on a conversation that may be two
    /// messages long.
    ///
    /// [`withheld`]: Self::withheld
    pub observed: Option<PromptUsage>,

    /// How many of `history`'s oldest messages the *previous* turn left out of its
    /// request. [`TurnOutcome::withheld`], threaded back unchanged.
    ///
    /// A floor, not an instruction: this turn may withhold more, never less. Without it
    /// compaction bounds nothing at all, because [`observed`] measures the request that
    /// was *already compacted* — small, by construction. The turn after a successful
    /// compaction would read comfortably under budget, put the whole history back, and
    /// send more than the turn that triggered. Compaction would fire on every other turn
    /// while the uncompacted leg grew without limit.
    ///
    /// `0` on a conversation's first turn, and whenever the previous turn withheld
    /// nothing. Safe to carry only because a caller *appends* to history: appending does
    /// not move the indices of a prefix, so a count from last turn still names the same
    /// messages. A caller that rewrites history instead invalidates it, which
    /// `compact::plan_cut` absorbs by dropping the floor rather than cutting blind.
    ///
    /// [`observed`]: Self::observed
    pub withheld: usize,
}

/// The prompt-side token counters of the last `AgentEvent::Usage` a turn reported.
///
/// Every field is optional because the API may omit any of them, and `None` means "not
/// reported" — deliberately distinguishable from a reported zero, as
/// `sandbx-providers` documents on the event itself.
///
/// `output_tokens` is absent on purpose. Nothing here reads it: compaction asks how
/// large the *request* was, and `observe` already sees the whole event for anyone who
/// wants the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromptUsage {
    /// Tokens in the request, excluding anything served from cache.
    pub input_tokens: Option<u32>,
    /// Tokens read from the prompt cache.
    pub cache_read_input_tokens: Option<u32>,
    /// Tokens written to the prompt cache.
    pub cache_creation_input_tokens: Option<u32>,
}

impl PromptUsage {
    /// The whole prompt, as the provider counted it.
    ///
    /// All three counters summed: a cache read is a real prompt token charged against
    /// the context window, so counting `input_tokens` alone would under-read a cached
    /// conversation by an order of magnitude — which is the long conversation this
    /// exists to catch.
    ///
    /// `u64` rather than `u32` because three saturated counters overflow a `u32`, and
    /// these figures come off the wire: a broken or hostile response must not be able
    /// to panic a debug build. An unreported counter sums as zero rather than poisoning
    /// the total, because the API omits the cache fields entirely when no cache was
    /// involved — reading that as "unknown" would disable compaction for every
    /// uncached request.
    #[must_use]
    pub fn prompt_tokens(&self) -> u64 {
        u64::from(self.input_tokens.unwrap_or(0))
            + u64::from(self.cache_read_input_tokens.unwrap_or(0))
            + u64::from(self.cache_creation_input_tokens.unwrap_or(0))
    }
}

/// What one turn came to.
///
/// More than the messages because the turn now has two things worth handing back that
/// it used to drop: what the request cost, and whether it had to leave anything out to
/// fit. Both are a caller's to act on — this crate has no route to the audit trail, and
/// no opinion about what a UI should say.
#[derive(Debug)]
pub struct TurnOutcome {
    /// The turns this call produced, oldest first, to be appended to the caller's
    /// history.
    ///
    /// Always complete. Compaction narrows the *request*, never this: a caller whose
    /// stored history lost whatever the model was not shown would compound that loss
    /// every turn.
    pub messages: Vec<RequestMessage>,

    /// What this turn's last round reported, or `None` if no round reported anything.
    ///
    /// Thread it into the next turn's [`Turn::observed`] with
    /// `observed = outcome.usage.or(observed)`. Not pre-merged with what was passed in,
    /// so "this turn reported nothing" stays distinguishable from "this turn reported
    /// what you already knew".
    ///
    /// On its own this figure is *not* enough to keep a conversation bounded: once
    /// compaction has fired it measures the compacted request. [`withheld`] is the other
    /// half, and both have to be threaded back.
    ///
    /// [`withheld`]: Self::withheld
    pub usage: Option<PromptUsage>,

    /// How many of the oldest history messages the last request left out.
    ///
    /// Thread it into the next turn's [`Turn::withheld`] unchanged, where it becomes the
    /// floor the next cut may deepen but not undo. Compaction only bounds a conversation
    /// if it does: see [`Turn::withheld`] for what goes wrong when it does not.
    ///
    /// `0` covers three cases a caller cannot tell apart from this number alone:
    /// compaction was off, it was on and under budget with nothing carried in, or it was
    /// over budget and found nothing it could legally withhold. The last is a real
    /// outcome — see `compact::plan_cut` — and a caller that cares can compare its own
    /// budget against [`usage`].
    ///
    /// [`usage`]: Self::usage
    pub withheld: usize,
}

/// The bounds one turn runs within.
///
/// Both defaults sit at the tighter end of plausible: a bound that is too tight
/// announces itself the first time real work dies, where one that is too loose
/// silently fails to catch the runaway it exists for.
#[derive(Debug, Clone, Copy)]
pub struct TurnLimits {
    /// How many times the model may be asked within one turn.
    ///
    /// A turn re-enters once per batch of tool calls, so this bounds how far a
    /// looping or injected-into model can drive tool execution. Reaching it is a
    /// [`TurnError::RoundLimit`], not a quiet stop.
    pub max_rounds: usize,

    /// How long one round may spend streaming before the turn is abandoned.
    ///
    /// Bounds the *consumption* of one round, which `sandbx-providers` leaves to a
    /// caller: its own read timeout bounds inactivity between chunks and resets on
    /// every one, so a connection that stays warm while producing nothing useful is
    /// not bounded by it.
    ///
    /// Nothing bounds a tool call in wall-clock terms, so a turn has no total time
    /// bound. `ExecutionContext::timeout` applies where the sandbox spawns a process,
    /// so it covers `bash` and none of the six in-process tools; those are bounded by
    /// *work* instead, `ToolLimits` capping the files a search walks and the bytes it
    /// reads. An outer deadline would not help: tools run on `spawn_blocking`, which
    /// cannot be cancelled, so the work continues after the future is dropped (#26).
    pub stream_timeout: std::time::Duration,

    /// Whether to withhold the oldest history from a request that has outgrown a
    /// budget, and how much to keep.
    ///
    /// The one bound here that is **off by default**, and the only one that is lossy.
    /// The others refuse to go on when they are hit, which announces itself; this one
    /// sends the model less than it was given, which does not. And the right value is
    /// not this crate's to guess: [`Turn::model`] is a freeform string with no
    /// context-window table behind it, so a default budget would be a number picked for
    /// an unknown model.
    ///
    /// `None` means a long conversation eventually dies on the provider's own
    /// context-length error, which is where #107 started. A caller that knows its
    /// model's window opts in.
    pub compaction: Option<Compaction>,
}

impl Default for TurnLimits {
    fn default() -> Self {
        Self {
            max_rounds: 8,
            // The pressure point is a long extended-thinking generation.
            stream_timeout: std::time::Duration::from_secs(300),
            // Lossy, and model-specific. See the field.
            compaction: None,
        }
    }
}

/// Run one turn, accumulating its event stream into replayable messages.
///
/// `open` is a closure that opens a stream rather than a provider, so this is
/// generic over the *stream shape* and not over which client produced it: the real
/// call is `run_turn(|request| client.stream_chat(request), ..)`, and a test passes
/// one that replays canned events. `AsyncFnMut` leaves the returned future unnamed,
/// which costs one thing — a *generic* wrapper around `run_turn` cannot add its own
/// `Send` bound to it. `observe` stays a generic for the mirror reason: `dyn FnMut`
/// is not `Send`, so taking one would make this future unspawnable.
///
/// `open` is a closure that opens a stream, rather than a provider. The real call
/// is `run_turn(|request| client.stream_chat(request), ..)`; a test passes one
/// that replays canned events. That keeps this generic over the *stream shape*
/// rather than over which client produced it, and means no trait, no `dyn` and
/// no test double in anyone's public API.
///
/// `AsyncFnMut` rather than a separate `Fut` parameter, so the future it returns
/// stays unnamed. The one thing that costs: a *generic* wrapper around `run_turn`
/// could not add its own `Send` bound to that future, since there is no stable way
/// to name it. Concrete callers are unaffected — the test suite's
/// `the_documented_call_shape_compiles_and_stays_spawnable` pins that the returned
/// future is still `Send` and so still spawnable.
///
/// `observe` stays a generic rather than `&mut dyn FnMut(..)` for the same reason
/// in reverse: `dyn FnMut` is not `Send`, so taking one would make this whole future
/// non-`Send` and unspawnable.
///
/// # What `observe` is for
///
/// Every event is handed to `observe` before being accumulated, in arrival order.
/// A renderer needs the increments as they land; the return value is the replayable
/// form. Both come out of one pass so neither caller has to rebuild the other's.
///
/// # What is dropped, and what is kept
///
/// `AgentEvent::Thinking` reaches `observe` but never the returned messages.
/// `ContentBlock` has no thinking variant, and the signature needed to replay a
/// thinking block is discarded upstream, so there is nowhere for it to go (#85).
///
/// `AgentEvent::Usage` is accounting rather than content, so it does not enter the
/// rebuilt history either — but it is no longer thrown away. The latest counts come
/// back on [`TurnOutcome::usage`], which is what a caller threads into the next turn's
/// [`Turn::observed`] to make compaction possible at all.
///
/// # Compaction
///
/// Off unless [`TurnLimits::compaction`] says otherwise. When the last *measured*
/// prompt was over budget, the oldest history is left out of the request — not
/// out of [`TurnOutcome::messages`], which is always the whole turn.
///
/// It needs **two** things threaded back, not one: `observed = outcome.usage.or(observed)`
/// *and* `withheld = outcome.withheld`. Usage alone does not bound anything, because
/// after a compaction it measures the compacted request — see [`Turn::withheld`] for the
/// oscillation that results.
///
/// Three properties that are easier to state here than to infer. **The cut only ever
/// deepens.** Within a turn it goes `None` to `Some` at most once and is then fixed —
/// never `Some` to a different `Some`, however the measurement moves after that. Across
/// turns the previous cut is the floor for the next. So the model is never re-shown
/// history it had lost, and the request's cached prefix is never rebuilt backwards.
///
/// The one `None`-to-`Some` move does narrow that prefix mid-turn, on the round after a
/// turn first measures itself over budget. That is the only in-turn bound there is:
/// `produced` grows the request as the turn goes round, and the alternative is a turn
/// that watches itself blow through the budget and keeps sending the whole history for
/// every remaining round.
///
/// The cut can never reach the messages *this* turn produced, because
/// `compact::plan_cut` is handed their count rather than the messages — so a turn cannot
/// withhold from itself the tool result it is waiting on. And it is a view: nothing here
/// mutates
/// [`Turn::history`] or narrows [`TurnOutcome::messages`].
///
/// Where it cannot help: it sheds whole exchanges, because those are the only legal cut
/// points, so a single enormous exchange is not compactable and the request goes out
/// oversized. The provider's own context-length error stays the backstop.
///
/// # The blocking boundary
///
/// `BuiltinTool::execute` is synchronous and may sit in a `write`, a directory walk
/// or a 90-second command, which on a current-thread runtime would freeze every
/// other task. So every call goes through `spawn_blocking`, and this is the only
/// place that has to know it.
///
/// `spawn_blocking` cannot be cancelled. Dropping this future drops the
/// `JoinHandle` while the blocking task runs to completion, so a turn abandoned
/// mid-tool still applies the `write` after the caller stopped waiting; the
/// transcript goes with the dropped future, and the audit trail is where that side
/// effect is still recorded (#26).
///
/// Needs a tokio runtime with the time driver enabled. The per-round bound is
/// `tokio::time::timeout`, which panics with "there is no timer running" otherwise,
/// on the first round. `#[tokio::main]` and `Builder::new_*().enable_all()` enable
/// it; `Builder::new_current_thread().enable_io().build()` does not. The flavour is
/// still the binary's call: `spawn_blocking` needs only `rt`.
///
/// The turn re-enters on the *presence* of tool calls, never on `StopReason::ToolUse`:
/// a stop reason is nullable on the wire, so a round can arrive with tool calls and
/// `StopReason::Unspecified`, and keying off the reason would drop them silently.
///
/// A tool that fails does not end the turn — it comes back as a `tool_result` marked
/// `is_error`, so the model can ask for something else. See [`TurnError`] for where
/// the line is drawn.
pub async fn run_turn<F, O>(
    mut open: F,
    turn: Turn<'_>,
    ctx: &ExecutionContext,
    mut observe: O,
) -> Result<TurnOutcome, TurnError>
where
    F: AsyncFnMut(MessagesRequest) -> Result<EventStream, ProviderError>,
    O: FnMut(&AgentEvent),
{
    // Built once: the offered set does not change between rounds.
    let definitions: Vec<ToolDefinition> = turn.tools.iter().copied().map(definition).collect();
    let mut produced: Vec<RequestMessage> = Vec::new();

    // The freshest measurement of what a request costs: the caller's, until this turn
    // makes one of its own.
    let mut observed = turn.observed;
    // This turn's own latest, which is what comes back. Deliberately not seeded from
    // `observed`: a caller has to be able to tell "reported nothing" from "reported what
    // you already knew".
    let mut usage: Option<PromptUsage> = None;
    // The `cut.is_none()` guard below is what makes this monotone: the state sequence is
    // some number of `None`s followed by one fixed `Some`. A plan that comes back `None`
    // is not a decision, so the next round asks again — which is how a turn with nothing
    // threaded in still reacts to its own first measurement. Once a cut lands it is
    // final for the turn.
    let mut cut: Option<usize> = None;

    for _ in 0..turn.limits.max_rounds {
        if cut.is_none()
            && let Some(policy) = turn.limits.compaction
        {
            // Over budget asks to deepen; within budget asks only to hold what the
            // previous turn withheld. `None` is not "do not compact" — a conversation
            // that has already been cut stays cut, or the cut it paid for is undone and
            // nothing is bounded.
            let keep_recent =
                compact::over_budget(observed, policy.budget_tokens).then_some(policy.keep_recent);
            cut = compact::plan_cut(turn.history, produced.len(), keep_recent, turn.withheld);
        }
        let withheld = cut.unwrap_or(0);

        let mut messages = turn.history[withheld..].to_vec();
        messages.extend_from_slice(&produced);

        let request = MessagesRequest {
            model: turn.model.clone(),
            max_tokens: turn.max_tokens,
            system: turn.system.clone(),
            messages,
            tools: definitions.clone(),
        };

        let mut stream = open(request).await.map_err(TurnError::Provider)?;

        // Only the consumption is wrapped. Opening the stream is the provider's own
        // request, already bounded by its connect and read timeouts.
        let round = tokio::time::timeout(
            turn.limits.stream_timeout,
            accumulate(&mut stream, &mut observe),
        )
        .await
        .map_err(|_| TurnError::TimedOut {
            after: turn.limits.stream_timeout,
        })??;

        // Recorded before any exit below, because a round's counts are worth reporting
        // even when that round is the one that ends the turn.
        if let Some(reported) = round.usage {
            usage = Some(reported);
            observed = Some(reported);
        }
        let blocks = round.blocks;

        // An empty content array is rejected by the API, so a round that produced
        // nothing appends nothing — a message with no blocks would invalidate every
        // later request in the conversation.
        if blocks.is_empty() {
            // Unless a `tool_result` is already waiting to be answered. Handing that
            // back as a finished turn breaks the request *after* this one, not this
            // one: a caller appends its own user message to what it is given, and the
            // API rejects two consecutive user turns. Discarded for the same reason
            // the `RoundLimit` path below discards.
            //
            // Compaction cannot reach `produced`, so this check reads the same with it
            // on or off. The coupling runs the other way: withholding history can be
            // what confuses a model into an empty round, and this is where that lands.
            if matches!(produced.last(), Some(last) if matches!(last.role, Role::User)) {
                return Err(TurnError::EndedMidToolUse);
            }

            return Ok(TurnOutcome {
                messages: produced,
                usage,
                withheld,
            });
        }

        // Answered before the assistant turn is pushed, because answering borrows
        // the blocks and pushing moves them.
        let results = answer_calls(&blocks, ctx).await?;

        produced.push(RequestMessage {
            role: Role::Assistant,
            content: blocks,
        });

        if results.is_empty() {
            return Ok(TurnOutcome {
                messages: produced,
                usage,
                withheld,
            });
        }

        produced.push(RequestMessage {
            role: Role::User,
            content: results,
        });
    }

    // Still wanting tools run. `produced` is dropped rather than returned: it ends in
    // a tool_result the model never answered, which would read as a finished turn.
    Err(TurnError::RoundLimit {
        rounds: turn.limits.max_rounds,
    })
}

/// Run every tool call in `blocks`, in the order the model asked for them, and
/// answer each one.
///
/// Sequential: concurrency would need the ordering semantics of two tools sharing
/// one `ExecutionContext` settled first (#26).
async fn answer_calls(
    blocks: &[ContentBlock],
    ctx: &ExecutionContext,
) -> Result<Vec<ContentBlock>, TurnError> {
    let mut results = Vec::new();

    for block in blocks {
        let ContentBlock::ToolUse { id, name, input } = block else {
            continue;
        };

        let Some(tool) = BuiltinTool::from_name(name) else {
            // Lookup is exact by design, so a miss is a prompt or schema bug rather
            // than a near-miss to normalise away. Nothing runs, and the model is told
            // which name failed so it can correct itself.
            results.push(refused(id, format!("unknown tool: {name}")));
            continue;
        };

        // Cloned because `spawn_blocking` needs `'static`, once per call because the
        // closure consumes it. Copying a few path lists is a fraction of the thread
        // handoff below; an `Arc` would pay off only if `ExecutionContext` grew
        // something costly to copy.
        let input = input.clone();
        let context = ctx.clone();
        let outcome = tokio::task::spawn_blocking(move || tool.execute(input, &context))
            .await
            .map_err(|_| TurnError::ToolPanicked {
                name: name.to_string(),
            })?;

        results.push(match outcome {
            Ok(output) => ContentBlock::ToolResult {
                tool_use_id: id.clone(),
                content: output.into_content(),
                is_error: None,
            },
            Err(error) => refused(id, error.to_string()),
        });
    }

    Ok(results)
}

/// A tool result the model should read as a failure.
fn refused(id: &str, content: String) -> ContentBlock {
    ContentBlock::ToolResult {
        tool_use_id: id.to_string(),
        content,
        is_error: Some(true),
    }
}

/// What one round of streaming came to.
struct Round {
    /// The content blocks the stream described.
    blocks: Vec<ContentBlock>,
    /// What it reported the request cost, if it reported anything.
    usage: Option<PromptUsage>,
}

/// Drain one stream into the content blocks it describes, keeping its token counts.
///
/// The counts are taken last-one-wins rather than summed: Anthropic restates them
/// cumulatively on every `message_delta`, so adding them up would multiply the figure.
/// `sandbx-providers` has already folded that down to at most one `Usage` event per
/// stream, so in practice there is one to take.
///
/// **Depends on `Usage` arriving before `Stop`**, since the `Stop` arm returns and
/// anything behind it is never seen. `sandbx-providers` guarantees the order — it
/// queues the usage event before the stop event at every exit — and its own
/// `wire/tests/usage.rs` pins it. Worth saying out loud because the failure is silent:
/// the counts would simply always be `None`, and compaction would never fire.
async fn accumulate<O>(stream: &mut EventStream, observe: &mut O) -> Result<Round, TurnError>
where
    O: FnMut(&AgentEvent),
{
    let mut blocks = Vec::new();
    let mut text = String::new();
    let mut usage = None;

    while let Some(event) = stream.next().await {
        let event = event.map_err(TurnError::Provider)?;
        observe(&event);

        match event {
            AgentEvent::Text { delta } => text.push_str(&delta),
            AgentEvent::ToolCallRequested { id, name, input } => {
                // Before the tool block, not after: the API reads a content array
                // in order, and the text that introduced a call precedes it.
                flush(&mut text, &mut blocks);
                blocks.push(ContentBlock::ToolUse { id, name, input });
            }
            AgentEvent::Usage {
                input_tokens,
                cache_read_input_tokens,
                cache_creation_input_tokens,
                // The reply, not the request. Compaction asks how large the request
                // was, and `observe` saw the whole event above.
                output_tokens: _,
            } => {
                usage = Some(PromptUsage {
                    input_tokens,
                    cache_read_input_tokens,
                    cache_creation_input_tokens,
                });
            }
            AgentEvent::Stop { .. } => {
                flush(&mut text, &mut blocks);
                return Ok(Round { blocks, usage });
            }
            // Observed above, carried no further — see `run_turn`'s docs.
            AgentEvent::Thinking { .. } => {}
        }
    }

    Err(TurnError::StreamEndedWithoutStop)
}

/// Move buffered text into a block of its own, if there is any to move.
fn flush(text: &mut String, blocks: &mut Vec<ContentBlock>) {
    if !text.is_empty() {
        blocks.push(ContentBlock::Text {
            text: std::mem::take(text),
        });
    }
}

/// Bridge a built-in into the shape a provider request wants.
///
/// Three field copies and no table of its own: `name`, `description` and
/// `input_schema` are one `SPEC` per tool in `sandbx-tools`, beside the behaviour
/// they describe, so nothing here can restate them or read them out of step.
fn definition(tool: BuiltinTool) -> ToolDefinition {
    ToolDefinition {
        name: tool.name().to_string(),
        description: tool.description().to_string(),
        input_schema: tool.input_schema(),
    }
}
