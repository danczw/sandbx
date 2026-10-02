use futures_util::StreamExt;
use sandbx_providers::{
    AgentEvent, ContentBlock, EventStream, MessagesRequest, ProviderError, RequestMessage, Role,
    ToolDefinition,
};
use sandbx_tools::{BuiltinTool, ExecutionContext};

use crate::{Compaction, TurnError, compact};

/// What to ask the model for.
///
/// Borrows the history rather than taking it, because [`run_turn`] hands back the
/// turns it produced instead of appending to a caller's list — see its docs.
pub struct Turn<'a> {
    /// The model to ask. A freeform string, as `MessagesRequest` takes it.
    pub model: String,
    /// The cap on the model's reply. This crate has no default opinion either.
    pub max_tokens: u32,
    /// The system prompt, omitted from the request entirely when `None`.
    pub system: Option<String>,
    /// The built-ins to offer. An empty slice offers none, which is not the same
    /// as offering all of them.
    pub tools: &'a [BuiltinTool],
    /// The conversation so far, oldest first.
    pub history: &'a [RequestMessage],
    /// The bounds this turn runs within.
    pub limits: TurnLimits,

    /// What the *previous* turn's request cost, as the provider measured it.
    ///
    /// Carried in rather than rediscovered because compaction has nothing else to go
    /// on: the first round of a turn has to build its request before any figure for it
    /// exists, and that first round is precisely the one whose history has grown too
    /// large. A turn given `None` cannot compact at all, so threading
    /// [`TurnOutcome::usage`] back here — `observed = outcome.usage.or(observed)` — is
    /// what makes [`TurnLimits::compaction`] do anything across a conversation.
    ///
    /// `None` on a conversation's first turn, where there is genuinely nothing to know.
    pub observed: Option<PromptUsage>,
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
    pub usage: Option<PromptUsage>,

    /// How many of the oldest history messages the last request left out.
    ///
    /// `0` covers three cases a caller cannot tell apart from this number alone:
    /// compaction was off, it was on and under budget, or it was over budget and found
    /// nothing it could legally withhold. The last is a real outcome — see
    /// `compact::plan_cut` — and a caller that cares can compare its own budget against
    /// [`usage`].
    ///
    /// [`usage`]: Self::usage
    pub withheld: usize,
}

/// The bounds one turn runs within.
///
/// Every field is at the tighter end of what is plausible. There is no agent caller
/// to measure against yet, and a bound that is too tight announces itself the first
/// time real work dies, where one that is too loose silently fails to catch the
/// runaway it exists for — the same reasoning `sandbx-tools`' own `DEFAULT_TIMEOUT`
/// is set by. Raise them when that actually bites.
#[derive(Debug, Clone, Copy)]
pub struct TurnLimits {
    /// How many times the model may be asked within one turn.
    ///
    /// A turn re-enters once per batch of tool calls, so this bounds how far a
    /// looping or injected-into model can drive tool execution. Reaching it is a
    /// [`TurnError::RoundLimit`], not a quiet stop, because a turn cut off here did
    /// not finish and a caller should not read it as if it had.
    pub max_rounds: usize,

    /// How long one round may spend streaming before the turn is abandoned.
    ///
    /// Bounds the *consumption* of one round, which is the bound
    /// `sandbx-providers` explicitly leaves to a caller: its own read timeout
    /// bounds inactivity between chunks and resets on every one, so a connection
    /// that stays warm while producing nothing useful is not bounded by it.
    ///
    /// This does not bound a tool call, and nothing bounds one in wall-clock
    /// terms. `ExecutionContext::timeout` is applied where the sandbox spawns a
    /// process, so it covers `bash` and none of the six in-process tools; those
    /// are bounded by *work* instead — `ToolLimits` caps the files a search
    /// walks and the bytes it reads, so a broad `grep` terminates, but a single
    /// read on a stalled filesystem still does not.
    ///
    /// So a turn has no total time bound to state. An outer deadline would
    /// bound when a caller stops waiting, not when the tool stops working:
    /// tools run on `spawn_blocking`, which cannot be cancelled, so the work
    /// continues after the future is dropped. Cancellation is #26.
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
/// # The seam
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
/// Two properties that are easier to state here than to infer. The cut is decided **at
/// most once per turn and then frozen**: re-deciding each round would let it move as
/// the measurement crossed the budget, rewriting the request's cached prefix every
/// round and showing the model history it had already lost. And the cut can never reach
/// the messages *this* turn produced — `compact::plan_cut` is handed their count rather
/// than the messages, so a turn cannot withhold from itself the tool result it is
/// waiting on.
///
/// Where it cannot help: it sheds whole exchanges, because those are the only legal cut
/// points, so a single enormous exchange is not compactable and the request goes out
/// oversized. The provider's own context-length error stays the backstop.
///
/// # The blocking boundary
///
/// `BuiltinTool::execute` is synchronous and may sit in a `write`, a directory walk
/// or a 90-second command. Calling it straight from here would block the runtime's
/// thread, and on a current-thread runtime that freezes every other task on it —
/// a TUI's input handling included. So every call goes through `spawn_blocking`,
/// and this is the only place that has to know it.
///
/// What that costs: `spawn_blocking` cannot be cancelled. Dropping this future
/// drops the `JoinHandle` while the blocking task runs to completion, so a turn
/// abandoned mid-tool — a TUI cancel, a losing `select!` branch, an outer
/// deadline — still applies the `write`, or lets the `bash` command run out its
/// timeout, after the caller has stopped waiting. The transcript that would have
/// named the call goes with the dropped future; the audit trail is where that
/// side effect is still recorded. Cancellation is #26.
///
/// # What the runtime must provide
///
/// A tokio runtime with the **time driver enabled**. The per-round bound is
/// `tokio::time::timeout`, which panics with "there is no timer running" when the
/// runtime has no timer — on the first round, before any work is done.
/// `#[tokio::main]` and `Builder::new_*().enable_all()` enable it;
/// `Builder::new_current_thread().enable_io().build()` does not. The *flavour* is
/// still the binary's call, as `Cargo.toml` says: `spawn_blocking` needs only
/// `rt`, never `rt-multi-thread`.
///
/// # When the turn re-enters
///
/// On the *presence* of tool calls, never on `StopReason::ToolUse`. A stop reason is
/// nullable on the wire, so a round can arrive with tool calls and
/// `StopReason::Unspecified`; keying off the reason would drop them silently.
///
/// A tool that fails does not end the turn. It comes back as a `tool_result` marked
/// `is_error`, which is what lets the model ask for something else — see
/// [`TurnError`] for where the line is drawn.
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
    // Decided at most once, then frozen — see the docs above. The state sequence is some
    // number of `None`s followed by one fixed `Some`, so there is no path on which the
    // cut moves.
    let mut cut: Option<usize> = None;

    for _ in 0..turn.limits.max_rounds {
        if cut.is_none()
            && let Some(policy) = turn.limits.compaction
            && compact::over_budget(observed, policy.budget_tokens)
        {
            cut = compact::plan_cut(turn.history, produced.len(), policy.keep_recent);
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

    // Fallen out of the loop still wanting tools run. `produced` is dropped rather
    // than returned: the last thing in it is a tool_result the model never got to
    // answer, and handing a caller a turn that ends there would read as finished.
    Err(TurnError::RoundLimit {
        rounds: turn.limits.max_rounds,
    })
}

/// Run every tool call in `blocks`, in the order the model asked for them, and
/// answer each one.
///
/// Sequential: concurrency here would need the ordering semantics of two tools
/// sharing one `ExecutionContext` settled first, which is #26's half of the
/// question, not this one's.
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
            // than a near-miss to normalise away. Nothing runs, and the model is
            // told which name failed so it can correct itself.
            results.push(refused(id, format!("unknown tool: {name}")));
            continue;
        };

        // Cloned into the closure because `spawn_blocking` needs `'static`, and one
        // clone per call because the closure consumes it. An `Arc` would avoid the
        // copies without changing the signature — it is simply not worth it: copying
        // a few path lists is a fraction of the thread handoff on the next line.
        // Revisit if `ExecutionContext` ever holds something costly to copy.
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
/// they describe. So nothing here restates them — the seven-arm match #54
/// predicted this crate would grow — and nothing here can read them out of step
/// with each other either (#88).
fn definition(tool: BuiltinTool) -> ToolDefinition {
    ToolDefinition {
        name: tool.name().to_string(),
        description: tool.description().to_string(),
        input_schema: tool.input_schema(),
    }
}
