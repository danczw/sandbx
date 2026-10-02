use futures_util::StreamExt;
use sandbx_providers::{
    AgentEvent, ContentBlock, EventStream, MessagesRequest, ProviderError, RequestMessage, Role,
    ToolDefinition,
};
use sandbx_tools::{BuiltinTool, ExecutionContext};

use crate::TurnError;

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
}

impl Default for TurnLimits {
    fn default() -> Self {
        Self {
            max_rounds: 8,
            // The pressure point is a long extended-thinking generation.
            stream_timeout: std::time::Duration::from_secs(300),
        }
    }
}

/// Run one turn, accumulating its event stream into replayable messages.
///
/// # The seam
///
/// `open` is a closure that opens a stream, rather than a provider. The real call
/// is `run_turn(|request| provider.stream_chat(request), ..)`; a test passes one
/// that replays canned events. That keeps this generic over the *stream shape*
/// rather than over which provider produced it, and means no trait, no `dyn` and
/// no test double in anyone's public API.
///
/// `AsyncFnMut` rather than a separate `Fut` parameter, so the future it returns
/// stays unnamed. The one thing that costs: a *generic* wrapper around `run_turn`
/// could not add its own `Send` bound to that future, since there is no stable way
/// to name it. Concrete callers are unaffected — `turn_is_send` in the test suite
/// pins that the returned future is still `Send` and so still spawnable.
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
/// # What is dropped
///
/// `AgentEvent::Thinking` reaches `observe` but never the returned messages.
/// `ContentBlock` has no thinking variant, and the signature needed to replay a
/// thinking block is discarded upstream, so there is nowhere for it to go.
/// `AgentEvent::Usage` is accounting rather than content, and is likewise observed
/// only.
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
) -> Result<Vec<RequestMessage>, TurnError>
where
    F: AsyncFnMut(MessagesRequest) -> Result<EventStream, ProviderError>,
    O: FnMut(&AgentEvent),
{
    // Built once: the offered set does not change between rounds.
    let definitions: Vec<ToolDefinition> = turn.tools.iter().copied().map(definition).collect();
    let mut produced: Vec<RequestMessage> = Vec::new();

    for _ in 0..turn.limits.max_rounds {
        let mut messages = turn.history.to_vec();
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
        let blocks = tokio::time::timeout(
            turn.limits.stream_timeout,
            accumulate(&mut stream, &mut observe),
        )
        .await
        .map_err(|_| TurnError::TimedOut {
            after: turn.limits.stream_timeout,
        })??;

        // An empty content array is rejected by the API, so a round that produced
        // nothing appends nothing — a message with no blocks would invalidate every
        // later request in the conversation.
        if blocks.is_empty() {
            // Unless a `tool_result` is already waiting to be answered. Handing that
            // back as a finished turn breaks the request *after* this one, not this
            // one: a caller appends its own user message to what it is given, and the
            // API rejects two consecutive user turns. Discarded for the same reason
            // the `RoundLimit` path below discards.
            if matches!(produced.last(), Some(last) if matches!(last.role, Role::User)) {
                return Err(TurnError::EndedMidToolUse);
            }

            return Ok(produced);
        }

        // Answered before the assistant turn is pushed, because answering borrows
        // the blocks and pushing moves them.
        let results = answer_calls(&blocks, ctx).await?;

        produced.push(RequestMessage {
            role: Role::Assistant,
            content: blocks,
        });

        if results.is_empty() {
            return Ok(produced);
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

/// Drain one stream into the content blocks it describes.
async fn accumulate<O>(
    stream: &mut EventStream,
    observe: &mut O,
) -> Result<Vec<ContentBlock>, TurnError>
where
    O: FnMut(&AgentEvent),
{
    let mut blocks = Vec::new();
    let mut text = String::new();

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
            AgentEvent::Stop { .. } => {
                flush(&mut text, &mut blocks);
                return Ok(blocks);
            }
            // Observed above, carried no further — see `run_turn`'s docs.
            AgentEvent::Thinking { .. } | AgentEvent::Usage { .. } => {}
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
/// Three field copies, not the seven-arm match #54 predicted this crate would
/// grow: `name`, `description` and `input_schema` all live in `sandbx-tools`,
/// beside the behaviour they describe, so nothing here restates them.
fn definition(tool: BuiltinTool) -> ToolDefinition {
    ToolDefinition {
        name: tool.name().to_string(),
        description: tool.description().to_string(),
        input_schema: tool.input_schema(),
    }
}
