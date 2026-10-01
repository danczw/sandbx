use std::future::Future;

use futures_util::StreamExt;
use sandbx_providers::{
    AgentEvent, ContentBlock, EventStream, MessagesRequest, ProviderError, RequestMessage, Role,
    ToolDefinition,
};
use sandbx_tools::BuiltinTool;

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
}

/// Run one turn, accumulating its event stream into replayable messages.
///
/// # What this owns
///
/// `AgentEvent::Text` carries an increment, never the accumulated total, and
/// nothing in `sandbx-providers` concatenates it. Doing that here is the point:
/// otherwise the agent loop, a TUI and an eval harness each rebuild it.
///
/// # The seam
///
/// `open` is a closure that opens a stream, rather than a provider. The real call
/// is `run_turn(|request| provider.stream_chat(request), ..)`; a test passes one
/// that replays canned events. That keeps this generic over the *stream shape*
/// rather than over which provider produced it, and means no trait, no `dyn` and
/// no test double in anyone's public API.
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
pub async fn run_turn<F, Fut, O>(
    mut open: F,
    turn: Turn<'_>,
    mut observe: O,
) -> Result<Vec<RequestMessage>, TurnError>
where
    F: FnMut(MessagesRequest) -> Fut,
    Fut: Future<Output = Result<EventStream, ProviderError>>,
    O: FnMut(&AgentEvent),
{
    let request = MessagesRequest {
        model: turn.model.clone(),
        max_tokens: turn.max_tokens,
        system: turn.system.clone(),
        messages: turn.history.to_vec(),
        tools: turn.tools.iter().copied().map(definition).collect(),
    };

    let mut stream = open(request).await.map_err(TurnError::Provider)?;
    let blocks = accumulate(&mut stream, &mut observe).await?;

    // An empty content array is rejected by the API, so a round that produced
    // nothing appends nothing. Returning an empty `Vec` rather than a message with
    // no blocks keeps a later request in the same conversation valid.
    if blocks.is_empty() {
        return Ok(Vec::new());
    }

    Ok(vec![RequestMessage {
        role: Role::Assistant,
        content: blocks,
    }])
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
