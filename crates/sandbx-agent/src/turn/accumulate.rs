//! Rebuilding one round's assistant message from the deltas it arrives as.
//!
//! Content comes off the wire as increments, so the blocks here are assembled rather than
//! received.

use futures_util::StreamExt;
use sandbx_providers::{AgentEvent, ContentBlock, EventStream, StopReason};

use super::PromptUsage;
use crate::TurnError;

/// What one round of streaming came to.
pub(super) struct Round {
    pub(super) blocks: Vec<ContentBlock>,
    pub(super) usage: Option<PromptUsage>,
    pub(super) reason: StopReason,
}

/// Drain one stream into the content blocks it describes, keeping its token counts.
///
/// The counts are last-one-wins rather than summed: Anthropic restates them cumulatively on
/// every `message_delta`, so adding them up would multiply the figure. Depends on `Usage`
/// arriving before `Stop`, since the `Stop` arm returns and anything behind it is never
/// seen. `sandbx-providers`' `wire/tests/usage.rs` pins that order; the failure would be
/// silent, the counts always `None` and compaction never firing.
pub(super) async fn accumulate<O>(
    stream: &mut EventStream,
    observe: &mut O,
) -> Result<Round, TurnError>
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
                // Before the tool block: the API reads a content array in order, and the
                // text introducing a call precedes it.
                flush(&mut text, &mut blocks);
                blocks.push(ContentBlock::ToolUse { id, name, input });
            }
            // Each flushed before its own block, for `ToolCallRequested`'s reason.
            AgentEvent::ThinkingBlock {
                text: reasoning,
                signature,
            } => {
                flush(&mut text, &mut blocks);
                blocks.push(ContentBlock::Thinking {
                    text: reasoning,
                    signature,
                });
            }
            AgentEvent::RedactedThinking { data } => {
                flush(&mut text, &mut blocks);
                blocks.push(ContentBlock::RedactedThinking { data });
            }
            AgentEvent::Usage {
                input_tokens,
                cache_read_tokens,
                cache_write_tokens,
                // The reply, not the request; `observe` saw the whole event above.
                output_tokens: _,
            } => {
                usage = Some(PromptUsage {
                    input_tokens,
                    cache_read_tokens,
                    cache_write_tokens,
                });
            }
            AgentEvent::Stop { reason } => {
                flush(&mut text, &mut blocks);
                return Ok(Round {
                    blocks,
                    usage,
                    reason,
                });
            }
            // A renderer's increment; the block it belongs to arrives whole as
            // `ThinkingBlock`, which is what can be replayed.
            AgentEvent::Thinking { .. } => {}
        }
    }

    Err(TurnError::StreamEndedWithoutStop)
}

fn flush(text: &mut String, blocks: &mut Vec<ContentBlock>) {
    if !text.is_empty() {
        blocks.push(ContentBlock::Text {
            text: std::mem::take(text),
        });
    }
}
