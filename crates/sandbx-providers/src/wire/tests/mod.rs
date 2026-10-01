//! Unit tests for the wire layer, grouped by what a turn is doing: token
//! accounting ([`usage`]), tool-call accumulation ([`tool_use`]), the content
//! blocks and the tags that must be tolerated ([`content`]), and how a turn ends
//! ([`lifecycle`]).
//!
//! All of them drive [`event_stream`] end to end over a canned frame sequence
//! rather than reaching for a `Raw*` type, so they pin the behaviour the caller
//! sees and not the deserialization that happens to produce it. They are unit
//! tests only because `event_stream` is `pub(crate)`; `tests/anthropic_client.rs`
//! asks the same questions over a real HTTP round-trip.

mod content;
mod lifecycle;
mod tool_use;
mod usage;

use crate::error::ProviderError;
use crate::event::{AgentEvent, StopReason};
use crate::sse::RawSseEvent;

use super::event_stream;

fn raw(data: &str) -> Result<RawSseEvent, ProviderError> {
    Ok(RawSseEvent {
        event: None,
        data: data.to_string(),
    })
}

async fn events(
    frames: Vec<Result<RawSseEvent, ProviderError>>,
) -> Vec<Result<AgentEvent, ProviderError>> {
    use futures_util::StreamExt;

    event_stream(futures_util::stream::iter(frames))
        .collect()
        .await
}

/// For tests asserting an all-success sequence. `ProviderError` does not
/// derive `PartialEq` (it wraps an opaque `reqwest::Error`, which does
/// not implement it either), so comparing a whole `Vec<Result<..>>`
/// directly is not possible — unwrap first instead of weakening the
/// error type just to make a test convenient.
async fn ok_events(frames: Vec<Result<RawSseEvent, ProviderError>>) -> Vec<AgentEvent> {
    events(frames)
        .await
        .into_iter()
        .map(|event| event.expect("expected every event to parse"))
        .collect()
}

/// The `Stop` every completed turn ends with, for tests whose subject is
/// what comes before it.
fn stop(reason: StopReason) -> AgentEvent {
    AgentEvent::Stop { reason }
}
