//! Unit tests for the wire layer, grouped by what a turn is doing: [`usage`],
//! [`tool_use`], [`content`], [`lifecycle`].
//!
//! All drive [`event_stream`] over a canned frame sequence rather than a `Raw*` type,
//! so they pin what the caller sees; unit tests because it is `pub(crate)`.

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

/// `ProviderError` cannot derive `PartialEq` — it wraps an opaque `reqwest::Error` —
/// so a `Vec<Result<..>>` is not comparable and an all-success run unwraps first.
async fn ok_events(frames: Vec<Result<RawSseEvent, ProviderError>>) -> Vec<AgentEvent> {
    events(frames)
        .await
        .into_iter()
        .map(|event| event.expect("expected every event to parse"))
        .collect()
}

fn stop(reason: StopReason) -> AgentEvent {
    AgentEvent::Stop { reason }
}
