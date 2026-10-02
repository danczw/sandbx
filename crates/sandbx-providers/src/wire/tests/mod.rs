//! Unit tests for the wire layer, grouped by what a turn is doing: [`usage`],
//! [`tool_use`], [`content`], [`lifecycle`].
//!
//! All of them drive [`event_stream`] over a canned frame sequence rather than
//! reaching for a `Raw*` type, so they pin the behaviour the caller sees. Unit tests
//! only because `event_stream` is `pub(crate)`.

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

/// For tests asserting an all-success sequence: `ProviderError` cannot derive
/// `PartialEq` (it wraps an opaque `reqwest::Error`), so a whole `Vec<Result<..>>`
/// is not comparable and the events are unwrapped first.
async fn ok_events(frames: Vec<Result<RawSseEvent, ProviderError>>) -> Vec<AgentEvent> {
    events(frames)
        .await
        .into_iter()
        .map(|event| event.expect("expected every event to parse"))
        .collect()
}

/// The `Stop` every completed turn ends with.
fn stop(reason: StopReason) -> AgentEvent {
    AgentEvent::Stop { reason }
}
