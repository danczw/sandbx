//! Frame builders and event shorthands shared by the wire tests.

use sandbx_event::{AgentEvent, StopReason};

use crate::error::ProviderError;

use super::super::event_stream;

pub(super) fn raw(data: &str) -> Result<String, ProviderError> {
    Ok(data.to_string())
}

pub(super) async fn events(
    frames: Vec<Result<String, ProviderError>>,
) -> Vec<Result<AgentEvent, ProviderError>> {
    use futures_util::StreamExt;

    event_stream(futures_util::stream::iter(frames))
        .collect()
        .await
}

/// `ProviderError` cannot derive `PartialEq` — it wraps an opaque `reqwest::Error` —
/// so a `Vec<Result<..>>` is not comparable and an all-success run unwraps first.
pub(super) async fn ok_events(frames: Vec<Result<String, ProviderError>>) -> Vec<AgentEvent> {
    events(frames)
        .await
        .into_iter()
        .map(|event| event.expect("expected every event to parse"))
        .collect()
}

pub(super) fn stop(reason: StopReason) -> AgentEvent {
    AgentEvent::Stop { reason }
}
