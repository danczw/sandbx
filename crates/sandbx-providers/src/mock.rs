use futures_util::Stream;

use crate::error::ProviderError;
use crate::event::AgentEvent;
use crate::request::MessagesRequest;

/// A test double that replays a canned sequence of events instead of calling
/// a real API.
///
/// Deliberately not a `Provider` variant: that would permanently ship a variant
/// which must never run in production. A caller that wants "produces this stream
/// shape" interchangeably with a real provider should be generic over the stream
/// itself (`impl Stream<Item = Result<AgentEvent, ProviderError>>`), not over
/// `Provider`/`MockProvider` identity.
pub struct MockProvider {
    events: Vec<Result<AgentEvent, ProviderError>>,
}

impl MockProvider {
    /// The common case: an all-success canned turn.
    pub fn new(events: impl IntoIterator<Item = AgentEvent>) -> Self {
        Self {
            events: events.into_iter().map(Ok).collect(),
        }
    }

    /// For negative-path tests: inject an error anywhere in the sequence.
    pub fn with_results(events: Vec<Result<AgentEvent, ProviderError>>) -> Self {
        Self { events }
    }

    /// Consumes `self` — a `MockProvider` is throwaway per-test canned data,
    /// unlike `Provider::stream_chat(&self, ..)`, which is reused across many
    /// real turns from one long-lived client.
    pub async fn stream_chat(
        self,
        _request: MessagesRequest,
    ) -> Result<impl Stream<Item = Result<AgentEvent, ProviderError>>, ProviderError> {
        Ok(futures_util::stream::iter(self.events))
    }
}
