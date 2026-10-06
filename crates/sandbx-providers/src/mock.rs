use crate::EventStream;
use crate::error::ProviderError;
use crate::event::AgentEvent;
use crate::request::MessagesRequest;

/// A test double that replays a canned sequence of events instead of calling a real
/// API, interchangeable with a real client through the returned [`EventStream`]
/// alone; see `context/decision-provider-seam.md`.
pub struct MockProvider {
    events: Vec<Result<AgentEvent, ProviderError>>,
}

impl MockProvider {
    /// The common case: an all-success canned turn.
    pub fn new(events: impl IntoIterator<Item = AgentEvent>) -> Self {
        Self::with_results(events.into_iter().map(Ok).collect())
    }

    /// For negative-path tests: inject an error anywhere in the sequence.
    pub fn with_results(events: Vec<Result<AgentEvent, ProviderError>>) -> Self {
        Self { events }
    }

    /// Replays the canned sequence, by value: throwaway per-test data, unlike
    /// [`AnthropicClient::stream_chat`](crate::AnthropicClient::stream_chat).
    pub async fn stream_chat(
        self,
        _request: MessagesRequest,
    ) -> Result<EventStream, ProviderError> {
        use futures_util::StreamExt;

        Ok(Box::pin(futures_util::stream::iter(self.events).fuse()))
    }
}
