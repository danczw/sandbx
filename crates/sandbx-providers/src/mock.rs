use crate::EventStream;
use crate::error::ProviderError;
use crate::event::AgentEvent;
use crate::request::MessagesRequest;

/// A test double that replays a canned sequence of events instead of calling
/// a real API.
///
/// Interchangeable with a real client through the return type alone: `stream_chat`
/// hands back the same [`EventStream`] an
/// [`AnthropicClient`](crate::AnthropicClient) does. Not a variant of a shared enum
/// over the backends, which would be part of the shipped surface permanently where
/// the `mock` feature can hide a whole module.
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

    /// Replays the canned sequence, consuming `self` — throwaway per-test data,
    /// unlike [`AnthropicClient::stream_chat`](crate::AnthropicClient::stream_chat),
    /// which takes `&self`. Returns the crate's [`EventStream`] so the mock carries
    /// the same `FusedStream + Send` guarantees as the real client.
    pub async fn stream_chat(
        self,
        _request: MessagesRequest,
    ) -> Result<EventStream, ProviderError> {
        use futures_util::StreamExt;

        Ok(Box::pin(futures_util::stream::iter(self.events).fuse()))
    }
}
