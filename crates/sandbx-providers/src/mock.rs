use crate::EventStream;
use crate::error::ProviderError;
use crate::event::AgentEvent;
use crate::request::MessagesRequest;

/// A test double that replays a canned sequence of events instead of calling
/// a real API.
///
/// Deliberately not a `Provider` variant: that would permanently ship a variant
/// which must never run in production. Interchangeability comes from the return
/// type instead — `stream_chat` hands back the same [`EventStream`] a real
/// provider does, so a caller takes that one concrete type and neither knows nor
/// cares which side produced it.
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

    /// Consumes `self` — a `MockProvider` is throwaway per-test canned data,
    /// unlike `Provider::stream_chat(&self, ..)`, which is reused across many
    /// real turns from one long-lived client.
    ///
    /// Returns the crate's [`EventStream`] rather than a bare `impl Stream`, so
    /// the mock carries the same `FusedStream + Send` guarantees a caller gets
    /// from a real provider — that is the whole point of the alias.
    pub async fn stream_chat(
        self,
        _request: MessagesRequest,
    ) -> Result<EventStream, ProviderError> {
        use futures_util::StreamExt;

        Ok(Box::pin(futures_util::stream::iter(self.events).fuse()))
    }
}
