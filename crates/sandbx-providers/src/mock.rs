use crate::EventStream;
use crate::error::ProviderError;
use crate::event::AgentEvent;
use crate::request::MessagesRequest;

/// A test double that replays a canned sequence of events instead of calling
/// a real API.
///
/// Interchangeability with a real client comes from the return type alone:
/// `stream_chat` hands back the same [`EventStream`] an [`AnthropicClient`] does,
/// so a caller takes that one concrete type and neither knows nor cares which
/// side produced it.
///
/// Deliberately *not* reached through a shared abstraction over the backends. As
/// an implementor of a common trait, or a variant of a common enum, this double
/// would be part of the shipped surface permanently and the `mock` feature could
/// not hide it. Having no such abstraction is what lets the feature gate work.
///
/// [`AnthropicClient`]: crate::AnthropicClient
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
    /// unlike [`AnthropicClient::stream_chat`], which takes `&self` because one
    /// long-lived client serves many real turns.
    ///
    /// Returns the crate's [`EventStream`] rather than a bare `impl Stream`, so
    /// the mock carries the same `FusedStream + Send` guarantees a caller gets
    /// from the real client — that is the whole point of the alias.
    ///
    /// [`AnthropicClient::stream_chat`]: crate::AnthropicClient::stream_chat
    pub async fn stream_chat(
        self,
        _request: MessagesRequest,
    ) -> Result<EventStream, ProviderError> {
        use futures_util::StreamExt;

        Ok(Box::pin(futures_util::stream::iter(self.events).fuse()))
    }
}
