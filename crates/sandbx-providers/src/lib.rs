//! Hand-rolled streaming clients against LLM provider APIs.
//!
//! The seam is the return type: every client's `stream_chat` hands back the
//! crate's [`EventStream`], so a caller names the concrete client it constructed
//! and no trait or enum over the backends is needed. Each client owns its own
//! request/response shape, SSE parsing, auth, and error mapping into the shared
//! [`ProviderError`]; no vendor SDK sits between sandbx and the wire format.

mod anthropic;
mod credentials;
mod error;
mod event;
#[cfg(feature = "mock")]
mod mock;
mod request;
mod sse;
mod wire;

pub use anthropic::AnthropicClient;
pub use credentials::{anthropic_api_key, resolve_api_key};
pub use error::ProviderError;
pub use event::{AgentEvent, StopReason};
/// Behind the `mock` feature so a provider that fabricates responses is not part
/// of the shipped surface.
///
/// Not enabled by a self dev-dependency: resolver v3 unifies features per
/// package, so `mock` would be on in the one rlib every consumer links against,
/// and production code referencing it would only fail in the release build.
/// `tests/mock_provider.rs` carries `required-features = ["mock"]` instead.
#[cfg(feature = "mock")]
pub use mock::MockProvider;
pub use request::{ContentBlock, MessagesRequest, RequestMessage, Role, ToolDefinition};

/// The event stream every provider client returns: owned, boxed, and fused.
///
/// Boxed rather than `impl Stream` because each backend's stream is a different
/// concrete type, so no single `impl Stream` return could name them all: one
/// allocation per HTTP round trip is what keeps the backend out of a caller's
/// signature. `FusedStream` rather than `Stream` because the stream underneath is
/// built from `futures_util::stream::unfold`, which panics if polled after it
/// returns `None`. `Send` so the turn built on it can be `tokio::spawn`ed.
pub type EventStream = std::pin::Pin<
    Box<dyn futures_util::stream::FusedStream<Item = Result<AgentEvent, ProviderError>> + Send>,
>;

/// Install the `ring` crypto provider for `rustls`, once per process.
///
/// `rustls-no-provider` (the reqwest TLS feature this crate uses) selects no
/// provider, so one must be installed before the first TLS handshake. `ring` over
/// the default `aws-lc-rs` because it needs no C/cmake/nasm build step.
///
/// Idempotent: `install_default` is itself a process-global set-once, so the
/// `Err` from a second call means a provider is already installed, and no `Once`
/// of its own is needed. `pub` so integration tests (a separate compiled crate)
/// can call it too: building any `reqwest::Client`, even one that makes no
/// network call, panics without a provider installed first.
pub fn ensure_crypto_provider_installed() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
