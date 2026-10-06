//! Hand-rolled streaming clients against LLM provider APIs.
//!
//! The seam is the return type: every client's `stream_chat` hands back
//! [`EventStream`], so there is no trait or enum over the backends. No vendor SDK
//! sits between sandbx and the wire format; see `context/decision-provider-seam.md`.

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
/// A provider that fabricates responses, kept out of a production build by the
/// `mock` feature; `Cargo.toml` records why no self dev-dependency enables it.
#[cfg(feature = "mock")]
pub use mock::MockProvider;
pub use request::{ContentBlock, MessagesRequest, RequestMessage, Role, ToolDefinition};

/// The event stream every provider client returns: owned, boxed, and fused.
///
/// Boxed because each backend's stream is a different concrete type. `FusedStream`
/// because the `unfold` under it panics if polled past `None`; `Send` so the turn
/// built on it can be `tokio::spawn`ed.
pub type EventStream = std::pin::Pin<
    Box<dyn futures_util::stream::FusedStream<Item = Result<AgentEvent, ProviderError>> + Send>,
>;

/// Install the `ring` crypto provider for `rustls`, once per process.
///
/// `rustls-no-provider` selects none and building any `reqwest::Client` panics
/// without one — hence `pub`, so an integration test, a separate compiled crate,
/// can install it too. Idempotent: `install_default` is a process-global set-once,
/// so a second call's `Err` means a provider is already installed.
pub fn ensure_crypto_provider_installed() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
