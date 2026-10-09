//! Hand-rolled streaming clients against LLM provider APIs.
//!
//! The seam is the return type: every client's `stream_chat` hands back
//! [`EventStream`], so there is no trait or enum over the backends. No vendor SDK
//! sits between sandbx and the wire format; see `context/decision-provider-seam.md`.
//!
//! [`Prompt`], [`AgentEvent`] and [`ProviderError`] are this crate's own vocabulary —
//! including [`invisible`], the one thing model-chosen text may never carry to a terminal,
//! owned here so no sink keeps its own copy of the table. Everything that knows one API's
//! field names, string tables and body rules lives under `anthropic`.

mod anthropic;
mod credentials;
mod error;
mod event;
#[cfg(feature = "mock")]
mod mock;
mod prompt;
mod sse;
mod text;

pub use anthropic::AnthropicClient;
pub use credentials::{anthropic_api_key, resolve_api_key};
pub use error::ProviderError;
pub use event::{AgentEvent, StopReason};
/// A provider that fabricates responses, kept out of a production build by the
/// `mock` feature; `Cargo.toml` records why no self dev-dependency enables it.
#[cfg(feature = "mock")]
pub use mock::MockProvider;
pub use prompt::{
    ContentBlock, Prompt, RequestMessage, Role, Thinking, ToolChoice, ToolDefinition,
};
pub use text::invisible;

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
