//! Hand-rolled streaming clients against LLM provider APIs.
//!
//! The seam is the return type: every client's `stream_chat` hands back
//! [`EventStream`], so there is no trait or enum over the backends. No vendor SDK
//! sits between sandbx and the wire format; see `context/decision-provider-seam.md`.
//!
//! [`Prompt`] and [`ProviderError`] are this crate's own vocabulary; the events a stream
//! yields are [`sandbx_event`]'s, and what that text may not carry to a terminal is
//! `sandbx-text`'s. Everything that knows one API's field names, string tables and body
//! rules lives under `anthropic`.

mod anthropic;
mod error;
mod prompt;
mod sse;

pub use anthropic::AnthropicClient;
pub use error::ProviderError;
pub use prompt::{
    ContentBlock, Prompt, RequestMessage, Role, Thinking, ToolChoice, ToolDefinition,
};

/// The event stream every provider client returns: owned, boxed, and fused.
///
/// Boxed because each backend's stream is a different concrete type. `FusedStream`
/// because the `unfold` under it panics if polled past `None`; `Send` so the turn
/// built on it can be `tokio::spawn`ed.
pub type EventStream = std::pin::Pin<
    Box<
        dyn futures_util::stream::FusedStream<
                Item = Result<sandbx_event::AgentEvent, ProviderError>,
            > + Send,
    >,
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
