//! Hand-rolled streaming clients against LLM provider APIs.
//!
//! `Provider` is a closed enum, not a trait object: the set of backends sandbx
//! ships is small and known at compile time (mirrors sandbx-tools' `BuiltinTool`),
//! so there is no `dyn Provider` and no `async_trait` here — see `ApprovalGate`
//! in sandbx-agent for where dyn dispatch actually earns its keep. Each variant
//! owns its own request/response shape, SSE parsing, auth, and error mapping
//! into the shared `ProviderError`; no vendor SDK or provider-abstraction crate
//! sits between sandbx and the wire format.

mod anthropic;
mod credentials;
mod error;
mod event;
mod request;
mod sse;
mod wire;

pub use anthropic::AnthropicClient;
pub use credentials::{anthropic_api_key, resolve_api_key};
pub use error::ProviderError;
pub use event::{AgentEvent, StopReason};
pub use request::{ContentBlock, MessagesRequest, RequestMessage, Role, ToolDefinition};

/// The LLM backends sandbx can talk to.
#[derive(Debug, Clone)]
pub enum Provider {
    Anthropic(AnthropicClient),
}

impl Provider {
    pub fn anthropic_from_env() -> Result<Self, ProviderError> {
        Ok(Self::Anthropic(AnthropicClient::from_env()?))
    }

    /// Boxed even with a single variant today: PLAN.md already commits to
    /// adding OpenAI "one provider at a time, against the same Provider
    /// [enum]" — not a hypothetical. `impl Stream` in this position would need
    /// to name one concrete type for every match arm, which breaks the moment
    /// a second real backend lands, forcing a breaking signature change on
    /// every caller two phases from now. Boxing now costs one `Box::pin` and
    /// no new dependency.
    pub async fn stream_chat(
        &self,
        request: MessagesRequest,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<AgentEvent, ProviderError>>,
        ProviderError,
    > {
        match self {
            Self::Anthropic(client) => Ok(Box::pin(client.stream_chat(request).await?)),
        }
    }
}

/// Install the `ring` crypto provider for `rustls`, once per process.
///
/// `rustls-no-provider` (the reqwest TLS feature this crate uses) deliberately
/// does not auto-select a crypto provider, so one must be installed before the
/// first TLS handshake. `ring` is chosen over the default `aws-lc-rs` because
/// it needs no C/cmake/nasm build step, matching the project's existing
/// no-C-dependency stance (see `redb` over `rusqlite`).
///
/// Idempotent: a second call in the same process — e.g. constructing a second
/// `AnthropicClient` — finds a provider already installed and does nothing,
/// which is the expected steady state, not a failure to propagate or panic on.
///
/// `AnthropicClient::new` calls this automatically. It is `pub` rather than
/// crate-private so integration tests (a separate compiled crate) can call it
/// too: building *any* `reqwest::Client` — even one used only to manufacture a
/// test [`reqwest::Error`], with no network call involved — panics without a
/// provider installed first, and `tests/*.rs` cannot reach a `pub(crate)` item.
pub fn ensure_crypto_provider_installed() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Calling this more than once — e.g. constructing a second
    /// `AnthropicClient` in the same process — must not panic. A naive
    /// `install_default()` without the `Once` guard returns `Err` on a second
    /// call, and propagating or panicking on that would make a second client
    /// unconstructable for no reason.
    #[test]
    fn installing_the_provider_twice_does_not_panic() {
        ensure_crypto_provider_installed();
        ensure_crypto_provider_installed();
    }

    /// Not just "doesn't panic": a provider must actually be installed and
    /// usable, or every TLS handshake this crate ever makes would fail at
    /// runtime with no compile-time signal.
    #[test]
    fn a_provider_is_actually_installed_and_usable() {
        ensure_crypto_provider_installed();
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "no crypto provider installed"
        );
    }
}
