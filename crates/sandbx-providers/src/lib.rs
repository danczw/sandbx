//! Hand-rolled streaming clients against LLM provider APIs.
//!
//! `Provider` is a closed enum, not a trait object: the set of backends sandbx
//! ships is small and known at compile time (mirrors sandbx-tools' `BuiltinTool`),
//! so there is no `dyn Provider` and no `async_trait` here. Runtime dispatch is
//! reserved for the approval gate sandbx-agent will take, where the
//! implementation genuinely is picked at runtime — an interactive prompt, an
//! auto-approver, or a test double — rather than fixed when the binary is
//! built. Each variant owns its own request/response shape, SSE parsing, auth,
//! and error mapping into the shared `ProviderError`; no vendor SDK or
//! provider-abstraction crate sits between sandbx and the wire format.

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
/// Behind the `mock` feature so a provider that fabricates responses is not
/// part of the shipped surface.
///
/// The feature is *not* turned on by a self dev-dependency — the convenient way
/// to cover it with a plain `cargo test` — because resolver v3 unifies features
/// per package, so `mock` would be on in the one rlib every consumer crate
/// links against: production code referencing `MockProvider` would pass clippy
/// and the whole test suite, then fail for the first time in the release build.
/// `tests/mock_provider.rs` carries `required-features = ["mock"]` instead.
#[cfg(feature = "mock")]
pub use mock::MockProvider;
pub use request::{ContentBlock, MessagesRequest, RequestMessage, Role, ToolDefinition};

/// The event stream a provider returns: owned, boxed, and fused.
///
/// Boxed for the reason [`Provider::stream_chat`] gives. `FusedStream` rather
/// than `Stream` because the concrete stream underneath is built from
/// `futures_util::stream::unfold`, which *panics* if polled after it returns
/// `None` — easy to do by accident in a `select!` loop that does not break on
/// `None`. Naming fusedness in the type keeps the box from erasing it.
pub type EventStream = std::pin::Pin<
    Box<dyn futures_util::stream::FusedStream<Item = Result<AgentEvent, ProviderError>> + Send>,
>;

/// The LLM backends sandbx can talk to.
#[derive(Debug, Clone)]
pub enum Provider {
    /// The Anthropic Messages API.
    Anthropic(AnthropicClient),
}

impl Provider {
    /// Builds the Anthropic variant from `ANTHROPIC_API_KEY`.
    ///
    /// Fails with [`ProviderError::MissingCredential`] if the variable is
    /// unset or empty; see [`AnthropicClient::from_env`].
    pub fn anthropic_from_env() -> Result<Self, ProviderError> {
        Ok(Self::Anthropic(AnthropicClient::from_env()?))
    }

    /// Opens a streamed turn against whichever backend this is.
    ///
    /// Boxed even with a single variant today: `impl Stream` here would have to
    /// name one concrete type for every match arm, so the second backend
    /// (OpenAI is the one planned next) would force a breaking signature change
    /// on every caller.
    ///
    /// Takes the request by value; [`MessagesRequest`] is `Clone` so a caller
    /// that may need to retry the turn can keep a copy.
    pub async fn stream_chat(
        &self,
        request: MessagesRequest,
    ) -> Result<EventStream, ProviderError> {
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
/// Idempotent: `install_default` is itself a process-global set-once, so a
/// second call returns `Err` meaning "a provider was already installed" — the
/// expected steady state, and the reason this needs no `Once` of its own. Which
/// provider won is deliberately not reported: if something else installed
/// `aws-lc-rs` first, handshakes still work, and the `ring` choice is about this
/// project's build dependencies, not runtime correctness.
///
/// `AnthropicClient::new` calls this automatically. It is `pub` rather than
/// crate-private so integration tests (a separate compiled crate, which cannot
/// reach a `pub(crate)` item) can call it too: building *any* `reqwest::Client`
/// — even one used only to manufacture a test [`reqwest::Error`], with no
/// network call involved — panics without a provider installed first.
pub fn ensure_crypto_provider_installed() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
