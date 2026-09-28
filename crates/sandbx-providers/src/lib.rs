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
/// part of the shipped surface — the same reasoning as sandbx-core's
/// `required-features` test probes.
///
/// The feature is *not* turned on by a self dev-dependency, which would be the
/// convenient way to cover it with a plain `cargo test`: that edge is active for
/// `--all-targets` and for `cargo test`, and resolver v3 unifies features per
/// package, so `mock` would be on in the one rlib every consumer crate links
/// against. Production code referencing `MockProvider` would then pass clippy
/// and the whole test suite, and fail for the first time in the release build.
/// `tests/mock_provider.rs` carries `required-features = ["mock"]` instead, so
/// the default lint and build passes see the shipped surface with `mock` off.
#[cfg(feature = "mock")]
pub use mock::MockProvider;
pub use request::{ContentBlock, MessagesRequest, RequestMessage, Role, ToolDefinition};

/// The event stream a provider returns: owned, boxed, and fused.
///
/// Boxed for the reason [`Provider::stream_chat`] gives. `FusedStream` rather
/// than `Stream` because the concrete stream underneath is built from
/// `futures_util::stream::unfold`, which *panics* if polled after it returns
/// `None` — an easy thing to do by accident in a `select!` loop that does not
/// break on `None`. The implementations here are fused; naming it in the type
/// keeps that guarantee from being erased by the box.
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
    /// Boxed even with a single variant today: PLAN.md already commits to
    /// adding OpenAI "one provider at a time, against the same Provider
    /// [enum]" — not a hypothetical. `impl Stream` in this position would need
    /// to name one concrete type for every match arm, which breaks the moment
    /// a second real backend lands, forcing a breaking signature change on
    /// every caller two phases from now. Boxing now costs one `Box::pin` and
    /// no new dependency.
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
/// second call — e.g. constructing a second `AnthropicClient` — returns `Err`
/// meaning "a provider was already installed", which is the expected steady
/// state and not something to propagate or panic on. The discarded `Err` is the
/// only reason this function needs no `Once` of its own.
///
/// It deliberately does not report *which* provider won. If something else in
/// the process installed `aws-lc-rs` first, that provider is used and every
/// handshake still works; the choice of `ring` is about this project's build
/// dependencies, not about correctness at runtime.
///
/// `AnthropicClient::new` calls this automatically. It is `pub` rather than
/// crate-private so integration tests (a separate compiled crate) can call it
/// too: building *any* `reqwest::Client` — even one used only to manufacture a
/// test [`reqwest::Error`], with no network call involved — panics without a
/// provider installed first, and `tests/*.rs` cannot reach a `pub(crate)` item.
pub fn ensure_crypto_provider_installed() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
