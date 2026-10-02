//! Hand-rolled streaming clients against LLM provider APIs.
//!
//! The seam is the return type: every client's `stream_chat` hands back the
//! crate's [`EventStream`]. Each client is its own concrete type
//! ([`AnthropicClient`] today, OpenAI planned next) and a caller names the one it
//! constructed — see that alias for why that is enough.
//!
//! No trait and no enum over the backends. There is one backend today,
//! constructed directly by its caller from `ANTHROPIC_API_KEY`; the intent is
//! that a backend is chosen where the client is constructed and does not vary
//! per request, which is why the mirror of sandbx-tools' `BuiltinTool` does not
//! hold — a tool is dispatched per call, on a name the model chose at runtime.
//! Nothing enforces that intent yet, and no binary wires a client up at all. If
//! a provider ever becomes a per-turn choice — a `/model` switch, a fallback on
//! rate-limit — the enum #90 removed is worth revisiting.
//!
//! Runtime dispatch is reserved for the approval gate sandbx-agent will take,
//! where the implementation genuinely is picked at runtime — an interactive
//! prompt, an auto-approver, or a test double — rather than fixed when the binary
//! is built.
//!
//! Each client owns its own request/response shape, SSE parsing, auth, and error
//! mapping into the shared [`ProviderError`]; no vendor SDK or
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

/// The event stream every provider client returns: owned, boxed, and fused.
///
/// This alias *is* the provider seam. A caller takes one concrete type and the
/// choice of backend never reaches its signature — which is why no trait and no
/// enum over the clients is needed to make them interchangeable.
///
/// Boxed rather than `impl Stream`, and that is what makes the seam hold: each
/// backend's stream is a different concrete type, so no single `impl Stream`
/// return could name them all, and a caller written against the Anthropic
/// client's opaque type would take a breaking change the day the second backend
/// (OpenAI is the one planned next) lands. One allocation per request, against
/// an HTTP round trip, buys that.
///
/// `FusedStream` rather than `Stream` because the concrete stream underneath is
/// built from `futures_util::stream::unfold`, which *panics* if polled after it
/// returns `None` — easy to do by accident in a `select!` loop that does not
/// break on `None`. Naming fusedness in the type keeps the box from erasing it.
///
/// `Send` so the turn built on it can be `tokio::spawn`ed, which is what a TUI
/// driving one has to do.
pub type EventStream = std::pin::Pin<
    Box<dyn futures_util::stream::FusedStream<Item = Result<AgentEvent, ProviderError>> + Send>,
>;

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
