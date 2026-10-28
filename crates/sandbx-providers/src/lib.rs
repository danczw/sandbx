//! Hand-rolled streaming clients against LLM provider APIs.
//!
//! The seam is the return type: every client's `stream_chat` hands back
//! [`sandbx_provider::EventStream`], so there is no trait or enum over the backends. No
//! vendor SDK sits between sandbx and the wire format; see
//! `context/decision-provider-seam.md`.
//!
//! Nothing here is vocabulary any more: what a request is made of is
//! [`sandbx_prompt`]'s, the error a stream can fail with is
//! [`sandbx_provider::ProviderError`], the events it yields are [`sandbx_event`]'s, and
//! what that text may not carry to a terminal is `sandbx-text`'s, and the SSE framing a
//! payload arrives in is `sandbx-sse`'s. What is left is the vendor boundary —
//! everything that knows one API's field names, string tables and body rules lives
//! under `anthropic` — plus the one crypto-provider install (#364, #366, #367).

mod anthropic;

pub use anthropic::AnthropicClient;

/// Install the `ring` crypto provider for `rustls`, once per process.
///
/// `rustls-no-provider` selects none and building any `reqwest::Client` panics
/// without one — hence `pub`, so an integration test, a separate compiled crate,
/// can install it too. Idempotent: `install_default` is a process-global set-once,
/// so a second call's `Err` means a provider is already installed.
pub fn ensure_crypto_provider_installed() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
