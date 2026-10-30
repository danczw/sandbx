//! The provider seam: the stream a client hands back, and the error it can fail with.
//!
//! There is no provider trait and no provider object. `Provider` was a one-variant enum
//! whose methods were pass-throughs, and it was deleted (#90) — a client's `stream_chat`
//! returns [`EventStream`] directly. The seam is the **return type**, which is also why
//! these two are one crate: the alias's `Item` names [`ProviderError`], so neither is
//! nameable without the other. The per-rule account is
//! `context/decision-provider-seam.md`.
//!
//! Nothing here speaks a wire format — the vendor's field names, string tables and body
//! rules are `sandbx-anthropic`'s — and no HTTP type crosses either:
//! [`ProviderError::Transport`] boxes its source rather than naming `reqwest::Error`, so
//! a crate that only names the seam does not link reqwest and hyper to do it (#335).

use std::fmt;
use std::pin::Pin;
use std::time::Duration;

/// The event stream every provider client returns: owned, boxed, and fused.
///
/// Boxed because each backend's stream is a different concrete type. `FusedStream`
/// because the `unfold` under it panics if polled past `None`; `Send` so the turn
/// built on it can be `tokio::spawn`ed.
pub type EventStream = Pin<
    Box<
        dyn futures_util::stream::FusedStream<
                Item = Result<sandbx_event::AgentEvent, ProviderError>,
            > + Send,
    >,
>;

/// Why a provider call did not produce a usable event stream.
#[derive(Debug)]
pub enum ProviderError {
    /// A base URL was rejected before any request was made: the key travels in the
    /// `x-api-key` header, so a non-`https` base URL would put it on the wire in
    /// cleartext. Loopback `http://` is permitted, for a local mock server.
    InvalidBaseUrl {
        /// The rejected value, as given.
        base_url: String,
        /// Which rule it broke, for the operator to act on.
        reason: &'static str,
    },

    /// The request never reached the API, or the connection dropped before a full
    /// response arrived — so there is no status code or vendor error body to report.
    Transport {
        /// What was being attempted, for the operator to act on.
        detail: String,
        /// The client's own error. Its `source()` chain, not its message, is what
        /// separates a DNS failure from a TLS one.
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The API answered with a non-2xx status other than a rate limit, or sent an
    /// in-band SSE `error` event mid-stream.
    ApiError {
        /// `None` for an in-band SSE `error` event, which carries no HTTP status.
        status: Option<u16>,
        /// The vendor's error type string, e.g. `"invalid_request_error"`.
        kind: String,
        /// The vendor's human-readable message.
        message: String,
    },

    /// The API answered 429.
    RateLimited {
        /// From `Retry-After`, if the API said.
        retry_after: Option<Duration>,
        /// The vendor's human-readable message.
        message: String,
    },

    /// A chunk of the SSE stream was not valid UTF-8, not a well-formed
    /// `event:`/`data:` frame, or matched no known event shape — including a
    /// `tool_use` block whose accumulated JSON never parsed.
    MalformedEvent {
        /// What was wrong, for the operator to act on.
        detail: String,
    },

    /// The connection closed before a `message_stop` event arrived: every event seen
    /// was well-formed, but the turn never reached a defined end.
    StreamEndedUnexpectedly,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl { base_url, reason } => {
                write!(f, "invalid base URL {base_url:?}: {reason}")
            }
            Self::Transport { detail, source } => write!(f, "{detail}: {source}"),
            Self::ApiError {
                status,
                kind,
                message,
            } => match status {
                Some(status) => write!(f, "API returned {status} ({kind}): {message}"),
                None => write!(f, "API reported an error mid-stream ({kind}): {message}"),
            },
            Self::RateLimited {
                retry_after,
                message,
            } => match retry_after {
                Some(duration) => write!(f, "rate limited, retry after {duration:?}: {message}"),
                None => write!(f, "rate limited: {message}"),
            },
            Self::MalformedEvent { detail } => write!(f, "malformed stream event: {detail}"),
            Self::StreamEndedUnexpectedly => {
                write!(f, "stream ended before the model reported it was done")
            }
        }
    }
}

impl std::error::Error for ProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport { source, .. } => Some(source.as_ref()),
            Self::InvalidBaseUrl { .. }
            | Self::ApiError { .. }
            | Self::RateLimited { .. }
            | Self::MalformedEvent { .. }
            | Self::StreamEndedUnexpectedly => None,
        }
    }
}
