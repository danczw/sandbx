/// Why a provider call did not produce a usable event stream.
///
/// Split by what the caller can do about it: a missing credential is a
/// configuration problem to fix before retrying at all; a transport failure,
/// a rate limit, or a 5xx might succeed on retry; a 4xx other than 429 will
/// not; and a malformed or truncated stream is a wire-format bug in sandbx or
/// a vendor-side change, not something any retry fixes.
#[derive(Debug)]
pub enum ProviderError {
    /// No credential could be resolved for this provider.
    MissingCredential {
        /// The environment variable that was checked and not found.
        env_var: &'static str,
    },

    /// The request never reached the API, or the connection dropped before a
    /// full response arrived.
    ///
    /// Distinct from [`ApiError`]: the API never got a chance to answer, so
    /// there is no status code or vendor error body to report.
    ///
    /// [`ApiError`]: Self::ApiError
    Transport {
        /// What was being attempted, for the operator to act on.
        detail: String,
        /// The underlying transport failure.
        source: reqwest::Error,
    },

    /// The API answered with a non-2xx status other than a rate limit, or sent
    /// an in-band SSE `error` event mid-stream.
    ///
    /// Rate limiting is split out as [`RateLimited`] so a caller can react to
    /// it differently (back off and retry) without string-matching `kind`.
    ///
    /// [`RateLimited`]: Self::RateLimited
    ApiError {
        /// `None` for an in-band SSE `error` event, which carries no HTTP
        /// status of its own.
        status: Option<u16>,
        /// The vendor's error type string, e.g. `"invalid_request_error"`.
        kind: String,
        /// The vendor's human-readable message.
        message: String,
    },

    /// The API answered 429.
    RateLimited {
        /// How long the API asked the caller to wait, from `Retry-After`, if
        /// it said.
        retry_after: Option<std::time::Duration>,
        /// The vendor's human-readable message.
        message: String,
    },

    /// A chunk of the SSE stream was not valid UTF-8, not a well-formed
    /// `event:`/`data:` frame, or its `data:` payload did not deserialize into
    /// any known event shape (including a `tool_use` block whose accumulated
    /// JSON never parsed).
    MalformedEvent {
        /// What was wrong, for the operator to act on.
        detail: String,
    },

    /// The connection closed before a `message_stop` event arrived.
    ///
    /// Distinct from [`MalformedEvent`]: every event seen so far was
    /// well-formed, but the turn never reached a defined end state, so nothing
    /// downstream can tell whether it actually finished.
    ///
    /// [`MalformedEvent`]: Self::MalformedEvent
    StreamEndedUnexpectedly,
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCredential { env_var } => {
                write!(f, "no credential found: set {env_var}")
            }
            Self::Transport { detail, source } => write!(f, "{detail}: {source}"),
            Self::ApiError {
                status: Some(status),
                kind,
                message,
            } => write!(f, "API returned {status} ({kind}): {message}"),
            Self::ApiError {
                status: None,
                kind,
                message,
            } => write!(f, "API reported an error mid-stream ({kind}): {message}"),
            Self::RateLimited {
                retry_after: Some(duration),
                message,
            } => write!(f, "rate limited, retry after {duration:?}: {message}"),
            Self::RateLimited {
                retry_after: None,
                message,
            } => write!(f, "rate limited: {message}"),
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
            Self::Transport { source, .. } => Some(source),
            Self::MissingCredential { .. }
            | Self::ApiError { .. }
            | Self::RateLimited { .. }
            | Self::MalformedEvent { .. }
            | Self::StreamEndedUnexpectedly => None,
        }
    }
}
