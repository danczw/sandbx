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
        /// The environment variable that was checked.
        env_var: &'static str,
    },

    /// A base URL handed to `AnthropicClient::with_base_url` was rejected
    /// before any request was made.
    ///
    /// A configuration problem, like [`MissingCredential`]: the key travels in
    /// a request header, so a non-`https` base URL would put it on the wire in
    /// cleartext. Loopback `http://` is permitted, for a local mock server.
    ///
    /// [`MissingCredential`]: Self::MissingCredential
    InvalidBaseUrl {
        /// The rejected value, as given.
        base_url: String,
        /// Which rule it broke, for the operator to act on.
        reason: &'static str,
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
        /// Kept so the cause survives `detail`: the reqwest message is what
        /// separates a DNS failure from a TLS one from a dropped socket.
        source: reqwest::Error,
    },

    /// The API answered with a non-2xx status other than a rate limit, or sent
    /// an in-band SSE `error` event mid-stream.
    ///
    /// Rate limiting is split out as [`RateLimited`] so a caller can back off
    /// without string-matching `kind`. Which *other* failures are worth retrying
    /// — a 529 `overloaded_error` and a 500 `api_error` are, a 400 is not — is
    /// [`is_retryable`]'s answer, not a `status`/`kind` comparison at the call
    /// site.
    ///
    /// [`RateLimited`]: Self::RateLimited
    /// [`is_retryable`]: Self::is_retryable
    ApiError {
        /// `None` for an in-band SSE `error` event, which carries no HTTP
        /// status of its own.
        status: Option<u16>,
        /// The vendor's error type string, e.g. `"invalid_request_error"`.
        kind: String,
        /// The vendor's human-readable message.
        message: String,
        /// How long the API asked the caller to wait, from `Retry-After`, if it
        /// said. A 529 carries one as often as a 429 does, so it is read on
        /// every status rather than only the rate-limited path.
        retry_after: Option<std::time::Duration>,
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
    /// downstream can tell whether it actually finished. The complement holds
    /// too — a turn that *did* reach `message_stop` always ends with an
    /// [`AgentEvent::Stop`], even when the API never named a stop reason, so
    /// these two are the only two ways a stream can end.
    ///
    /// [`MalformedEvent`]: Self::MalformedEvent
    /// [`AgentEvent::Stop`]: crate::AgentEvent::Stop
    StreamEndedUnexpectedly,
}

impl ProviderError {
    /// Vendor `type` strings that mean "transient, try again" on an in-band SSE
    /// `error` event, which carries no HTTP status to classify by.
    const RETRYABLE_KINDS: &'static [&'static str] = &["overloaded_error", "api_error"];

    /// Whether retrying the identical request could plausibly succeed.
    ///
    /// The one place the retry/no-retry split is decided, so a retry layer never
    /// matches on `status` or `kind` itself: a transport failure or a rate limit
    /// is retryable, a 5xx is (Anthropic documents 500 `api_error` and 529
    /// `overloaded_error` as such), a 4xx other than 429 is not. A malformed
    /// stream is a wire-format bug no retry fixes; a truncated one might be, but
    /// the turn was already partially delivered, so re-sending is the caller's
    /// judgement call.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { .. } | Self::RateLimited { .. } => true,
            Self::ApiError {
                status: Some(status),
                ..
            } => *status >= 500,
            Self::ApiError {
                status: None, kind, ..
            } => Self::RETRYABLE_KINDS.contains(&kind.as_str()),
            Self::MissingCredential { .. }
            | Self::InvalidBaseUrl { .. }
            | Self::MalformedEvent { .. }
            | Self::StreamEndedUnexpectedly => false,
        }
    }

    /// How long the API asked the caller to wait before retrying, if it said.
    ///
    /// Reads the same `Retry-After` for a rate limit and for an overload, so a
    /// backoff layer does not need to know which variant it is holding.
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        match self {
            Self::RateLimited { retry_after, .. } | Self::ApiError { retry_after, .. } => {
                *retry_after
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCredential { env_var } => {
                write!(f, "no credential found: set {env_var}")
            }
            Self::InvalidBaseUrl { base_url, reason } => {
                write!(f, "invalid base URL {base_url:?}: {reason}")
            }
            Self::Transport { detail, source } => write!(f, "{detail}: {source}"),
            Self::ApiError {
                status: Some(status),
                kind,
                message,
                ..
            } => write!(f, "API returned {status} ({kind}): {message}"),
            Self::ApiError {
                status: None,
                kind,
                message,
                ..
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
            | Self::InvalidBaseUrl { .. }
            | Self::ApiError { .. }
            | Self::RateLimited { .. }
            | Self::MalformedEvent { .. }
            | Self::StreamEndedUnexpectedly => None,
        }
    }
}
