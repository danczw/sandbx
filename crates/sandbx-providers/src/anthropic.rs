use secrecy::{ExposeSecret, SecretString};

use crate::error::ProviderError;
use crate::event::AgentEvent;
use crate::request::MessagesRequest;
use crate::{credentials, ensure_crypto_provider_installed, sse, wire};

/// A hand-rolled streaming client for the Anthropic Messages API.
///
/// `#[derive(Clone)]` works directly — `reqwest::Client`, `SecretString`, and
/// `String` are all `Clone` — but `Debug` cannot be derived, since
/// `SecretString` implements neither, and a field the derive could not see
/// would make an accidental leak into a log line invisible until it happened.
#[derive(Clone)]
pub struct AnthropicClient {
    http: reqwest::Client,
    api_key: SecretString,
    base_url: String,
}

impl std::fmt::Debug for AnthropicClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnthropicClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl AnthropicClient {
    pub const DEFAULT_BASE_URL: &'static str = "https://api.anthropic.com";
    const ANTHROPIC_VERSION: &'static str = "2023-06-01";

    pub fn new(api_key: SecretString) -> Result<Self, ProviderError> {
        ensure_crypto_provider_installed();
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            // No overall .timeout(...): it would bound the whole streamed
            // response body, killing a legitimately long generation. A
            // per-turn wall-clock bound, if wanted, belongs one layer up
            // (wrapping the whole consumption loop), and is not the same
            // mechanism as sandbx-core's SandboxedCommand::timeout — that
            // bounds a local CPU-bound subprocess by SIGKILLing a process
            // group, this would bound a remote I/O-bound call by cancelling a
            // future. Do not unify them.
            .build()
            .map_err(|source| ProviderError::Transport {
                detail: "building HTTP client".to_string(),
                source,
            })?;
        Ok(Self {
            http,
            api_key,
            base_url: Self::DEFAULT_BASE_URL.to_string(),
        })
    }

    pub fn from_env() -> Result<Self, ProviderError> {
        Self::new(credentials::anthropic_api_key()?)
    }

    /// Overrides the base URL. Not test-only — also the right seam for a
    /// self-hosted/enterprise Anthropic-compatible gateway — so a plain
    /// public method rather than a `#[cfg(test)]`-gated one, which
    /// `tests/*.rs` (a separate compiled crate) could not reach anyway.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub async fn stream_chat(
        &self,
        request: MessagesRequest,
    ) -> Result<
        // `+ use<>`: the returned stream owns everything it needs (the auth
        // header is read before this point; the stream itself only holds an
        // owned `reqwest::Response`) and borrows nothing from `&self`. Without
        // this, Rust's default RPIT capture rules tie the opaque type to
        // `&self`'s lifetime, which breaks `Provider::stream_chat` boxing this
        // into a `BoxStream<'static, _>`.
        impl futures_util::Stream<Item = Result<AgentEvent, ProviderError>> + use<>,
        ProviderError,
    > {
        let response = self
            .http
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", self.api_key.expose_secret())
            .header("anthropic-version", Self::ANTHROPIC_VERSION)
            .json(&request)
            .send()
            .await
            .map_err(|source| ProviderError::Transport {
                detail: "sending request".to_string(),
                source,
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(map_error_response(status, response).await);
        }

        Ok(wire::event_stream(sse::tokenize(response.bytes_stream())))
    }
}

/// Turn a non-2xx response into the right `ProviderError` variant.
///
/// A 429 is split out as [`ProviderError::RateLimited`] so a caller can react
/// to it distinctly; everything else falls back to
/// [`ProviderError::ApiError`], parsed from the vendor's standard
/// `{"type":"error","error":{...}}` envelope where present.
async fn map_error_response(
    status: reqwest::StatusCode,
    response: reqwest::Response,
) -> ProviderError {
    #[derive(serde::Deserialize)]
    struct ErrorEnvelope {
        error: ErrorBody,
    }
    #[derive(serde::Deserialize)]
    struct ErrorBody {
        #[serde(rename = "type")]
        kind: String,
        message: String,
    }

    let retry_after = status
        .as_u16()
        .eq(&429)
        .then(|| {
            response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .map(std::time::Duration::from_secs)
        })
        .flatten();

    let body = response.text().await.unwrap_or_default();
    let (kind, message) = match serde_json::from_str::<ErrorEnvelope>(&body) {
        Ok(envelope) => (envelope.error.kind, envelope.error.message),
        Err(_) => ("unknown_error".to_string(), body),
    };

    if status.as_u16() == 429 {
        ProviderError::RateLimited {
            retry_after,
            message,
        }
    } else {
        ProviderError::ApiError {
            status: Some(status.as_u16()),
            kind,
            message,
        }
    }
}
