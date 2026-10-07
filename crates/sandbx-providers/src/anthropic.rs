use secrecy::{ExposeSecret, SecretString};

use crate::EventStream;
use crate::error::ProviderError;
use crate::prompt::Prompt;
use crate::{credentials, ensure_crypto_provider_installed, sse};

mod body;
mod wire;

use body::Body;

/// A hand-rolled streaming client for the Anthropic Messages API.
///
/// `Debug` is derived, not hand-written: `SecretString`'s `Debug` prints
/// `[REDACTED]`, so the key reaches a log only through an explicit
/// `expose_secret`, and the derive picks up any field added later.
#[derive(Clone, Debug)]
pub struct AnthropicClient {
    http: reqwest::Client,
    api_key: SecretString,
    base_url: String,
}

impl AnthropicClient {
    /// Where [`new`](Self::new) points unless
    /// [`with_base_url`](Self::with_base_url) overrides it.
    pub const DEFAULT_BASE_URL: &'static str = "https://api.anthropic.com";
    const ANTHROPIC_VERSION: &'static str = "2023-06-01";

    /// Builds a client against [`DEFAULT_BASE_URL`](Self::DEFAULT_BASE_URL). Makes no
    /// network call, so every failure is local.
    pub fn new(api_key: SecretString) -> Result<Self, ProviderError> {
        Self::configured(api_key, Self::DEFAULT_BASE_URL)
    }

    /// Builds a client from `ANTHROPIC_API_KEY`, failing with
    /// [`ProviderError::MissingCredential`] if it is unset or empty.
    pub fn from_env() -> Result<Self, ProviderError> {
        Self::new(credentials::anthropic_api_key()?)
    }

    /// Overrides the base URL; public, not `#[cfg(test)]`-gated, because it is also
    /// the seam for a self-hosted Anthropic-compatible gateway.
    ///
    /// [`ProviderError::InvalidBaseUrl`] for anything but `https://`, since every
    /// request carries the API key in `x-api-key`; `http://` to a loopback host is
    /// the one exception, for a local mock server. A trailing `/` is trimmed, so no
    /// doubled slash reaches `/v1/messages`.
    pub fn with_base_url(self, base_url: impl Into<String>) -> Result<Self, ProviderError> {
        Self::configured(self.api_key, base_url)
    }

    /// The one construction path: the URL is validated, and the HTTP client built to
    /// match where it points.
    fn configured(
        api_key: SecretString,
        base_url: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        let base_url = base_url.into();
        let trimmed = base_url.trim_end_matches('/');
        let reachability = match validate_base_url(trimmed) {
            // Reported untrimmed: the operator should see the URL they gave.
            Err(reason) => return Err(ProviderError::InvalidBaseUrl { base_url, reason }),
            Ok(reachability) => reachability,
        };

        Ok(Self {
            http: build_http(reachability)?,
            api_key,
            // Not `Url::as_str`, which normalises `https://host` to
            // `https://host/` and so would double the slash in `/v1/messages`.
            base_url: trimmed.to_string(),
        })
    }

    /// Opens a streamed turn against the Messages API.
    ///
    /// The returned `Result` covers everything knowable before the first event;
    /// anything that goes wrong once events are flowing arrives as an `Err` item in
    /// the stream. A caller that may retry clones the prompt first.
    pub async fn stream_chat(&self, prompt: Prompt) -> Result<EventStream, ProviderError> {
        let response = self
            .http
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", self.api_key.expose_secret())
            .header("anthropic-version", Self::ANTHROPIC_VERSION)
            .json(&Body(&prompt))
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

        Ok(Box::pin(wire::event_stream(sse::tokenize(
            response.bytes_stream(),
        ))))
    }
}

/// What kind of endpoint a base URL points at, which decides two settings of the
/// HTTP client built for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reachability {
    /// An `https://` URL to anywhere.
    PublicHttps,
    /// `http://` to a loopback host — permitted only for a local mock server.
    LoopbackHttp,
}

/// Accept `https://` anywhere, `http://` only to a loopback host.
fn validate_base_url(base_url: &str) -> Result<Reachability, &'static str> {
    let url = reqwest::Url::parse(base_url).map_err(|_| "not a valid absolute URL")?;
    // `/v1/messages` is appended to the path, so anything after it lands mid-URL: a
    // post to `https://host/v1/messages?x=1`, or a userinfo that puts a second
    // credential on the wire.
    if url.query().is_some() {
        return Err("a base URL may not carry a query string");
    }
    if url.fragment().is_some() {
        return Err("a base URL may not carry a fragment");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("a base URL may not embed credentials");
    }
    match url.scheme() {
        "https" => Ok(Reachability::PublicHttps),
        "http" if url.host_str().is_some_and(is_loopback_host) => Ok(Reachability::LoopbackHttp),
        "http" => Err("http:// would send the API key in cleartext; use https://"),
        _ => Err("only https:// (or http:// to a loopback host) is supported"),
    }
}

/// Build the HTTP client for a base URL of the given kind.
fn build_http(reachability: Reachability) -> Result<reqwest::Client, ProviderError> {
    ensure_crypto_provider_installed();
    let mut builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        // A read timeout, not `.timeout(..)`: the latter bounds the whole streamed
        // body and would kill a long generation, while this bounds inactivity and
        // resets on every chunk. Anthropic sends `ping` frames throughout a turn, so
        // 120s of silence means the connection is gone, not that the model is slow.
        .read_timeout(std::time::Duration::from_secs(120))
        // reqwest's cross-host redirect scrubbing strips only the headers it knows
        // are credentials — `Authorization`, `Cookie`, `Proxy-Authorization` — never
        // `x-api-key`, so under the default policy a 3xx would replay the key, and
        // for 307/308 the conversation body, to whatever host `Location` names.
        .redirect(reqwest::redirect::Policy::none());

    builder = match reachability {
        // Belt and braces over `validate_base_url`: if a later code path ever sets
        // a cleartext URL, the client refuses rather than sending the key.
        Reachability::PublicHttps => builder.https_only(true),
        // The `system-proxy` feature is on, so reqwest honours `HTTP_PROXY`, which
        // would route an approved `http://127.0.0.1` request off the machine with
        // `x-api-key` in cleartext. Loopback needs no proxy.
        Reachability::LoopbackHttp => builder.no_proxy(),
    };

    builder.build().map_err(|source| ProviderError::Transport {
        detail: "building HTTP client".to_string(),
        source,
    })
}

/// `host_str` keeps the brackets on an IPv6 literal, so they come off before
/// parsing; `localhost` is matched by name because it does not parse as an IP.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// 429 becomes [`ProviderError::RateLimited`], every other non-2xx
/// [`ProviderError::ApiError`], parsed from the vendor's
/// `{"type":"error","error":{...}}` envelope where present.
async fn map_error_response(
    status: reqwest::StatusCode,
    response: reqwest::Response,
) -> ProviderError {
    // Read for every status, not just 429: Anthropic sends `Retry-After` with a 529
    // too. Only the integer-seconds form it documents parses; the HTTP-date form an
    // intermediary might use degrades to `None`.
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(std::time::Duration::from_secs);

    let body = response.text().await.unwrap_or_default();
    let (kind, message) = match serde_json::from_str::<wire::RawApiErrorEnvelope>(&body) {
        Ok(envelope) => (envelope.error.kind, envelope.error.message),
        Err(_) => ("unknown_error".to_string(), body),
    };

    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        ProviderError::RateLimited {
            retry_after,
            message,
        }
    } else {
        ProviderError::ApiError {
            status: Some(status.as_u16()),
            kind,
            message,
            retry_after,
            // Every 5xx, including the 529 Anthropic uses for an overload. A 4xx
            // other than the 429 handled above is a request this client built wrong.
            transient: status.as_u16() >= 500,
        }
    }
}
