use secrecy::{ExposeSecret, SecretString};

use crate::EventStream;
use crate::error::ProviderError;
use crate::request::MessagesRequest;
use crate::{credentials, ensure_crypto_provider_installed, sse, wire};

/// A hand-rolled streaming client for the Anthropic Messages API.
///
/// `Debug` is derived rather than hand-written: `SecretString`'s own `Debug`
/// prints a redaction instead of the secret, and the derive picks up any field
/// added later.
#[derive(Clone, Debug)]
pub struct AnthropicClient {
    http: reqwest::Client,
    api_key: SecretString,
    base_url: String,
}

impl AnthropicClient {
    /// Where [`new`] points unless [`with_base_url`] overrides it.
    ///
    /// [`new`]: Self::new
    /// [`with_base_url`]: Self::with_base_url
    pub const DEFAULT_BASE_URL: &'static str = "https://api.anthropic.com";
    const ANTHROPIC_VERSION: &'static str = "2023-06-01";

    /// Builds a client against [`DEFAULT_BASE_URL`] with the given key.
    ///
    /// Installs the `ring` crypto provider first (see
    /// [`ensure_crypto_provider_installed`]), since building a `reqwest::Client`
    /// without one panics. Makes no network call, so every failure is local.
    ///
    /// [`DEFAULT_BASE_URL`]: Self::DEFAULT_BASE_URL
    /// [`ensure_crypto_provider_installed`]: crate::ensure_crypto_provider_installed
    pub fn new(api_key: SecretString) -> Result<Self, ProviderError> {
        Self::configured(api_key, Self::DEFAULT_BASE_URL)
    }

    /// Builds a client from `ANTHROPIC_API_KEY`.
    ///
    /// Fails with [`ProviderError::MissingCredential`] if the variable is
    /// unset or empty.
    pub fn from_env() -> Result<Self, ProviderError> {
        Self::new(credentials::anthropic_api_key()?)
    }

    /// Overrides the base URL; also the seam for a self-hosted
    /// Anthropic-compatible gateway, so public rather than `#[cfg(test)]`-gated.
    ///
    /// Returns [`ProviderError::InvalidBaseUrl`] for anything that is not
    /// `https://`, since every request carries the API key in a header. `http://`
    /// to a loopback host is the one exception, for a local mock server.
    ///
    /// A trailing `/` is trimmed, so no doubled slash reaches `/v1/messages`. A
    /// path prefix is allowed, but a query string, fragment or embedded
    /// credentials are rejected: the endpoint appends `/v1/messages`, which would
    /// land *before* a `?`, so such a URL would post somewhere other than where
    /// it reads. Rebuilds the HTTP client, two of whose settings depend on where
    /// it now points — see `build_http`.
    pub fn with_base_url(self, base_url: impl Into<String>) -> Result<Self, ProviderError> {
        Self::configured(self.api_key, base_url)
    }

    /// The one construction path, [`new`](Self::new) included: whatever the client
    /// points at is validated, and the HTTP client built to match where that is.
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
    /// The returned `Result` covers everything knowable before the first event —
    /// transport failure, a non-2xx status — while anything that goes wrong once
    /// events are flowing arrives as an `Err` item *in* the stream. Takes the
    /// request by value, so a caller that may retry should clone it first.
    pub async fn stream_chat(
        &self,
        request: MessagesRequest,
    ) -> Result<EventStream, ProviderError> {
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

        Ok(Box::pin(wire::event_stream(sse::tokenize(
            response.bytes_stream(),
        ))))
    }
}

/// What kind of endpoint a base URL points at, which decides two client
/// settings that cannot be chosen before the URL is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reachability {
    /// An `https://` URL to anywhere.
    PublicHttps,
    /// `http://` to a loopback host — permitted only for a local mock server.
    LoopbackHttp,
}

/// Accept `https://` anywhere, `http://` only to a loopback host.
///
/// `Err` carries the operator-facing reason rather than a bool, so the error
/// says which rule was broken.
fn validate_base_url(base_url: &str) -> Result<Reachability, &'static str> {
    let url = reqwest::Url::parse(base_url).map_err(|_| "not a valid absolute URL")?;
    // `/v1/messages` is appended to the path, so anything after it would end up
    // mid-URL: a post to `https://host/v1/messages?x=1`, or a userinfo that puts
    // a second credential on the wire.
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
///
/// Installs the `ring` crypto provider first (see
/// [`ensure_crypto_provider_installed`]), since building a `reqwest::Client`
/// without one panics.
///
/// [`ensure_crypto_provider_installed`]: crate::ensure_crypto_provider_installed
fn build_http(reachability: Reachability) -> Result<reqwest::Client, ProviderError> {
    ensure_crypto_provider_installed();
    let mut builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        // A read timeout, not `.timeout(..)`: the latter bounds the whole streamed
        // body and would kill a legitimately long generation, while this bounds
        // *inactivity between chunks* and resets on every one, so a stalled or
        // half-open connection cannot hang `stream_chat` forever. Anthropic sends
        // `ping` frames throughout a turn, so 120s of total silence means the
        // connection is gone, not that the model is thinking. Not a per-turn
        // wall-clock bound; that belongs one layer up.
        .read_timeout(std::time::Duration::from_secs(120))
        // reqwest's cross-host redirect scrubbing only strips headers it knows are
        // credentials (`Authorization`, `Cookie`, `Proxy-Authorization`), never the
        // `x-api-key` the key travels in. Under the default policy a 3xx would
        // replay the key — and, for 307/308, the conversation body — to whatever
        // host `Location` names. The Messages API never legitimately redirects.
        .redirect(reqwest::redirect::Policy::none());

    builder = match reachability {
        // Belt and braces over `validate_base_url`: if a later code path ever sets
        // a cleartext URL, the client refuses the request rather than sending the
        // key.
        Reachability::PublicHttps => builder.https_only(true),
        // `system-proxy` is enabled, so reqwest honours `HTTP_PROXY`. For a
        // loopback URL that would route an approved `http://127.0.0.1` request off
        // the machine with `x-api-key` in cleartext, and loopback needs no proxy.
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

/// Turn a non-2xx response into the right `ProviderError` variant.
///
/// A 429 becomes [`ProviderError::RateLimited`]; everything else becomes
/// [`ProviderError::ApiError`], parsed from the vendor's
/// `{"type":"error","error":{...}}` envelope where present. Which of those are
/// worth retrying is [`ProviderError::is_retryable`]'s job.
async fn map_error_response(
    status: reqwest::StatusCode,
    response: reqwest::Response,
) -> ProviderError {
    // Read for every status, not just 429: Anthropic sends `Retry-After` with a 529
    // too. Only the integer-seconds form Anthropic documents is parsed; the
    // HTTP-date form an intermediary might use degrades to `None`.
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
        }
    }
}
