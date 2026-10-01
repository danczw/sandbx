use secrecy::{ExposeSecret, SecretString};

use crate::error::ProviderError;
use crate::event::AgentEvent;
use crate::request::MessagesRequest;
use crate::{credentials, ensure_crypto_provider_installed, sse, wire};

/// A hand-rolled streaming client for the Anthropic Messages API.
///
/// `Debug` is derived rather than hand-written: `SecretString`'s own `Debug`
/// prints a redaction instead of the secret — the entire reason the key is
/// wrapped in it — and the derive picks up any field added later, where a
/// hand-written impl would silently omit it.
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
    /// [`ensure_crypto_provider_installed`]), since building a
    /// `reqwest::Client` without one panics. Fails only if reqwest cannot
    /// construct its client at all — no network access happens here.
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

    /// Overrides the base URL. Not test-only — also the right seam for a
    /// self-hosted/enterprise Anthropic-compatible gateway — so a plain
    /// public method rather than a `#[cfg(test)]`-gated one, which
    /// `tests/*.rs` (a separate compiled crate) could not reach anyway.
    ///
    /// Returns [`ProviderError::InvalidBaseUrl`] for anything that is not
    /// `https://`: every request carries the API key in a header, so a mistyped
    /// or downgraded `http://` URL here puts the key on the wire in cleartext.
    /// `http://` to a loopback host is the one exception, for a local mock
    /// server under test.
    ///
    /// A trailing `/` is trimmed, so both `https://host` and `https://host/`
    /// produce `https://host/v1/messages` rather than a doubled slash. A path
    /// prefix is allowed (a gateway may mount the API under one), but a query
    /// string, fragment or embedded credentials are rejected: the endpoint is
    /// built by appending `/v1/messages`, which would land *before* a `?`, so
    /// such a URL would silently post somewhere other than where it reads.
    ///
    /// Rebuilds the underlying HTTP client, because two of its settings depend
    /// on where it now points — see [`build_http`].
    pub fn with_base_url(self, base_url: impl Into<String>) -> Result<Self, ProviderError> {
        Self::configured(self.api_key, base_url)
    }

    /// The one construction path: whatever the client points at is validated,
    /// and the HTTP client is built to match where that is.
    ///
    /// [`new`] went through this too rather than asserting
    /// [`Reachability::PublicHttps`] for itself — that made the https-ness of the
    /// default URL a fact stated in a second place, free to drift from what
    /// [`validate_base_url`] would say about it.
    ///
    /// [`new`]: Self::new
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
            // Stored trimmed, not as `Url::as_str`, which normalises
            // `https://host` to `https://host/` and so would double the slash in
            // the `/v1/messages` endpoint built from it.
            base_url: trimmed.to_string(),
        })
    }

    /// Opens a streamed turn against the Messages API.
    ///
    /// The returned `Result` covers everything knowable before the first
    /// event — transport failure, a non-2xx status — while anything that goes
    /// wrong once events are flowing arrives as an `Err` item *in* the stream.
    ///
    /// Takes the request by value, and [`MessagesRequest`] is `Clone`: a caller
    /// that wants to retry a turn after [`ProviderError::RateLimited`] should
    /// clone it before calling.
    pub async fn stream_chat(
        &self,
        request: MessagesRequest,
    ) -> Result<
        // `FusedStream`, not plain `Stream`: the stream is safe to poll past its
        // end, and saying so in the signature is what lets a caller — or a
        // combinator requiring fusedness — rely on that.
        //
        // `+ use<>`: the returned stream owns everything it needs (the auth
        // header is read before this point; the stream itself only holds an
        // owned `reqwest::Response`) and borrows nothing from `&self`. Without
        // this, Rust's default RPIT capture rules tie the opaque type to
        // `&self`'s lifetime, which breaks `Provider::stream_chat` boxing this
        // into an owned box.
        impl futures_util::stream::FusedStream<Item = Result<AgentEvent, ProviderError>> + use<>,
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
    // The endpoint is formed by appending `/v1/messages`, so anything after the
    // path would end up in the middle of the URL. Rejecting it here beats
    // silently posting to `https://host/v1/messages?x=1` — or worse, to a URL
    // whose userinfo puts a second credential on the wire.
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
        // A read timeout, not `.timeout(..)`: the latter bounds the whole
        // streamed response body and so would kill a legitimately long
        // generation, while this one bounds *inactivity between chunks* and
        // resets on every one. Without it a server that accepts the connection
        // and then stalls — or a half-open TCP connection after a laptop
        // suspend, VPN flap or NAT rebind — hangs `stream_chat` forever, with
        // nothing downstream able to notice: there is no cancellation path in
        // this workspace yet, so a non-interactive embedder has no escape.
        // Anthropic sends `ping` frames throughout a turn, so 120s of total
        // silence means the connection is gone, not that the model is thinking.
        //
        // This is still not a per-turn wall-clock bound; that belongs one layer
        // up, wrapping the consumption loop. Do not unify it with sandbx-core's
        // `SandboxedCommand::timeout`: that bounds a local subprocess by
        // SIGKILLing a process group, this would cancel a remote I/O future.
        .read_timeout(std::time::Duration::from_secs(120))
        // The API key travels in an `x-api-key` header, and reqwest's cross-host
        // redirect scrubbing only strips headers it knows are credentials
        // (`Authorization`, `Cookie`, `Proxy-Authorization`), never a custom one.
        // Under the default policy a 3xx from the base URL would replay the key —
        // and, for 307/308, the whole conversation body — to whatever host
        // `Location` names, in cleartext if it says so. The Messages API never
        // legitimately redirects, so refusing outright costs nothing.
        .redirect(reqwest::redirect::Policy::none());

    builder = match reachability {
        // Belt and braces over `validate_base_url`: even if some later code path
        // sets a cleartext URL, the client itself refuses to make the request
        // rather than putting the key on the wire.
        Reachability::PublicHttps => builder.https_only(true),
        // `system-proxy` is enabled, so reqwest honours `HTTP_PROXY` from the
        // environment. For a loopback base URL that is strictly wrong and
        // actively dangerous: an approved `http://127.0.0.1` request would be
        // routed to whatever host the variable names, carrying `x-api-key` in
        // cleartext off the machine. A loopback address needs no proxy by
        // definition, so refuse to use one.
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
/// [`ProviderError::ApiError`], parsed from the vendor's standard
/// `{"type":"error","error":{...}}` envelope where present. Which of those are
/// worth retrying is [`ProviderError::is_retryable`]'s job, so no status
/// comparison is duplicated at a call site.
async fn map_error_response(
    status: reqwest::StatusCode,
    response: reqwest::Response,
) -> ProviderError {
    // Read for every status, not just 429: Anthropic sends `Retry-After` with a
    // 529 too, and a backoff layer holding an `ApiError` needs it just as much.
    // Only the integer-seconds form is parsed — the one Anthropic documents. The
    // HTTP-date form an intermediary might use would need a date parser, and
    // degrades to `None`, which a caller already has to handle.
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
