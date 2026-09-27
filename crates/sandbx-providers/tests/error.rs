//! Public contract of [`ProviderError`].
//!
//! Every variant's `Display` must render something a user or log line can act
//! on, and `source()` must be wired only where a variant actually carries an
//! underlying error — mirroring `SandboxError`'s contract in sandbx-core.

use sandbx_providers::ProviderError;

fn source_of(error: &ProviderError) -> Option<&(dyn std::error::Error + 'static)> {
    std::error::Error::source(error)
}

#[test]
fn missing_credential_names_the_env_var() {
    let error = ProviderError::MissingCredential {
        env_var: "ANTHROPIC_API_KEY",
    };

    assert!(error.to_string().contains("ANTHROPIC_API_KEY"));
    assert!(source_of(&error).is_none());
}

/// Distinct from `ApiError`: the request never got far enough to receive a
/// status code or vendor error body, so this is the only variant whose
/// `source()` points at anything.
#[test]
fn transport_carries_its_source() {
    let reqwest_error = reqwest_error_for_test();

    let error = ProviderError::Transport {
        detail: "sending request".to_string(),
        source: reqwest_error,
    };

    assert!(error.to_string().contains("sending request"));
    assert!(
        source_of(&error).is_some(),
        "Transport must expose its source"
    );
}

#[test]
fn api_error_with_a_status_reports_it() {
    let error = ProviderError::ApiError {
        status: Some(400),
        kind: "invalid_request_error".to_string(),
        message: "model field is required".to_string(),
    };

    let rendered = error.to_string();
    assert!(rendered.contains("400"));
    assert!(rendered.contains("invalid_request_error"));
    assert!(rendered.contains("model field is required"));
    assert!(source_of(&error).is_none());
}

/// `status: None` is how an in-band SSE `error` event is distinguished from an
/// HTTP-level failure — it carries no status code of its own.
#[test]
fn api_error_without_a_status_still_reports_the_body() {
    let error = ProviderError::ApiError {
        status: None,
        kind: "overloaded_error".to_string(),
        message: "the API is temporarily overloaded".to_string(),
    };

    let rendered = error.to_string();
    assert!(rendered.contains("overloaded_error"));
    assert!(rendered.contains("temporarily overloaded"));
    assert!(!rendered.contains("400"), "should not fabricate a status");
}

#[test]
fn rate_limited_reports_the_retry_after_when_present() {
    let error = ProviderError::RateLimited {
        retry_after: Some(std::time::Duration::from_secs(2)),
        message: "too many requests".to_string(),
    };

    assert!(error.to_string().contains("2s"));
    assert!(source_of(&error).is_none());
}

#[test]
fn rate_limited_without_a_retry_after_still_renders() {
    let error = ProviderError::RateLimited {
        retry_after: None,
        message: "too many requests".to_string(),
    };

    assert!(error.to_string().contains("too many requests"));
}

#[test]
fn malformed_event_reports_the_detail() {
    let error = ProviderError::MalformedEvent {
        detail: "non-UTF-8 SSE line".to_string(),
    };

    assert!(error.to_string().contains("non-UTF-8 SSE line"));
    assert!(source_of(&error).is_none());
}

#[test]
fn stream_ended_unexpectedly_renders_without_panicking() {
    let error = ProviderError::StreamEndedUnexpectedly;

    assert!(!error.to_string().is_empty());
    assert!(source_of(&error).is_none());
}

/// The only way to get a real `reqwest::Error` without a network call: ask a
/// client to build a request against a URL it cannot parse.
fn reqwest_error_for_test() -> reqwest::Error {
    // Building any reqwest::Client panics without a crypto provider installed
    // first — see `ensure_crypto_provider_installed`'s doc comment.
    sandbx_providers::ensure_crypto_provider_installed();
    reqwest::Client::new()
        .get("not a url")
        .build()
        .expect_err("a malformed URL must fail to build")
}
