//! Public contract of [`ProviderError`].
//!
//! Every variant's `Display` must render something a user or log line can act on, and
//! `source()` must be wired only where a variant carries an underlying error.

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

/// The request never got far enough for a status code or vendor error body, so this is
/// the only variant whose `source()` points at anything.
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
        retry_after: None,
    };

    let rendered = error.to_string();
    assert!(rendered.contains("400"));
    assert!(rendered.contains("invalid_request_error"));
    assert!(rendered.contains("model field is required"));
    assert!(source_of(&error).is_none());
}

/// `status: None` is how an in-band SSE `error` event, which carries no status code of
/// its own, is distinguished from an HTTP-level failure.
#[test]
fn api_error_without_a_status_still_reports_the_body() {
    let error = ProviderError::ApiError {
        status: None,
        kind: "overloaded_error".to_string(),
        message: "the API is temporarily overloaded".to_string(),
        retry_after: None,
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
fn stream_ended_unexpectedly_renders() {
    let error = ProviderError::StreamEndedUnexpectedly;

    assert!(!error.to_string().is_empty());
    assert!(source_of(&error).is_none());
}

/// `InvalidBaseUrl` is hit before any I/O, so its `Display` has to name the offending
/// URL *and* say what was wrong with it.
#[test]
fn invalid_base_url_reports_the_url_and_reason() {
    let error = ProviderError::InvalidBaseUrl {
        base_url: "ftp://example.com".to_string(),
        reason: "scheme must be https",
    };

    let rendered = error.to_string();
    assert!(rendered.contains("ftp://example.com"));
    assert!(rendered.contains("scheme must be https"));
    assert!(source_of(&error).is_none());
}

/// A retry loop classifies by these two accessors rather than by matching the enum, so
/// the classification is part of the public contract.
#[test]
fn transient_is_retryable_client_error_is_not() {
    let overloaded_http = ProviderError::ApiError {
        status: Some(529),
        kind: "overloaded_error".to_string(),
        message: "overloaded".to_string(),
        retry_after: None,
    };
    let overloaded_in_band = ProviderError::ApiError {
        status: None,
        kind: "overloaded_error".to_string(),
        message: "overloaded".to_string(),
        retry_after: None,
    };
    let bad_request = ProviderError::ApiError {
        status: Some(400),
        kind: "invalid_request_error".to_string(),
        message: "bad model".to_string(),
        retry_after: None,
    };
    let not_authorized = ProviderError::ApiError {
        status: None,
        kind: "authentication_error".to_string(),
        message: "bad key".to_string(),
        retry_after: None,
    };

    assert!(overloaded_http.is_retryable(), "5xx is transient");
    assert!(
        overloaded_in_band.is_retryable(),
        "an in-band overloaded_error carries no status but is still transient"
    );
    assert!(
        !bad_request.is_retryable(),
        "4xx will fail again identically"
    );
    assert!(
        !not_authorized.is_retryable(),
        "a bad key does not fix itself"
    );

    assert!(
        ProviderError::RateLimited {
            retry_after: None,
            message: "slow down".to_string(),
        }
        .is_retryable()
    );
    assert!(
        ProviderError::Transport {
            detail: "connection reset".to_string(),
            source: reqwest_error_for_test(),
        }
        .is_retryable()
    );
    assert!(
        !ProviderError::MissingCredential {
            env_var: "ANTHROPIC_API_KEY",
        }
        .is_retryable(),
        "no amount of retrying conjures a credential"
    );
    assert!(
        !ProviderError::MalformedEvent {
            detail: "bad frame".to_string(),
        }
        .is_retryable(),
        "a parse bug is ours, not the server's"
    );
}

/// A 429's `Retry-After` and a 5xx's are surfaced through one accessor, so a retry loop
/// need not know which variant it holds.
#[test]
fn retry_after_is_exposed_from_both_carrying_variants() {
    let two_secs = std::time::Duration::from_secs(2);

    assert_eq!(
        ProviderError::RateLimited {
            retry_after: Some(two_secs),
            message: "slow down".to_string(),
        }
        .retry_after(),
        Some(two_secs)
    );
    assert_eq!(
        ProviderError::ApiError {
            status: Some(529),
            kind: "overloaded_error".to_string(),
            message: "overloaded".to_string(),
            retry_after: Some(two_secs),
        }
        .retry_after(),
        Some(two_secs)
    );
    assert_eq!(
        ProviderError::StreamEndedUnexpectedly.retry_after(),
        None,
        "a variant that cannot carry a hint must not invent one"
    );
}

/// The only way to get a real `reqwest::Error` without a network call.
fn reqwest_error_for_test() -> reqwest::Error {
    // Building any reqwest::Client panics without a crypto provider installed first.
    sandbx_providers::ensure_crypto_provider_installed();
    reqwest::Client::new()
        .get("not a url")
        .build()
        .expect_err("a malformed URL must fail to build")
}
