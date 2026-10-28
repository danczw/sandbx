//! Public contract of [`ProviderError`]: every variant's `Display` renders something
//! actionable, and `source()` is wired only where a variant carries one.
//!
//! `Transport` is tested from `sandbx-anthropic` instead: building the real
//! `reqwest::Error` it carries needs a crypto provider installed, and the function that
//! installs one stayed there (#366).

use sandbx_provider::ProviderError;

fn source_of(error: &ProviderError) -> Option<&(dyn std::error::Error + 'static)> {
    std::error::Error::source(error)
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

/// `status: None` is what separates an in-band SSE `error` event, which carries no
/// status code, from an HTTP-level failure.
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
fn stream_ended_unexpectedly_renders() {
    let error = ProviderError::StreamEndedUnexpectedly;

    assert!(!error.to_string().is_empty());
    assert!(source_of(&error).is_none());
}

/// Hit before any I/O, so the message is all the operator gets: the URL and the rule.
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
