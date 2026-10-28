//! The one part of [`ProviderError`]'s contract that has to be tested from here: the
//! `reqwest::Error` `Transport` carries is only buildable once a crypto provider is
//! installed, and [`ensure_crypto_provider_installed`] is this crate's. Every other
//! variant is covered by `sandbx-provider`'s own `tests/error.rs` (#366).

use sandbx_anthropic::ensure_crypto_provider_installed;
use sandbx_provider::ProviderError;

fn source_of(error: &ProviderError) -> Option<&(dyn std::error::Error + 'static)> {
    std::error::Error::source(error)
}

/// The one variant carrying an underlying error, the request never having got far
/// enough for a status code or vendor body.
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

/// The only way to get a real `reqwest::Error` without a network call.
fn reqwest_error_for_test() -> reqwest::Error {
    // Building any reqwest::Client panics without a crypto provider installed first.
    ensure_crypto_provider_installed();
    reqwest::Client::new()
        .get("not a url")
        .build()
        .expect_err("a malformed URL must fail to build")
}
