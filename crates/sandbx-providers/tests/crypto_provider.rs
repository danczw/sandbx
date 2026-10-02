//! Public contract of [`ensure_crypto_provider_installed`].
//!
//! In `tests/` rather than a `#[cfg(test)] mod tests`, which also exercises the reason
//! the function is `pub`: an integration test is a separate compiled crate, and
//! building any `reqwest::Client` panics without a provider installed first.

use sandbx_providers::ensure_crypto_provider_installed;

/// `install_default()` returns `Err` on a second call, and propagating that would make
/// a second `AnthropicClient` in one process unconstructable.
#[test]
fn installing_the_provider_twice_does_not_panic() {
    ensure_crypto_provider_installed();
    ensure_crypto_provider_installed();
}

/// Not just "doesn't panic": without a usable provider every TLS handshake fails at
/// runtime with no compile-time signal.
#[test]
fn a_provider_is_actually_installed_and_usable() {
    ensure_crypto_provider_installed();
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_some(),
        "no crypto provider installed"
    );
}
