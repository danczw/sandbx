//! Public contract of [`ensure_crypto_provider_installed`].
//!
//! Here rather than in a `#[cfg(test)] mod tests` inside `src/lib.rs`: the item
//! is `pub`, and this crate's siblings test public surface exclusively from
//! `tests/`. It also exercises the reason the function is `pub` at all — an
//! integration test is a separate compiled crate, and building any
//! `reqwest::Client` panics without a provider installed first.

use sandbx_providers::ensure_crypto_provider_installed;

/// Calling this more than once — e.g. constructing a second `AnthropicClient`
/// in the same process — must not panic. A naive `install_default()` without
/// the `Once` guard returns `Err` on a second call, and propagating or
/// panicking on that would make a second client unconstructable for no reason.
#[test]
fn installing_the_provider_twice_does_not_panic() {
    ensure_crypto_provider_installed();
    ensure_crypto_provider_installed();
}

/// Not just "doesn't panic": a provider must actually be installed and usable,
/// or every TLS handshake this crate ever makes would fail at runtime with no
/// compile-time signal.
#[test]
fn a_provider_is_actually_installed_and_usable() {
    ensure_crypto_provider_installed();
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_some(),
        "no crypto provider installed"
    );
}
