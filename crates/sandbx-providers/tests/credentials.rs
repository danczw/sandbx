//! Public contract of Anthropic API key resolution.
//!
//! `std::env::set_var`/`remove_var` are `unsafe fn` under edition 2024, and
//! this workspace forbids `unsafe_code` everywhere, including in integration
//! test binaries like this one. So resolution takes an injected lookup
//! closure rather than reading the real environment directly — these tests
//! exercise that closure, never a real environment mutation.

use sandbx_providers::ProviderError;

#[test]
fn resolves_the_key_when_the_lookup_finds_one() {
    let key = sandbx_providers::resolve_api_key("SOME_VAR", |_| Ok("sk-ant-test".to_string()))
        .expect("a present var must resolve");

    use secrecy::ExposeSecret;
    assert_eq!(key.expose_secret(), "sk-ant-test");
}

#[test]
fn reports_which_env_var_was_missing() {
    let error = sandbx_providers::resolve_api_key("ANTHROPIC_API_KEY", |_| {
        Err(std::env::VarError::NotPresent)
    })
    .expect_err("an absent var must not resolve");

    match error {
        ProviderError::MissingCredential { env_var } => assert_eq!(env_var, "ANTHROPIC_API_KEY"),
        other => panic!("expected MissingCredential, got {other:?}"),
    }
}

/// Non-UTF-8 environment values are also `VarError`, and get the same
/// treatment as absent — there is no useful distinction to surface to a
/// caller deciding whether to prompt for a key.
#[test]
fn reports_a_non_utf8_value_as_missing_too() {
    let error = sandbx_providers::resolve_api_key("ANTHROPIC_API_KEY", |_| {
        Err(std::env::VarError::NotUnicode(Default::default()))
    })
    .expect_err("a non-UTF-8 var must not resolve");

    assert!(matches!(error, ProviderError::MissingCredential { .. }));
}

#[test]
fn anthropic_api_key_names_the_right_env_var() {
    // anthropic_api_key() reads the real environment, but only to name the
    // var — it cannot be made to succeed without a real key set on this
    // machine, and must not mutate the real environment to force the failure
    // path (env::set_var is unsafe under edition 2024). So only the case where
    // this dev machine happens not to have one set is asserted.
    if std::env::var("ANTHROPIC_API_KEY").is_ok() {
        return; // a real key is set here; nothing to assert either way
    }

    let error = sandbx_providers::anthropic_api_key().expect_err("no key is set here");
    match error {
        ProviderError::MissingCredential { env_var } => assert_eq!(env_var, "ANTHROPIC_API_KEY"),
        other => panic!("expected MissingCredential, got {other:?}"),
    }
}
