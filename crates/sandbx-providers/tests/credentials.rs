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

/// A copy-paste out of a dashboard, or a `.env` file with a trailing newline,
/// produces exactly this. Trimming means the worst case is a clean 401, not a
/// malformed header.
#[test]
fn surrounding_whitespace_is_trimmed_off_the_key() {
    let key = sandbx_providers::resolve_api_key("SOME_VAR", |_| Ok("  sk-ant-test\n".to_string()))
        .expect("a padded var must still resolve");

    use secrecy::ExposeSecret;
    assert_eq!(key.expose_secret(), "sk-ant-test");
}

/// `ANTHROPIC_API_KEY=` in a shell profile leaves the variable *present* and
/// empty, which `std::env::var` reports as `Ok("")`. Treating that as resolved
/// would send an empty `x-api-key` header and surface as a confusing 401 instead
/// of the actionable "set ANTHROPIC_API_KEY".
#[test]
fn an_empty_value_is_reported_as_missing() {
    let error = sandbx_providers::resolve_api_key("ANTHROPIC_API_KEY", |_| Ok(String::new()))
        .expect_err("an empty var must not resolve");

    match error {
        ProviderError::MissingCredential { env_var } => assert_eq!(env_var, "ANTHROPIC_API_KEY"),
        other => panic!("expected MissingCredential, got {other:?}"),
    }
}

#[test]
fn a_whitespace_only_value_is_reported_as_missing_too() {
    let error = sandbx_providers::resolve_api_key("ANTHROPIC_API_KEY", |_| Ok(" \t\n".to_string()))
        .expect_err("a blank var must not resolve");

    assert!(matches!(error, ProviderError::MissingCredential { .. }));
}

#[test]
fn anthropic_api_key_names_the_right_env_var() {
    // anthropic_api_key() reads the real environment, and must not mutate it to
    // force the failure path (env::set_var is unsafe under edition 2024) — so
    // which branch runs depends on what is already set.
    //
    // The probe is for a *usable* key, not merely a present one: gating on `Ok`
    // would skip the assertion under `ANTHROPIC_API_KEY=`, exactly the
    // environment where the blank-rejection above matters most.
    let a_real_key_is_set =
        std::env::var("ANTHROPIC_API_KEY").is_ok_and(|value| !value.trim().is_empty());
    if a_real_key_is_set {
        assert!(
            sandbx_providers::anthropic_api_key().is_ok(),
            "a non-blank key in the environment must resolve"
        );
        return;
    }

    let error = sandbx_providers::anthropic_api_key().expect_err("no usable key is set here");
    match error {
        ProviderError::MissingCredential { env_var } => assert_eq!(env_var, "ANTHROPIC_API_KEY"),
        other => panic!("expected MissingCredential, got {other:?}"),
    }
}
