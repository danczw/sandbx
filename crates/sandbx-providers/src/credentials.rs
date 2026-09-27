use secrecy::SecretString;

use crate::ProviderError;

/// Resolve an API key from an environment variable, wrapping it immediately.
///
/// Takes an injected lookup rather than calling [`std::env::var`] directly so
/// tests can exercise both the present and absent cases without touching the
/// real environment — `std::env::set_var`/`remove_var` are `unsafe fn` under
/// edition 2024, and this workspace forbids `unsafe_code` everywhere,
/// including in test binaries, so a test cannot set a real env var to drive
/// this function even if it wanted to.
pub fn resolve_api_key(
    env_var: &'static str,
    lookup: impl Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<SecretString, ProviderError> {
    lookup(env_var)
        .map(SecretString::from)
        .map_err(|_| ProviderError::MissingCredential { env_var })
}

/// Resolve the Anthropic API key from `ANTHROPIC_API_KEY`.
///
/// Only tier of credential resolution built so far — the OS-keyring and
/// permissioned-file fallbacks PLAN.md describes are deferred to the phase
/// that builds `sandbx auth login`/`set`, since nothing else would call them
/// yet.
pub fn anthropic_api_key() -> Result<SecretString, ProviderError> {
    resolve_api_key("ANTHROPIC_API_KEY", |key| std::env::var(key))
}
