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
///
/// A variable that is set but blank is treated as absent, and surrounding
/// whitespace is trimmed off the key. An unpopulated CI secret or `docker run -e
/// ANTHROPIC_API_KEY` yields `Ok("")`, which would otherwise send an empty
/// `x-api-key` and 401 after a network round trip; `export
/// ANTHROPIC_API_KEY=$(cat key)` keeps a trailing newline, which `HeaderValue`
/// rejects much later as an opaque `Transport` error naming nothing. Both are
/// configuration problems, so both get the one error that says what to fix.
pub fn resolve_api_key(
    env_var: &'static str,
    lookup: impl Fn(&str) -> Result<String, std::env::VarError>,
) -> Result<SecretString, ProviderError> {
    let value = lookup(env_var).map_err(|_| ProviderError::MissingCredential { env_var })?;
    let key = value.trim();
    if key.is_empty() {
        return Err(ProviderError::MissingCredential { env_var });
    }
    Ok(SecretString::from(key.to_string()))
}

/// Resolve the Anthropic API key from `ANTHROPIC_API_KEY`.
///
/// Only tier of credential resolution built so far; the OS-keyring and
/// permissioned-file fallbacks PLAN.md describes are deferred to the phase that
/// builds `sandbx auth login`/`set`.
pub fn anthropic_api_key() -> Result<SecretString, ProviderError> {
    resolve_api_key("ANTHROPIC_API_KEY", |key| std::env::var(key))
}
