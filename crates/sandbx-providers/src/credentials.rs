use secrecy::SecretString;

use crate::ProviderError;

/// Resolve an API key from an environment variable, wrapping it immediately.
///
/// Takes an injected lookup rather than calling [`std::env::var`] directly:
/// `set_var`/`remove_var` are `unsafe fn` under edition 2024 and this workspace
/// forbids `unsafe_code` in test binaries too, so a test cannot drive it through a
/// real environment.
///
/// A variable that is set but blank is treated as absent, and surrounding
/// whitespace is trimmed off. An unpopulated CI secret yields `Ok("")`, which would
/// otherwise 401 after a round trip; `$(cat key)` keeps a trailing newline, which
/// `HeaderValue` rejects much later as an opaque `Transport` error.
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

/// Resolve the Anthropic API key from `ANTHROPIC_API_KEY`, the only tier of
/// credential resolution built so far.
pub fn anthropic_api_key() -> Result<SecretString, ProviderError> {
    resolve_api_key("ANTHROPIC_API_KEY", |key| std::env::var(key))
}
