use secrecy::SecretString;

use crate::ProviderError;

/// Resolve an API key from an environment variable, wrapping it immediately.
///
/// The lookup is injected because `set_var`/`remove_var` are `unsafe fn` under
/// edition 2024 and this workspace forbids `unsafe_code` in test binaries too, so a
/// test cannot drive a real environment.
///
/// A set-but-blank variable counts as absent and whitespace is trimmed: an
/// unpopulated CI secret yields `Ok("")`, and `$(cat key)` keeps a trailing newline
/// that `HeaderValue` rejects much later as an opaque `Transport` error.
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
pub fn anthropic_api_key() -> Result<SecretString, ProviderError> {
    resolve_api_key("ANTHROPIC_API_KEY", |key| std::env::var(key))
}
