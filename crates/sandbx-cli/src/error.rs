//! What can stop a subcommand before it has an answer.
//!
//! One module per error, each with its own `Display` and `Error` impls: [`agent_error`] for
//! a turn, [`sandbox_run_error`] for `sandbox-run`, [`hash_error`] for the digest a pin is
//! taken from. `sandbx_auth::AuthError` covers the credential file and the key read off it,
//! and `sandbx_grants::PolicyError` the flags that described no policy; [`agent_error`]
//! converts from both.
//!
//! Only [`sandbox_run_error`] and [`agent_error`] carry `From` impls. [`hash_error`] wraps
//! errors too, but what wraps mostly needs a path or `detail` a conversion cannot know.

use std::error::Error;

#[path = "agent_error.rs"]
mod agent_error;
#[path = "hash_error.rs"]
mod hash_error;
#[path = "sandbox_run_error.rs"]
mod sandbox_run_error;

pub use agent_error::AgentError;
pub use hash_error::HashError;
pub use sandbox_run_error::SandboxRunError;

/// `error` and every cause below it, each joined to the last by `: `.
///
/// Every sandbx error already writes its source into its own message, so a link is
/// printed only when its parent's did not include it. That check is against the parent
/// and not the line so far, so a short cause is not hidden by unrelated text above it.
/// What this adds is the foreign links: reqwest's message names only the URL, and the
/// DNS failure, the refused connection or the rejected certificate sits below it (#457).
///
/// The walk follows `source()` and nothing else, so an error that withholds a cause
/// keeps it withheld — `AuthError::Malformed` has none because toml's quotes the key.
#[must_use]
pub fn error_line(error: &dyn Error) -> String {
    let mut line = error.to_string();
    let mut parent = line.clone();
    let mut cause = error.source();
    while let Some(link) = cause {
        let text = link.to_string();
        if !parent.contains(&text) {
            line.push_str(": ");
            line.push_str(&text);
        }
        parent = text;
        cause = link.source();
    }
    line
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
