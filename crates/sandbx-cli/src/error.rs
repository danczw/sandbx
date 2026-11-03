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

#[path = "agent_error.rs"]
mod agent_error;
#[path = "hash_error.rs"]
mod hash_error;
#[path = "sandbox_run_error.rs"]
mod sandbox_run_error;

pub use agent_error::AgentError;
pub use hash_error::HashError;
pub use sandbox_run_error::SandboxRunError;
