//! What can stop a subcommand before it has an answer.
//!
//! One module per error, each with its own `Display` and `Error` impls: [`agent`] for a
//! turn, [`run`] for `sandbox-run`, [`hash`] for the digest a pin is taken from.
//! `sandbx_auth::AuthError` covers the credential file and the key read off it, and
//! `sandbx_grants::PolicyError` the flags that described no policy; [`agent`] converts from
//! both.
//!
//! Only [`run`] and [`agent`] carry `From` impls. [`hash`] wraps errors too, but what wraps
//! mostly needs a path or `detail` a conversion cannot know.

mod agent;
mod hash;
mod run;

pub use agent::AgentError;
pub use hash::HashError;
pub use run::SandboxRunError;
