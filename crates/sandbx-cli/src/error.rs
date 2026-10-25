//! What can stop a subcommand before it has an answer.
//!
//! One module per error, each with its own `Display` and `Error` impls: [`agent`] for a
//! turn, [`run`] for `sandbox-run`, [`policy`] for the flags that described no policy,
//! [`hash`] for the digest a pin is taken from, [`auth`] for the credential file
//! and the key read off it.
//!
//! Only [`run`] and [`agent`] carry `From` impls. The other three wrap errors too, but
//! what wraps mostly needs a path or `detail` a conversion cannot know; the two
//! newtype variants in [`auth`] that would not are constructed explicitly anyway.

mod agent;
mod auth;
mod hash;
mod policy;
mod run;

pub use agent::AgentError;
pub use auth::AuthError;
pub use hash::HashError;
pub use policy::PolicyError;
pub use run::SandboxRunError;
