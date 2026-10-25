//! What can stop a subcommand before it has an answer.
//!
//! One module per error, each with its own `Display` and `Error` impls: [`agent`] for a
//! turn, [`run`] for `sandbox-run`, [`policy`] for the flags that described no policy,
//! [`hash`] for the one subcommand that confines nothing, [`auth`] for a key that could
//! not be resolved.
//!
//! Only [`run`] and [`agent`] carry `From` impls. The other three wrap errors too, but
//! their wrapping variants mostly need a path or `detail` a conversion cannot know; the two
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
