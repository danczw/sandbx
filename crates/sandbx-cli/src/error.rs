//! What can stop a subcommand before it has an answer.
//!
//! One module per error, each with its own `Display` and `Error` impls: [`agent`] for a
//! turn, [`run`] for `sandbox-run`, [`policy`] for the flags that described no policy,
//! [`hash`] for the digest a pin is taken from. `sandbx_auth::AuthError` covers the
//! credential file and the key read off it, and [`agent`] converts from it.
//!
//! Only [`run`] and [`agent`] carry `From` impls. The other two wrap errors too, but
//! what wraps mostly needs a path or `detail` a conversion cannot know.

mod agent;
mod hash;
mod policy;
mod run;

pub use agent::AgentError;
pub use hash::HashError;
pub use policy::PolicyError;
pub use run::SandboxRunError;
