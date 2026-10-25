//! The `sandbx` command line.
//!
//! Parsing and policy derivation live here, not in `main.rs`, so a unit test can answer
//! what a flag grants on a machine with no sandbox-capable kernel.

mod agent;
mod auth;
mod error;
mod grants;
mod hash;
mod invocation;
pub mod logging;
mod sandbox;
mod session;

pub use agent::{AgentRun, Tui};
pub use auth::Auth;
pub use error::{AgentError, AuthError, HashError, PolicyError, SandboxRunError};
pub use grants::Grants;
pub use hash::Hash;
pub use invocation::{Cli, Command};
pub use sandbox::SandboxRun;
pub use session::SessionChoice;
