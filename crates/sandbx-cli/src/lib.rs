//! The `sandbx` command line.
//!
//! Parsing and policy derivation live here, not in `main.rs`, so a unit test can answer
//! what a flag grants on a machine with no sandbox-capable kernel.

mod agent;
mod error;
mod grants;
mod hash;
mod invocation;
mod sandbox;
mod session;

pub use agent::{AgentRun, Tui};
pub use error::{AgentError, HashError, PolicyError, SandboxRunError};
pub use grants::Grants;
pub use hash::Hash;
pub use invocation::{Cli, Command};
pub use sandbox::SandboxRun;
pub use session::SessionChoice;
