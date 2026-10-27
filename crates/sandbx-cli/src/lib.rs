//! The `sandbx` command line.
//!
//! Parsing lives here, not in `main.rs`, so a unit test can answer what a subcommand does on
//! a machine with no sandbox-capable kernel. Deriving a policy from the flags is
//! `sandbx-grants`, whose `Grants` every subcommand that confines something flattens.

mod agent;
mod error;
mod hash;
mod invocation;
mod sandbox;

pub use agent::{AgentRun, Tui};
pub use error::{AgentError, HashError, SandboxRunError};
pub use hash::Hash;
pub use invocation::{Cli, Command};
pub use sandbox::SandboxRun;

pub use sandbx_grants::{Grants, PolicyError};
