//! The `sandbx` command line.
//!
//! Parsing lives here, not in `main.rs`, so a unit test can answer what a subcommand does on
//! a machine with no sandbox-capable kernel. Deriving a policy from the flags is
//! `sandbx-grants`, whose `Grants` every subcommand that confines something flattens.

mod agent;
mod cli;
mod error;
mod hash;
mod sandbox_run;

pub use agent::{AgentRun, Tui};
pub use cli::{Cli, Command};
pub use error::{AgentError, HashError, SandboxRunError, error_line};
pub use hash::Hash;
pub use sandbox_run::SandboxRun;

// Both are in this crate's surface: `Grants` flattened into `SandboxRun` and `AgentRun`,
// `PolicyError` their errors' `Policy` variant, which the integration tests match on.
pub use sandbx_grants::{Grants, PolicyError};
// `AgentRun::session` returns one and a caller matches on its variants. The other foreign
// types in this surface are displayed or passed along, never destructured, so they stay
// spelled by their own crates (#351).
pub use sandbx_session_bridge::SessionChoice;
