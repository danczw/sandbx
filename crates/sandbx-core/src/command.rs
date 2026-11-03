//! Running a command under a policy. [`sandboxed_command`] holds the builder, the audit channel and
//! the deadline — one supervision sequence; [`dispatch`] is the host-side entry into the helper
//! side that does the restricting.

#[path = "command_dispatch.rs"]
pub(crate) mod dispatch;
#[path = "sandboxed_command.rs"]
mod sandboxed_command;

pub use dispatch::{HELPER_FLAG, HELPER_INNER_FLAG, with_helper_dispatch};
pub(crate) use sandboxed_command::self_exe;
pub use sandboxed_command::{CommandLine, SandboxedCommand};
