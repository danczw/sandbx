//! Running a command under a policy. [`run`] holds the builder, the audit channel and the
//! deadline — one supervision sequence; [`dispatch`] is the host-side entry into the helper
//! side that does the restricting.

pub(crate) mod dispatch;
mod run;

pub use dispatch::{HELPER_FLAG, HELPER_INNER_FLAG, with_helper_dispatch};
pub use run::SandboxedCommand;
pub(crate) use run::self_exe;
