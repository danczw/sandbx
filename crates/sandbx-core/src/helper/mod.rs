//! The two-stage re-exec that turns a plain process into a sandboxed command.
//!
//! [`exec`] holds both stages and the ordered syscall sequence that confines the command;
//! [`hardening`], [`ruleset`] and [`seccomp`] are the three mechanisms it sequences, and
//! [`resolver`] the files it installs for them.

mod exec;
mod hardening;
mod resolver;
mod ruleset;
mod seccomp;

pub use exec::exit_code;
pub(crate) use exec::{AUDIT_STDIN_FLAG, exec_inner, exec_sandboxed};
pub use seccomp::BLOCKED_SYSCALLS;
