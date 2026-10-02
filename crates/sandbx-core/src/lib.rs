//! Sandboxed execution for sandbx.
//!
//! The only place in the workspace permitted to spawn a subprocess, at the single
//! `#[allow(clippy::disallowed_methods)]` in `spawn::command`. Two layers, both
//! default-deny (see [`SandboxPolicy`]): [`FsGuard`] checks paths in-process, for tools
//! written in Rust that never spawn anything and so are never seen by the kernel
//! enforcement; and Landlock, seccomp and namespaces restrict child processes, applied by
//! a re-exec'd helper to *itself* before it becomes the command, so sandbx is never caged
//! by them.

#[cfg(not(target_os = "linux"))]
compile_error!(
    "sandbx-core sandboxes using Landlock, seccomp and Linux namespaces, and has \
     no unsandboxed fallback — it is Linux-only by design. Build for a Linux \
     target, or depend on it only from a Linux-gated target in your manifest."
);

mod audit;
mod command;
mod degradation;
mod error;
mod fs_guard;
mod helper;
mod helper_args;
mod policy;
mod spawn;

pub use audit::{AUDIT_TARGET, AuditEvent};
pub use command::{
    HELPER_FLAG, HELPER_INNER_FLAG, HelperDispatch, SandboxedCommand, dispatch_helper_mode,
    with_helper_dispatch,
};
pub use error::SandboxError;
pub use fs_guard::{FsGuard, ReadableWalk};
pub use helper::{BLOCKED_SYSCALLS, exit_code};
pub use helper_args::HelperArgs;
pub use policy::{Axis, Grants, SandboxPolicy};
