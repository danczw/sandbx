//! Sandboxed execution for sandbx.
//!
//! Every tool an agent runs passes through this crate. It is the only place in
//! the workspace permitted to spawn a subprocess, and even here the permission
//! is per-call-site: four `#[allow(clippy::disallowed_methods)]` annotations,
//! each on a line that re-execs the sandbox helper. `unsafe` is forbidden in
//! this crate exactly as it is in every other one.
//!
//! Two layers, because they cover different things:
//!
//! - [`FsGuard`] checks paths in-process, for tools written in Rust that never
//!   spawn anything and so are never seen by the kernel enforcement.
//! - Kernel enforcement (Landlock, seccomp, namespaces) restricts child
//!   processes. sandbx re-execs a helper which applies the restrictions to
//!   *itself* and then becomes the command, so sandbx is never caged by them.
//!
//! Both are default-deny: see [`SandboxPolicy`].
//!
//! Linux only, and refused at compile time rather than at runtime. Every
//! mechanism here — Landlock, seccomp, the namespaces — is a Linux interface with
//! no equivalent elsewhere, so there is nothing for another platform to fall back
//! *to* except running the command unsandboxed, which is the one outcome this
//! crate exists to prevent. Refusing to build is the strongest form that refusal
//! can take: a binary that could run unsandboxed cannot be produced at all.
//!
//! This replaced a set of per-function stubs that returned
//! [`SandboxError::Unsupported`] on other platforms. They described a build that
//! was never produced — CI is Linux, the shipped targets are Linux — and the crate
//! did not actually compile without them anyway, so they were five things to keep
//! in sync in exchange for nothing.

// Deliberately the whole crate, not a feature or a module: see the note above.
#[cfg(not(target_os = "linux"))]
compile_error!(
    "sandbx-core sandboxes using Landlock, seccomp and Linux namespaces, and has \
     no unsandboxed fallback — it is Linux-only by design. Build for a Linux \
     target, or depend on it only from a Linux-gated target in your manifest."
);

mod audit;
mod command;
mod error;
mod fs_guard;
mod helper;
mod helper_args;
mod policy;

pub use audit::{AUDIT_TARGET, AuditEvent};
pub use command::{
    HELPER_FLAG, HELPER_INNER_FLAG, HelperDispatch, SandboxedCommand, dispatch_helper_mode,
    with_helper_dispatch,
};
pub use error::SandboxError;
pub use fs_guard::FsGuard;
pub use helper::{BLOCKED_SYSCALLS, exit_code};
pub use helper_args::HelperArgs;
pub use policy::{Axis, Grants, SandboxPolicy};
