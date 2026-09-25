//! Sandboxed execution for echo.
//!
//! Every tool an agent runs passes through this crate. It is the only place in
//! the workspace permitted to spawn a subprocess or use `unsafe`; every other
//! crate forbids both at compile time.
//!
//! Two layers, because they cover different things:
//!
//! - [`FsGuard`] checks paths in-process, for tools written in Rust that never
//!   spawn anything and so are never seen by the kernel enforcement.
//! - Kernel enforcement (Landlock, seccomp, namespaces) restricts child
//!   processes. echo re-execs a helper which applies the restrictions to
//!   *itself* and then becomes the command, so echo is never caged by them.
//!
//! Both are default-deny: see [`SandboxPolicy`].

mod audit;
mod command;
mod error;
mod fs_guard;
mod helper;
mod helper_args;
mod policy;
mod support;

pub use audit::{AUDIT_TARGET, AuditEvent};
pub use command::{HELPER_FLAG, SandboxedCommand, dispatch_helper_mode};
pub use error::SandboxError;
pub use fs_guard::FsGuard;
pub use helper::exec_sandboxed;
pub use helper_args::HelperArgs;
pub use policy::SandboxPolicy;
pub use support::KernelSupport;
