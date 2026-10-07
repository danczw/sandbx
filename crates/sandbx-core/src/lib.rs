//! Sandboxed execution for sandbx, and the only place any crate's `src/` may spawn a
//! subprocess — `spawn::command`, per the `Command::new` ban in `clippy.toml`.
//!
//! Two default-deny layers (see [`SandboxPolicy`]): [`FsGuard`] checks paths in-process, for
//! Rust tools that never spawn and so are never seen by the kernel; Landlock, seccomp and
//! namespaces restrict children, applied by a re-exec'd helper to itself so sandbx is not.

#[cfg(not(target_os = "linux"))]
compile_error!(
    "sandbx-core sandboxes using Landlock, seccomp and Linux namespaces, and has \
     no unsandboxed fallback — it is Linux-only by design. Build for a Linux \
     target, or depend on it only from a Linux-gated target in your manifest."
);

mod audit;
mod command;
mod concealment;
mod degradation;
mod digest;
mod error;
mod fs_guard;
mod helper;
mod helper_args;
mod policy;
mod resolver;
mod spawn;

pub use audit::{AUDIT_TARGET, AuditEvent};
pub use command::{
    HELPER_FLAG, HELPER_INNER_FLAG, HelperDispatch, SandboxedCommand, dispatch_helper_mode,
    with_helper_dispatch,
};
pub use concealment::conceal_process_state;
pub use digest::{DigestParseError, Sha256Digest};
pub use error::{Access, HelperRefusal, SandboxError};
pub use fs_guard::{FsGuard, ReadableWalk};
pub use helper::{BLOCKED_SYSCALLS, exit_code};
pub use helper_args::HelperArgs;
pub use policy::{Axis, DNS_NAME_LIMIT, Grants, NAMESERVER_PORT, NetworkPolicy, SandboxPolicy};
pub use resolver::RESOLVER_FILES;
