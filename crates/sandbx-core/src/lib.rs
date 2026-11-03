//! Sandboxed execution for sandbx, and the only place any crate's `src/` may spawn a
//! subprocess (`spawn::command`, per the `Command::new` ban in `clippy.toml`). Two
//! default-deny layers (see [`SandboxPolicy`]): [`FsGuard`] checks paths in-process, for
//! Rust tools that never spawn and so are never seen by the kernel; Landlock, seccomp and
//! namespaces restrict children, applied by a re-exec'd helper to itself so sandbx is not.
//!
//! Nothing the sandbox starts outlives the call that started it (#28). The helper's first
//! stage unshares a PID namespace, which places only its children, so its second is PID 1
//! there and stays it: the command is that init's child, and the init's exit is what tears
//! the namespace down. Two independent paths end the init, never the command — the process
//! group kill on a timed run, and the parent death signal when stage 1 dies. The command can
//! shed both from itself, which is why it is not the init.

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
mod error;
mod fs_guard;
mod helper;
mod helper_args;
mod policy;
mod resolver;
mod sha256_digest;
mod spawn;
mod spawn_id;

pub use audit::{AUDIT_TARGET, AuditEvent, Pinning};
pub use command::{
    CommandLine, HELPER_FLAG, HELPER_INNER_FLAG, SandboxedCommand, with_helper_dispatch,
};
pub use concealment::conceal_process_state;
pub use error::{Access, HelperRefusal, SandboxError};
pub use fs_guard::{FsGuard, Listed, Listing, ReadableWalk};
pub use helper::{BLOCKED_SYSCALLS, exit_code};
pub use helper_args::HelperArgs;
pub use policy::{
    Axis, DNS_NAME_LIMIT, GrantedPath, Grants, NAMESERVER_PORT, NetworkPolicy, ObjectId,
    SandboxPolicy, VettedPath,
};
pub use resolver::{RESOLVER_FILES, bound_by_resolver};
pub use sha256_digest::{DigestParseError, Sha256Digest};
pub use spawn_id::SpawnId;
