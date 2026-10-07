//! What the harness hides about itself from everything else running as the same user.
//!
//! The one step sandbx takes against its *own* process rather than a sandboxed child's, so
//! it is applied by the binary once at startup and not by the helper — see
//! `helper::hardening`, which explains why the same flag would not survive there.

use crate::SandboxError;

/// Clear this process's dumpable flag, so its own `/proc` entry stops answering a same-uid
/// reader.
///
/// The kernel reparents `/proc/<pid>/` to root, so `environ`, `mem`, `maps` and `fd/` fail
/// `__ptrace_may_access` — which keeps an exported provider key out of a tool granted `/proc`.
/// A same-thread-group read of `fd/` and `exe` stays exempt and one of `environ` does not, so
/// `digest` and the helper re-exec are unaffected while sandbx's own `environ` closes to it too.
pub fn conceal_process_state() -> Result<(), SandboxError> {
    nix::sys::prctl::set_dumpable(false).map_err(|errno| SandboxError::ProcessConcealment {
        detail: format!("could not clear the dumpable flag: {errno}"),
    })
}
