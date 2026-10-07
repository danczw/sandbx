//! What the harness hides about itself from everything else running as the same user.
//!
//! The one step sandbx takes against its *own* process rather than a sandboxed child's, so
//! it is applied by the binary once at startup and not by the helper — see
//! `helper::hardening`, which explains why the same flag would not survive there.

use crate::SandboxError;

/// Clear this process's dumpable flag, so its own `/proc` entry stops answering a same-uid
/// reader.
///
/// With the flag clear the kernel reparents `/proc/<pid>/` to root and `environ`, `mem`,
/// `maps` and `fd/` fail `__ptrace_may_access`, which is what keeps an exported provider key
/// out of a tool granted `/proc`. The cost is a core dump of sandbx and a same-uid debugger
/// attach to it; a failure is a refusal, since what fails is the concealment itself.
pub fn conceal_process_state() -> Result<(), SandboxError> {
    nix::sys::prctl::set_dumpable(false).map_err(|errno| SandboxError::ProcessConcealment {
        detail: format!("could not clear the dumpable flag: {errno}"),
    })
}
