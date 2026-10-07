//! Opening a granted path, and confirming it is the path that was granted.
//!
//! The policy is judged in the harness and the rules are opened here, so between the two a
//! symlink can be redirected: the grant the operator vetted and the directory the kernel is
//! told about would be different ones (#205).

use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};

use landlock::PathFd;

use crate::SandboxError;

/// `path`, opened, having confirmed that it opened as itself.
///
/// The one way this crate gets a [`PathFd`], so the confirmation cannot be skipped by adding a
/// rule somewhere else.
pub(in crate::helper) fn open_grant(path: &Path) -> Result<PathFd, SandboxError> {
    // `O_PATH | O_CLOEXEC` and no `O_NOFOLLOW`, so every component is followed and the
    // descriptor may name an inode no part of this spelling pointed at when it was vetted.
    let fd = PathFd::new(path).map_err(super::landlock_failed)?;
    let opened = reads_back(&fd)?;

    if opened != path {
        return Err(SandboxError::GrantRedirected {
            granted: path.to_path_buf(),
            opened,
        });
    }

    Ok(fd)
}

/// The path `fd` actually names, as the kernel spells it.
///
/// A comparison of spellings, so it holds only while a granted path spells the same here as
/// it did in the harness. A `pivot_root`, an `MS_MOVE` over a granted root, or a bind whose
/// source is unlinked (`read_link` then appends `" (deleted)"`) makes every grant read back as
/// something else, refusing the run under a label that names the grant and not the mount that
/// moved it.
fn reads_back(fd: &PathFd) -> Result<PathBuf, SandboxError> {
    // A task may always read its own `fd/`, `proc_fd_permission` exempting a same-thread-group
    // reader from `__ptrace_may_access`. Independently, `execve` resets the dumpable flag that
    // check turns on, so neither sandbx's own clearing of it (`concealment`) nor the
    // supervisor's reaches this stage.
    let link = format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd());

    // Not `GrantRedirected`, which would claim to know where the grant went: a sandbox whose
    // rules cannot be confirmed is one this kernel will not enforce, so it refuses as that.
    std::fs::read_link(&link).map_err(|_| SandboxError::Unsupported {
        detail: "a granted path could not be read back through /proc/self/fd, so it cannot be \
                 confirmed to be the path that was opened",
    })
}
