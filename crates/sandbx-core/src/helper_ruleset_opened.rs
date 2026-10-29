//! Opening a granted path, and confirming it is the grant that was vetted.
//!
//! The policy is judged in the harness and the rules are opened here, so between the two a
//! symlink can be redirected: the grant the operator vetted and the directory the kernel is
//! told about would be different ones (#205). A `rename(2)` does the same without a symlink,
//! leaving the spelling identical, so the two questions are asked separately (#212).

use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;

use landlock::PathFd;

use super::rights::RuleTarget;
use crate::{ObjectId, SandboxError};

/// `granted`, opened, having confirmed that it opened as the object it was vetted as.
///
/// The one way this crate gets a [`PathFd`], so neither confirmation can be skipped by adding
/// a rule somewhere else.
///
/// After this the window is closed rather than narrowed: [`PathBeneath`] holds the descriptor,
/// so the kernel attaches the rule to that inode and a later rename moves the name and not the
/// rule.
///
/// [`PathBeneath`]: landlock::PathBeneath
pub(in crate::helper) fn open_grant(target: &RuleTarget<'_>) -> Result<PathFd, SandboxError> {
    // `O_PATH | O_CLOEXEC` and no `O_NOFOLLOW`, so every component is followed and the
    // descriptor may name an inode no part of this spelling pointed at when it was vetted.
    let fd = PathFd::new(target.path()).map_err(super::landlock_failed)?;

    // The spellings first: it is the cheap check, and it is the one whose refusal can say what
    // was substituted for what. It applies to both kinds — an installed path redirected under
    // the bind is still a rule on an inode sandbx did not place.
    let opened = reads_back(&fd)?;
    if opened != target.path() {
        return Err(SandboxError::GrantRedirected {
            granted: target.path().to_path_buf(),
            opened,
        });
    }

    // Only a grant has a second answer to check against. `Installed` has none that would mean
    // anything: the object was made in this process, so a pin taken here would be this
    // process agreeing with itself.
    let RuleTarget::Granted(granted) = target else {
        return Ok(fd);
    };

    let object = ObjectId::of_fd(&fd)?;
    if object != granted.object() {
        return Err(SandboxError::GrantReplaced {
            granted: granted.path().to_path_buf(),
            vetted: granted.object(),
            opened: object,
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
    // check turns on, so sandbx's own clearing of it (`concealment`) does not reach this stage.
    let link = format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd());

    // Not `GrantRedirected`, which would claim to know where the grant went: a sandbox whose
    // rules cannot be confirmed is one this kernel will not enforce, so it refuses as that.
    std::fs::read_link(&link).map_err(|_| SandboxError::Unsupported {
        detail: "a granted path could not be read back through /proc/self/fd, so it cannot be \
                 confirmed to be the path that was opened",
    })
}
