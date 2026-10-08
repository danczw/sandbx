//! Who may read a file, and whether it is the file that was checked.
//!
//! The modes the store creates with, the flag that keeps a leaf from being a link, and
//! the one way a mode or an owner is read. Which bit refuses and which only reports
//! stays with the sequence that applies it.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::{SessionError, SessionId};

/// The mode a transcript is created with.
pub(super) const OWNER_ONLY: u32 = 0o600;

/// The mode the directory holding them is created with.
pub(super) const DIR_OWNER_ONLY: u32 = 0o700;

/// The bits that let somebody else write, which refuse a resume.
///
/// Split from [`READABLE_BITS`], not shared with `auth/store.rs`'s `SHARED_BITS`: a leaked
/// credential rotates and a conversation does not; see `context/decision-on-disk-state.md`.
pub(super) const WRITABLE_BITS: u32 = 0o022;

/// The bits that let somebody else read, which resume and report.
pub(super) const READABLE_BITS: u32 = 0o044;

/// Every bit outside the owner's, which the root is narrowed to shed.
///
/// Wider than [`WRITABLE_BITS`]: a transcript's name is clock-derived and so guessable,
/// and group/other execute alone lets somebody else traverse to it.
pub(super) const DIR_SHARED_BITS: u32 = 0o077;

/// `O_NOFOLLOW`, so the leaf of a path this store vets is never a symbolic link. The
/// last component only: a symlinked `~/.local/state` is the operator's business.
fn no_follow() -> i32 {
    nix::fcntl::OFlag::O_NOFOLLOW.bits()
}

/// Translate an open failure, naming a link that [`no_follow`] refused.
///
/// By errno, not `ErrorKind::FilesystemLoop`, which is unstable. `ELOOP` from these
/// opens can only be the leaf, every component above it having been followed.
pub(super) fn opening(path: &Path, source: std::io::Error) -> SessionError {
    if source.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32) {
        return SessionError::Symlink {
            path: path.to_owned(),
        };
    }

    SessionError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Open the directory holding transcripts, refusing one that is a symbolic link.
///
/// [`narrow_root`](super::SessionStore::narrow_root) `fchmod`s this descriptor, so
/// following a link would narrow a directory outside the store. No `O_DIRECTORY`: with
/// `O_NOFOLLOW` the kernel reports a symlinked directory as `ENOTDIR`, as it does a root
/// that is a plain file, and the two are worth telling apart.
pub(super) fn open_root(root: &Path) -> Result<File, SessionError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(no_follow())
        .open(root)
        .map_err(|source| opening(root, source))
}

/// Open a transcript, refusing one that is a symbolic link: the mode and owner would
/// come from the target, the vetted directory from where the link sits.
pub(super) fn open_transcript(path: &Path, id: &SessionId) -> Result<File, SessionError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(no_follow())
        .open(path)
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                return SessionError::NotFound { id: id.clone() };
            }

            opening(path, source)
        })
}

/// Reopen a vetted transcript for appending. `O_NOFOLLOW` again, not just on the read:
/// a link planted between the two opens would make the appended-to file a different one
/// than the vetted descriptor.
pub(super) fn reopen_for_append(path: &Path) -> Result<File, SessionError> {
    OpenOptions::new()
        .append(true)
        .custom_flags(no_follow())
        .open(path)
        .map_err(|source| opening(path, source))
}

/// The permission bits and owner of an open file, from the descriptor.
pub(super) fn ownership(file: &File, path: &Path) -> Result<(u32, u32), SessionError> {
    let metadata = file.metadata().map_err(|source| SessionError::Io {
        path: path.to_owned(),
        source,
    })?;

    // Masked to the permission bits: the raw mode carries the file type too, which no
    // message should print as part of an octal mode.
    Ok((metadata.permissions().mode() & 0o7777, metadata.uid()))
}
