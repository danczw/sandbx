//! Who may read a file, and whether it is the file that was checked.
//!
//! The modes the store creates with, the flag that keeps a leaf from being a link, and
//! the one way a mode is read, which refuses a foreign owner on the way. Which mode bit
//! refuses and which only reports stays with the sequence that applies it.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use nix::fcntl::OFlag;
use nix::sys::stat::Mode;

use crate::SessionError;

/// The mode a transcript is created with.
pub(super) const OWNER_ONLY: u32 = 0o600;

/// The mode the directory holding them is created with.
pub(super) const DIR_OWNER_ONLY: u32 = 0o700;

/// The bits that let somebody else write, which refuse a resume.
///
/// Split from [`READABLE_BITS`], not shared with `sandbx-auth`'s `SHARED_BITS`: a leaked
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
const NO_FOLLOW: OFlag = OFlag::O_NOFOLLOW;

/// Translate an open failure, naming a link that [`NO_FOLLOW`] refused.
///
/// By errno, not `ErrorKind::FilesystemLoop`, which is unstable. `ELOOP` from these
/// opens can only be the leaf, every component above it having been followed.
pub(super) fn opening(path: &Path, source: std::io::Error) -> SessionError {
    let path = path.to_owned();
    if source.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32) {
        return SessionError::Symlink { path };
    }

    SessionError::Io { path, source }
}

/// Open the root for reading, refusing one that is a symbolic link, since
/// [`narrow_root`](super::SessionStore::narrow_root) `fchmod`s this descriptor.
///
/// No `O_DIRECTORY`: with `O_NOFOLLOW` the kernel reports a symlinked directory as
/// `ENOTDIR`, as it does a root that is a plain file, and the two are worth telling apart.
pub(super) fn open_nofollow(path: &Path) -> Result<File, SessionError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(NO_FOLLOW.bits())
        .open(path)
        .map_err(|source| opening(path, source))
}

/// Open transcript `name` in the vetted root `directory`, `path` being for errors, and
/// [`OWNER_ONLY`] the mode should `flags` create it.
///
/// By descriptor, so a rename of the root or an ancestor after the vet cannot swap the
/// directory read (#317); `O_NOFOLLOW`, since a link's mode and owner are its target's.
/// `O_CLOEXEC` by hand: `OpenOptions` sets it, `openat` does not, and without it the
/// agent's commands inherit the transcript.
pub(super) fn open_at(
    directory: &File,
    name: &str,
    path: &Path,
    flags: OFlag,
) -> Result<File, SessionError> {
    let flags = flags | NO_FOLLOW | OFlag::O_CLOEXEC;
    nix::fcntl::openat(directory, name, flags, Mode::from_bits_truncate(OWNER_ONLY))
        .map(File::from)
        .map_err(|errno| opening(path, errno.into()))
}

/// The permission bits of an open file, from the descriptor, refusing one another uid owns.
///
/// Both uids must own it: the store creates as the effective one, and under a setuid
/// launch, where they differ, either alone admits files the other owns (#318).
pub(super) fn ownership(file: &File, path: &Path) -> Result<u32, SessionError> {
    let metadata = file.metadata().map_err(|source| SessionError::Io {
        path: path.to_owned(),
        source,
    })?;
    let uid = metadata.uid();
    if uid != nix::unistd::geteuid().as_raw() || uid != nix::unistd::getuid().as_raw() {
        let path = path.to_owned();
        return Err(SessionError::ForeignOwner { path, uid });
    }

    // Masked to the permission bits: the raw mode carries the file type too, which no
    // message should print as part of an octal mode.
    Ok(metadata.permissions().mode() & 0o7777)
}
