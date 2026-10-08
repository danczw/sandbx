//! A granted path, and the object it named when the harness vetted it.
//!
//! Rules are opened in the helper and the policy is judged in the harness, so a `rename(2)` in
//! between can put one real directory where another was vetted — identical spelling, so the
//! readback in `helper/ruleset/opened.rs` agrees and only the object tells the two apart (#212).
//!
//! `FsGuard` asks the same question of its own roots per access, so the measurement lives here.

use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use crate::SandboxError;

/// Between the two halves of the pin on the wire, and nowhere else.
const SEPARATOR: char = ':';

/// Which filesystem object a path named: the device, and the inode on it.
///
/// Compared and never interpreted. Neither half is stable across a remount, which is the
/// property that makes the pair worth carrying: an object that moved is not the one that was
/// vetted, whatever it is now called.
///
/// An inode number is reused after its object is unlinked, so a directory deleted and
/// re-created at a granted name can compare equal — the floor on what either pin can claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectId {
    dev: u64,
    ino: u64,
}

impl ObjectId {
    /// The object `path` names now, following every symlink in it.
    fn of_path(path: &Path) -> std::io::Result<Self> {
        let metadata = std::fs::metadata(path)?;

        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    /// The object `fd` holds, which renaming the name it was opened under cannot change.
    ///
    /// `fstat` and not a second walk of the path: a descriptor names its object directly, so
    /// this is the one measurement the rename window cannot reach. The kernel has answered it
    /// for an `O_PATH` descriptor since 3.6.
    pub(crate) fn of_fd(fd: &impl AsFd) -> Result<Self, SandboxError> {
        // Not `GrantReplaced`, which would claim the object changed: a grant that cannot be
        // measured is one this kernel will not let the sandbox confirm.
        let stat = nix::sys::stat::fstat(fd).map_err(|_| SandboxError::Unsupported {
            detail: "a granted path could not be stat'ed through the descriptor it opened as, \
                     so it cannot be confirmed to be the object that was vetted",
        })?;

        Ok(Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
        })
    }

    /// The pin `token` carries, or `None` for anything [`Display`] would not have written.
    ///
    /// [`Display`]: std::fmt::Display
    pub(crate) fn parse(token: &str) -> Option<Self> {
        let (dev, ino) = token.split_once(SEPARATOR)?;

        Some(Self {
            dev: dev.parse().ok()?,
            ino: ino.parse().ok()?,
        })
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{SEPARATOR}{}", self.dev, self.ino)
    }
}

/// A path, and the object it named when the harness vetted it.
///
/// The one thing [`SandboxPolicy::grant`] accepts, so no construction path reaches a policy
/// holding a grant with no pin and the helper has no unpinned case to have a policy about.
/// An embedder meets that as a signature change rather than as a refused run —
/// `context/decision-grant-identity.md`.
///
/// [`SandboxPolicy::grant`]: crate::SandboxPolicy::grant
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VettedPath {
    path: PathBuf,
    object: ObjectId,
}

impl VettedPath {
    /// `path`, resolved, and pinned to the object it names now.
    ///
    /// The only producer that touches the filesystem, and it runs in the harness: the helper
    /// decodes a policy through [`grant`](crate::SandboxPolicy::grant) too, where resolving or
    /// stat'ing would measure whatever the links point at by then — the process a grant is meant
    /// to be safe from. Resolving here rather than in the caller keeps the path and the object
    /// from being taken a step apart, and a path naming nothing cannot be vetted at all.
    pub fn vet(path: impl AsRef<Path>) -> Result<Self, SandboxError> {
        let requested = path.as_ref();
        let unpinnable = |source| SandboxError::GrantUnpinnable {
            granted: requested.to_path_buf(),
            source,
        };

        let path = requested.canonicalize().map_err(unpinnable)?;
        let object = ObjectId::of_path(&path).map_err(unpinnable)?;

        Ok(Self { path, object })
    }

    /// The pin as it crossed the helper argv, with no I/O at all.
    ///
    /// Not a weaker source than [`vet`](Self::vet): argv is the harness's own, passed from
    /// stage 1 to stage 2 verbatim, and the path token has always been trusted on that basis.
    /// Crate-private, so the helper's producer is not an embedder's.
    pub(crate) fn from_wire(path: impl Into<PathBuf>, object: ObjectId) -> Self {
        Self {
            path: path.into(),
            object,
        }
    }

    /// The path, as the harness resolved it.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The object it named when it was vetted.
    pub fn object(&self) -> ObjectId {
        self.object
    }

    /// Whether the path still names the object it was vetted on, measured now.
    ///
    /// `O_PATH`, so the open is a lookup and not an access, and `fstat` on that descriptor
    /// rather than a second walk, so the two steps cannot resolve to different objects. No
    /// `O_NOFOLLOW`: a spelling that became a symlink names another object *through* it.
    pub(crate) fn confirm(&self) -> Confirmation {
        let Ok(opened) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(&self.path)
        else {
            return Confirmation::Unmeasurable;
        };

        match ObjectId::of_fd(&opened) {
            Ok(object) if object == self.object => Confirmation::Vetted,
            Ok(object) => Confirmation::Replaced(object),
            Err(_) => Confirmation::Unmeasurable,
        }
    }
}

/// What [`VettedPath::confirm`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Confirmation {
    /// The object the path was vetted on.
    Vetted,
    /// Some other object, under the same spelling.
    Replaced(ObjectId),
    /// Nothing to compare: the path names no object now, or this kernel would not say which.
    /// Not [`Replaced`](Self::Replaced), which would accuse a removed grant of a swap.
    Unmeasurable,
}

impl AsRef<Path> for VettedPath {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every pin `encode` emits has to be one `decode` accepts, the wire form being the whole
    /// of what the helper is told.
    #[test]
    fn a_pin_round_trips_through_its_own_wire_form() {
        let object = ObjectId {
            dev: 259,
            ino: 2_097_153,
        };

        assert_eq!(
            ObjectId::parse(&object.to_string()),
            Some(object),
            "a pin did not survive its own spelling"
        );
    }

    #[test]
    fn a_pin_that_is_not_two_numbers_is_refused() {
        for token in ["", ":", "259", "259:", ":17", "259:17:4", "a:b", "-1:17"] {
            assert_eq!(
                ObjectId::parse(token),
                None,
                "{token:?} was accepted as a pin"
            );
        }
    }

    /// A vetted path is resolved by construction, so nothing downstream has to resolve it
    /// again to compare it — and the pin belongs to the resolved path, not to the spelling.
    #[test]
    fn vetting_resolves_the_path_it_pins() {
        let work = tempfile::tempdir().expect("a temporary directory");
        let real = work.path().canonicalize().expect("a resolved directory");
        let link = real.join("link");
        let target = real.join("target");
        std::fs::create_dir(&target).expect("a directory to link to");
        std::os::unix::fs::symlink(&target, &link).expect("a symlink to it");

        let vetted = VettedPath::vet(&link).expect("a symlink to a directory that exists");

        assert_eq!(
            vetted.path(),
            target,
            "a symlinked spelling was pinned as itself"
        );
        assert_eq!(
            vetted.object(),
            VettedPath::vet(&target).expect("the target").object(),
            "the link and its target pinned different objects"
        );
    }

    /// The rename #212 is about, measured: two real directories, one name.
    #[test]
    fn a_renamed_directory_is_a_different_object() {
        let work = tempfile::tempdir().expect("a temporary directory");
        let root = work.path().canonicalize().expect("a resolved directory");
        let granted = root.join("granted");
        let other = root.join("other");
        std::fs::create_dir(&granted).expect("the directory to vet");
        std::fs::create_dir(&other).expect("the directory to substitute");

        let vetted = VettedPath::vet(&granted).expect("a directory that exists");
        std::fs::rename(&other, &granted).expect("a substitution at the same name");

        let replaced = VettedPath::vet(&granted).expect("the substituted directory");

        assert_eq!(
            vetted.path(),
            replaced.path(),
            "the substitution changed the spelling, so this asserts nothing about objects"
        );
        assert_ne!(
            vetted.object(),
            replaced.object(),
            "a substituted directory pinned the same object"
        );
    }

    #[test]
    fn a_path_naming_nothing_cannot_be_vetted() {
        let work = tempfile::tempdir().expect("a temporary directory");

        let error = VettedPath::vet(work.path().join("no-such-directory"))
            .expect_err("a path that names nothing");

        assert!(
            matches!(error, SandboxError::GrantUnpinnable { .. }),
            "{error} is not the unpinnable-grant refusal"
        );
    }

    /// The helper's half: the two producers measure one thing, so a pin taken from a path and
    /// one taken from a descriptor on it have to agree.
    #[test]
    fn a_descriptor_names_the_object_its_path_did() {
        let work = tempfile::tempdir().expect("a temporary directory");
        let vetted = VettedPath::vet(work.path()).expect("a temporary directory to vet");
        let opened = std::fs::File::open(vetted.path()).expect("a directory to open");

        assert_eq!(
            ObjectId::of_fd(&opened).expect("a descriptor on an open directory"),
            vetted.object(),
            "the path and the descriptor on it named different objects"
        );
    }

    /// The positive the other two are read against: without it the guard could refuse all.
    #[test]
    fn confirming_a_path_that_did_not_move() {
        let work = tempfile::tempdir().expect("a temporary directory");
        let vetted = VettedPath::vet(work.path()).expect("a temporary directory to vet");

        assert_eq!(
            vetted.confirm(),
            Confirmation::Vetted,
            "an untouched grant did not confirm as the object it was vetted on"
        );
    }

    /// A refusal names what it found: the operator has one name and two objects to tell apart.
    #[test]
    fn confirming_a_renamed_over_path_names_it() {
        let work = tempfile::tempdir().expect("a temporary directory");
        let root = work.path().canonicalize().expect("a resolved directory");
        let granted = root.join("granted");
        let other = root.join("other");
        std::fs::create_dir(&granted).expect("the directory to vet");
        std::fs::create_dir(&other).expect("the directory to substitute");

        let vetted = VettedPath::vet(&granted).expect("a directory that exists");
        let substitute = VettedPath::vet(&other).expect("the directory to substitute");
        std::fs::rename(&other, &granted).expect("a substitution at the same name");

        assert_eq!(
            vetted.confirm(),
            Confirmation::Replaced(substitute.object()),
            "the substitution was not reported as the object that is there now"
        );
    }

    /// Not [`Confirmation::Replaced`]: a path that names nothing has substituted nothing.
    #[test]
    fn confirming_a_path_that_is_gone() {
        let work = tempfile::tempdir().expect("a temporary directory");
        let granted = work.path().join("granted");
        std::fs::create_dir(&granted).expect("the directory to vet");

        let vetted = VettedPath::vet(&granted).expect("a directory that exists");
        std::fs::remove_dir(&granted).expect("the grant to be removed under it");

        assert_eq!(
            vetted.confirm(),
            Confirmation::Unmeasurable,
            "a grant that is gone was reported as one that moved"
        );
    }
}
