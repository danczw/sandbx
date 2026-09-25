use std::path::{Path, PathBuf};

use crate::{SandboxError, SandboxPolicy};

/// Checks paths against a [`SandboxPolicy`] before echo's own code touches them.
///
/// This is the in-process complement to the kernel enforcement applied to child
/// processes: tools implemented in Rust (`read`, `write`, `edit`) never spawn
/// anything, so Landlock never sees them. `FsGuard` is what keeps those honest.
///
/// Roots are canonicalized once at construction, and every checked path is
/// canonicalized before comparison, so neither `..` nor a symlink can present a
/// path that merely *looks* like it is inside an allowed root.
#[derive(Debug, Clone)]
pub struct FsGuard {
    readable: Vec<PathBuf>,
    writable: Vec<PathBuf>,
}

impl FsGuard {
    /// Resolve `policy`'s roots into a guard.
    ///
    /// Roots that do not exist are dropped rather than rejected: a policy may
    /// name a directory that has not been created yet, and a root that cannot be
    /// resolved can never match a canonical path anyway — so dropping it is the
    /// conservative choice, not a permissive one.
    pub fn new(policy: &SandboxPolicy) -> Result<Self, SandboxError> {
        Ok(Self {
            readable: canonical_roots(policy.readable_paths()),
            writable: canonical_roots(policy.writable_paths()),
        })
    }

    /// Permit reading `path`, returning its resolved location.
    ///
    /// The path must already exist — you cannot read what is not there.
    pub fn check_read(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        match canonicalize(path) {
            Ok(resolved) => permit(resolved, &self.readable, path, "read"),
            // Why a path failed to resolve is information: ENOENT, EACCES and
            // "resolves but out of bounds" are distinguishable, and a caller
            // that can probe arbitrary paths reads them back as a map of the
            // host. Only disclose the reason where the policy already grants
            // the area being asked about.
            Err(unresolved) => {
                Err(self.conceal_unless_granted(path, unresolved, &self.readable, "read"))
            }
        }
    }

    /// Report why a path could not be resolved, but only inside a granted area.
    ///
    /// Resolution failed, so the path itself cannot be located — instead the
    /// nearest ancestor that *does* resolve decides. If that ancestor sits in an
    /// allowed root, the caller was already entitled to know what is in there,
    /// and a plain "no such file" is honest feedback it needs to avoid retrying.
    /// Anywhere else, the refusal is indistinguishable from any other.
    fn conceal_unless_granted(
        &self,
        requested: &Path,
        unresolved: SandboxError,
        roots: &[PathBuf],
        operation: &str,
    ) -> SandboxError {
        let grants_area = requested
            .ancestors()
            .skip(1)
            .find_map(|ancestor| ancestor.canonicalize().ok())
            .is_some_and(|existing| roots.iter().any(|root| existing.starts_with(root)));

        let subject = requested.display().to_string();
        if grants_area {
            crate::AuditEvent::denied(operation, &subject, "path does not resolve").emit();
            return unresolved;
        }

        crate::AuditEvent::denied(operation, &subject, "outside every allowed root").emit();
        SandboxError::PathNotAllowed {
            requested: requested.to_path_buf(),
        }
    }

    /// Open `path` for reading, refusing anything the policy does not allow.
    ///
    /// Prefer this to [`check_read`] wherever the caller is going to open the
    /// file anyway. Returning a path means the caller re-resolves it, and
    /// between the check and that open the leaf can be swapped for a symlink
    /// pointing outside the allowed roots — the handle closes that window,
    /// because there is nothing left to re-resolve.
    ///
    /// `O_NOFOLLOW` makes the open itself fail (`ELOOP`) if the final component
    /// became a symlink after the check. Note it guards the *final* component
    /// only: an attacker able to swap a parent directory mid-open would need
    /// full `openat`-chain resolution to defeat, which this does not attempt.
    ///
    /// [`check_read`]: FsGuard::check_read
    pub fn open_read(&self, path: &Path) -> Result<std::fs::File, SandboxError> {
        let resolved = self.check_read(path)?;
        open(std::fs::OpenOptions::new().read(true), &resolved, path)
    }

    /// Open `path` for writing, creating or truncating it.
    ///
    /// Same reasoning as [`open_read`]: the handle removes the window between
    /// the policy check and the open.
    ///
    /// [`open_read`]: FsGuard::open_read
    pub fn open_write(&self, path: &Path) -> Result<std::fs::File, SandboxError> {
        let resolved = self.check_write(path)?;
        open(
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true),
            &resolved,
            path,
        )
    }

    /// Every regular file beneath `root` that this guard permits reading.
    ///
    /// Exists here rather than in each tool because the confinement rule is the
    /// guard's to define: a tool that walks a tree itself has to remember that a
    /// symlink inside a readable directory can point anywhere, and a tool that
    /// forgets is a silent escape.
    ///
    /// **Symlinks are never followed into.** A symlinked directory is not
    /// descended, which also makes the walk cycle-safe; a symlinked file is
    /// included only if it resolves inside an allowed root.
    ///
    /// Only regular files are returned. FIFOs, sockets and devices are skipped —
    /// reading a FIFO with no writer blocks forever, which would wedge the
    /// caller rather than return.
    ///
    /// Entries are returned sorted, since `read_dir` order is
    /// filesystem-dependent.
    pub fn walk_readable(&self, root: &Path) -> Result<Vec<PathBuf>, SandboxError> {
        // One check for the root, which also records one audit decision for the
        // walk. Checking every entry would emit thousands of "agent read this"
        // records for files never opened, corrupting the trail it feeds.
        let root = self.check_read(root)?;

        let mut files = Vec::new();
        let mut stack = vec![root];

        while let Some(dir) = stack.pop() {
            // An unreadable subdirectory is skipped, not fatal.
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };

            for entry in entries.flatten() {
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };

                // `dir` is canonical and `read_dir` never yields `.` or `..`, so
                // a non-symlink child of it is canonical too — no need to pay
                // `canonicalize` per entry. Only a symlink can leave the root,
                // and only those are re-checked.
                if file_type.is_symlink() {
                    let Ok(resolved) = self.check_read(&entry.path()) else {
                        continue;
                    };
                    if resolved.is_file() {
                        files.push(resolved);
                    }
                    continue;
                }

                let path = dir.join(entry.file_name());
                if file_type.is_dir() {
                    stack.push(path);
                } else if file_type.is_file() {
                    files.push(path);
                }
            }
        }

        files.sort();
        Ok(files)
    }

    /// Permit writing `path`, returning its resolved location.
    ///
    /// Unlike reads, the target need not exist yet — writes create files. Only
    /// the parent directory is resolved, and the filename is appended to that
    /// resolved parent, so `..` in the path is still collapsed before the check.
    pub fn check_write(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        let resolved = match canonicalize(path) {
            Ok(existing) => existing,
            Err(_) => {
                // `canonicalize` fails the same way on a nonexistent path and on
                // a *dangling* symlink. Resolving only the parent would approve
                // the link, and the caller's write would then follow it out of
                // the root — so refuse a symlink leaf outright rather than
                // treating it as a file yet to be created.
                if path.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
                    crate::AuditEvent::denied(
                        "write",
                        &path.display().to_string(),
                        "symlink leaf may resolve outside the allowed root",
                    )
                    .emit();
                    return Err(SandboxError::PathNotAllowed {
                        requested: path.to_path_buf(),
                    });
                }

                let parent = path.parent().ok_or_else(|| SandboxError::PathNotAllowed {
                    requested: path.to_path_buf(),
                })?;
                let file_name = path
                    .file_name()
                    .ok_or_else(|| SandboxError::PathNotAllowed {
                        requested: path.to_path_buf(),
                    })?;
                canonicalize(parent)?.join(file_name)
            }
        };

        permit(resolved, &self.writable, path, "write")
    }
}

/// Resolve every root that currently exists, discarding the rest.
fn canonical_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    roots.iter().filter_map(|r| canonicalize(r).ok()).collect()
}

fn canonicalize(path: &Path) -> Result<PathBuf, SandboxError> {
    path.canonicalize()
        .map_err(|source| SandboxError::Unresolvable {
            requested: path.to_path_buf(),
            source,
        })
}

/// Allow `resolved` only if it sits inside one of `roots`.
///
/// Compares whole path components, not string prefixes: `/work-secrets` must not
/// match the root `/work`, which a `starts_with` on strings would allow.
/// `Path::starts_with` is component-wise, which is exactly the needed semantics.
fn permit(
    resolved: PathBuf,
    roots: &[PathBuf],
    requested: &Path,
    operation: &str,
) -> Result<PathBuf, SandboxError> {
    let subject = requested.display().to_string();

    if roots.iter().any(|root| resolved.starts_with(root)) {
        crate::AuditEvent::allowed(operation, &subject).emit();
        Ok(resolved)
    } else {
        crate::AuditEvent::denied(operation, &subject, "outside every allowed root").emit();
        Err(SandboxError::PathNotAllowed {
            requested: requested.to_path_buf(),
        })
    }
}

/// Open an already-approved path without following a symlink at the leaf.
///
/// `O_NOFOLLOW` is the whole point: the path was canonical when checked, so if
/// the final component is a symlink *now*, it was swapped in afterwards.
fn open(
    options: &mut std::fs::OpenOptions,
    resolved: &Path,
    requested: &Path,
) -> Result<std::fs::File, SandboxError> {
    use std::os::unix::fs::OpenOptionsExt;

    options
        .custom_flags(libc::O_NOFOLLOW)
        .open(resolved)
        .map_err(|source| SandboxError::Unresolvable {
            requested: requested.to_path_buf(),
            source,
        })
}
