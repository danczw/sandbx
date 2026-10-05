use std::path::{Path, PathBuf};

use crate::{Access, SandboxError, SandboxPolicy};

/// Checks paths against a [`SandboxPolicy`] before sandbx's own code touches them.
///
/// The in-process complement to the kernel enforcement applied to child processes: tools
/// implemented in Rust (`read`, `write`, `edit`) never spawn anything, so Landlock never
/// sees them. Roots are canonicalized once at construction and every checked path before
/// comparison, so neither `..` nor a symlink can present a path that merely *looks* inside
/// an allowed root.
#[derive(Debug, Clone)]
pub struct FsGuard {
    readable: Vec<PathBuf>,
    writable: Vec<PathBuf>,
}

impl FsGuard {
    /// Resolve `policy`'s roots into a guard.
    ///
    /// A root that does not exist is dropped rather than rejected: unresolvable, it can
    /// never match a canonical path, so dropping it is conservative. Which axis feeds which
    /// list is [`Axis::grants`](crate::Axis::grants)'s to say, which is what keeps this
    /// layer and the kernel layer enforcing one policy. No `executable` list, nothing
    /// in-process execing anything — but the execute axis still feeds `readable`.
    pub fn new(policy: &SandboxPolicy) -> Self {
        let mut readable = Vec::new();
        let mut writable = Vec::new();

        for (axis, path) in policy.granted_paths() {
            // Destructured, not read field by field — see `Grants`.
            let crate::Grants {
                read,
                write,
                execute: _,
            } = axis.grants();

            if read {
                readable.push(path);
            }
            if write {
                writable.push(path);
            }
        }

        Self {
            readable: canonical_roots(readable),
            writable: canonical_roots(writable),
        }
    }

    /// Permit reading `path`, which must already exist, returning its resolved location.
    pub fn check_read(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        match canonicalize(path) {
            Ok(resolved) => permit(resolved, &self.readable, path, Access::Read),
            // Why a path failed to resolve is information: a caller that can probe
            // arbitrary paths reads ENOENT against EACCES back as a map of the host.
            Err(unresolved) => {
                Err(self.conceal_unless_granted(path, unresolved, &self.readable, Access::Read))
            }
        }
    }

    /// Report why a path could not be resolved, but only inside a granted area.
    ///
    /// The nearest ancestor that *does* resolve decides: inside an allowed root the caller
    /// was already entitled to know what is in there, so "no such file" is honest.
    /// Anywhere else the refusal is indistinguishable from any other.
    fn conceal_unless_granted(
        &self,
        requested: &Path,
        unresolved: SandboxError,
        roots: &[PathBuf],
        access: Access,
    ) -> SandboxError {
        let grants_area = requested
            .ancestors()
            .skip(1)
            .find_map(|ancestor| ancestor.canonicalize().ok())
            .is_some_and(|existing| within(&existing, roots));

        let subject = requested.display().to_string();
        if grants_area {
            crate::AuditEvent::denied(access.operation(), &subject, "path does not resolve").emit();
            return unresolved;
        }

        crate::AuditEvent::denied(access.operation(), &subject, access.outside()).emit();
        SandboxError::PathNotAllowed {
            requested: requested.to_path_buf(),
            access,
        }
    }

    /// Open `path` for reading, refusing anything the policy does not allow.
    ///
    /// Prefer this to [`check_read`](FsGuard::check_read) wherever the caller will open the
    /// file anyway: returning a path means re-resolving it, and in between the leaf can be
    /// swapped for a symlink pointing outside the roots. `O_NOFOLLOW` fails the open
    /// (`ELOOP`) if it was, but guards the *final* component only; a parent swapped mid-open
    /// would need full `openat`-chain resolution to defeat.
    pub fn open_read(&self, path: &Path) -> Result<std::fs::File, SandboxError> {
        let resolved = self.check_read(path)?;
        open(std::fs::OpenOptions::new().read(true), &resolved, path)
    }

    /// Open `path` for writing, creating or truncating it.
    ///
    /// The handle removes the window between the policy check and the open, as in
    /// [`open_read`](FsGuard::open_read).
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
    /// Here rather than in each tool because the confinement rule is the guard's to define:
    /// a symlink inside a readable directory can point anywhere. So a symlinked directory
    /// is never descended, which also makes the walk cycle-safe, and a symlinked file is
    /// included only if it resolves inside an allowed root. Only regular files; a FIFO with
    /// no writer would block forever. Sorted, `read_dir` order being filesystem-dependent.
    ///
    /// `max_files` bounds the walk, not the result: it stops as soon as a file would be the
    /// `max_files + 1`th, where trimming afterwards would bound neither time nor memory.
    /// [`ReadableWalk`] says whether anything was left.
    pub fn walk_readable(
        &self,
        root: &Path,
        max_files: usize,
    ) -> Result<ReadableWalk, SandboxError> {
        // One check for the root, and so one audit decision for the walk: checking every
        // entry would put thousands of "agent read this" records on the trail for files
        // never opened.
        let root = self.check_read(root)?;

        let mut files = Vec::new();
        let mut stack = vec![root];
        // Set where a file enters the result, so directories do not count toward the cap
        // and a tree that exactly fits reports nothing.
        let mut truncated = false;

        'walk: while let Some(dir) = stack.pop() {
            // An unreadable subdirectory is skipped, not fatal.
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };

            for entry in entries.flatten() {
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };

                // `dir` is canonical and `read_dir` never yields `.` or `..`, so a
                // non-symlink child is canonical too — hence no `canonicalize` per entry,
                // and only a symlink can leave the root.
                if file_type.is_symlink() {
                    let link = entry.path();
                    // Not through `check_read`, which would emit an `allowed` record per
                    // symlink and undo the single decision above. A dangling link is
                    // nothing to read; one escaping the roots is what the trail is for.
                    let Ok(resolved) = link.canonicalize() else {
                        continue;
                    };
                    if !within(&resolved, &self.readable) {
                        crate::AuditEvent::denied(
                            Access::Read.operation(),
                            &link.display().to_string(),
                            Access::Read.outside(),
                        )
                        .emit();
                        continue;
                    }
                    if resolved.is_file() {
                        if files.len() == max_files {
                            truncated = true;
                            break 'walk;
                        }
                        files.push(resolved);
                    }
                    continue;
                }

                let path = dir.join(entry.file_name());
                if file_type.is_dir() {
                    stack.push(path);
                } else if file_type.is_file() {
                    if files.len() == max_files {
                        truncated = true;
                        break 'walk;
                    }
                    files.push(path);
                }
            }
        }

        files.sort();
        Ok(ReadableWalk { files, truncated })
    }

    /// Permit writing `path`, returning its resolved location.
    ///
    /// The target need not exist, writes creating files; only the parent is resolved, with
    /// the filename appended, so `..` is still collapsed first.
    pub fn check_write(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        let resolved = match canonicalize(path) {
            Ok(existing) => existing,
            Err(_) => {
                let not_allowed = || SandboxError::PathNotAllowed {
                    requested: path.to_path_buf(),
                    access: Access::Write,
                };

                // `canonicalize` fails the same way on a nonexistent path and on a
                // *dangling* symlink, and resolving only the parent would approve the
                // link, whose write then follows it out of the root.
                if path.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
                    crate::AuditEvent::denied(
                        Access::Write.operation(),
                        &path.display().to_string(),
                        "symlink leaf may resolve outside the writable root",
                    )
                    .emit();
                    return Err(not_allowed());
                }

                // The only inputs where the halves disagree are `.`/`..`-tailed, refused
                // either way, so one failure covers both.
                let (parent, file_name) = path
                    .parent()
                    .zip(path.file_name())
                    .ok_or_else(not_allowed)?;
                canonicalize(parent)?.join(file_name)
            }
        };

        permit(resolved, &self.writable, path, Access::Write)
    }
}

/// Resolve every root that currently exists, discarding the rest.
fn canonical_roots<'a>(roots: impl IntoIterator<Item = &'a Path>) -> Vec<PathBuf> {
    roots
        .into_iter()
        .filter_map(|root| canonicalize(root).ok())
        .collect()
}

fn canonicalize(path: &Path) -> Result<PathBuf, SandboxError> {
    path.canonicalize()
        .map_err(|source| SandboxError::Unresolvable {
            requested: path.to_path_buf(),
            source,
        })
}

/// Whether `resolved` sits inside one of `roots`.
///
/// `Path::starts_with` compares whole components, not string prefixes: `/work-secrets` must
/// not match the root `/work`. Audit-free, so the walk can reuse the rule without recording
/// a decision per entry.
fn within(resolved: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| resolved.starts_with(root))
}

/// Allow `resolved` only if it sits inside one of `roots`, recording the verdict.
///
/// `roots` has to be the set `access` names: a denial reports the access, so handing it the
/// other axis's roots would record a true verdict with a false reason.
fn permit(
    resolved: PathBuf,
    roots: &[PathBuf],
    requested: &Path,
    access: Access,
) -> Result<PathBuf, SandboxError> {
    let subject = requested.display().to_string();

    if within(&resolved, roots) {
        crate::AuditEvent::allowed(access.operation(), &subject).emit();
        Ok(resolved)
    } else {
        crate::AuditEvent::denied(access.operation(), &subject, access.outside()).emit();
        Err(SandboxError::PathNotAllowed {
            requested: requested.to_path_buf(),
            access,
        })
    }
}

/// Open an already-approved path without following a symlink at the leaf, which — the path
/// having been canonical when checked — was swapped in after the check.
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

/// The files a walk returned, and whether it stopped before the tree ended.
///
/// A bool rather than a count: the walk stops at the cap, so it never learns how much tree
/// was left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadableWalk {
    /// Readable regular files beneath the root, sorted.
    pub files: Vec<PathBuf>,
    /// Whether the cap stopped the walk with tree left unvisited.
    pub truncated: bool,
}
