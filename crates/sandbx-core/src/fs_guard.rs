use std::path::{Path, PathBuf};

use crate::{Access, SandboxError, SandboxPolicy};

/// Checks paths against a [`SandboxPolicy`] before sandbx's own code touches them.
///
/// The in-process complement to the kernel enforcement on child processes: Rust tools
/// (`read`, `write`, `edit`) never spawn anything, so Landlock never sees them. Roots and
/// every checked path are canonicalized before comparison, so neither `..` nor a symlink can
/// present a path that merely looks inside an allowed root.
#[derive(Debug, Clone)]
pub struct FsGuard {
    readable: Vec<PathBuf>,
    writable: Vec<PathBuf>,
}

impl FsGuard {
    /// Resolve `policy`'s roots into a guard.
    ///
    /// A nonexistent root is dropped, not rejected: unresolvable, it can never match a
    /// canonical path. Which axis feeds which list is [`Axis::grants`](crate::Axis::grants)'s
    /// to say — no `executable` list, nothing in-process execs, but execute feeds `readable`.
    pub fn new(policy: &SandboxPolicy) -> Self {
        let mut readable = Vec::new();
        let mut writable = Vec::new();

        for (axis, path) in policy.granted_paths() {
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
        match path.canonicalize() {
            Ok(resolved) => permit(resolved, &self.readable, path, Access::Read),
            // Why a path failed to resolve is information: ENOENT against EACCES over
            // arbitrary paths reads back as a map of the host.
            Err(source) => {
                Err(self.conceal_unless_granted(path, path, source, &self.readable, Access::Read))
            }
        }
    }

    /// Report why a path could not be resolved, but only inside a granted area.
    ///
    /// The nearest ancestor that does resolve decides: inside an allowed root the caller was
    /// already entitled to know what is there, so "no such file" is honest. Anywhere else
    /// the refusal is indistinguishable from any other. Absence inside a grant is no
    /// verdict, so it gets no record; `allowed` would name a file nothing read.
    ///
    /// `failed` is the component resolution actually tripped on, which is the parent for a
    /// write; it is named only on the granted path, where it is inside the roots already.
    fn conceal_unless_granted(
        &self,
        requested: &Path,
        failed: &Path,
        source: std::io::Error,
        roots: &[PathBuf],
        access: Access,
    ) -> SandboxError {
        let grants_area = requested
            .ancestors()
            .skip(1)
            .find_map(|ancestor| ancestor.canonicalize().ok())
            .is_some_and(|existing| within(&existing, roots));

        let subject = requested.display().to_string();
        if !grants_area {
            crate::AuditEvent::denied(access.operation(), &subject, access.outside()).emit();
            return SandboxError::PathNotAllowed {
                requested: requested.to_path_buf(),
                access,
            };
        }

        let failed = failed.to_path_buf();
        if names_nothing(&source) {
            return SandboxError::NotFound {
                requested: failed,
                source,
            };
        }

        crate::AuditEvent::denied(access.operation(), &subject, "path does not resolve").emit();
        SandboxError::Unresolvable {
            requested: failed,
            source,
        }
    }

    /// Open `path` for reading, refusing anything the policy does not allow.
    ///
    /// Prefer this to [`check_read`](FsGuard::check_read) wherever the caller will open the
    /// file anyway: returning a path means re-resolving it, and in between the leaf can be
    /// swapped for a symlink out of the roots. `O_NOFOLLOW` fails such an open with `ELOOP`,
    /// but guards the final component only; a swapped parent needs `openat`-chain resolution.
    pub fn open_read(&self, path: &Path) -> Result<std::fs::File, SandboxError> {
        let resolved = self.check_read(path)?;
        open(std::fs::OpenOptions::new().read(true), &resolved, path)
    }

    /// Open `path` for writing, creating or truncating it; closes the check-to-open window
    /// as [`open_read`](FsGuard::open_read) does.
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
    /// A symlink inside a readable directory can point anywhere, so a symlinked directory is
    /// never descended — which also makes the walk cycle-safe — and a symlinked file is
    /// included only if it resolves inside an allowed root. Regular files only; a FIFO with
    /// no writer would block forever. Sorted, `read_dir` order being filesystem-dependent.
    ///
    /// `max_files` bounds the walk and not the result: it stops at the `max_files + 1`th
    /// file, where trimming afterwards would bound neither time nor memory.
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
                    // symlink and undo the single decision above.
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
    /// the filename appended, so `..` is collapsed first either way.
    pub fn check_write(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        let resolved = match path.canonicalize() {
            Ok(existing) => existing,
            Err(_) => {
                let not_allowed = || SandboxError::PathNotAllowed {
                    requested: path.to_path_buf(),
                    access: Access::Write,
                };

                // `canonicalize` fails the same way on a nonexistent path and on a dangling
                // symlink, and resolving only the parent would approve the link, whose
                // write then follows it out of the root.
                if path.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
                    crate::AuditEvent::denied(
                        Access::Write.operation(),
                        &path.display().to_string(),
                        "symlink leaf may resolve outside the writable root",
                    )
                    .emit();
                    return Err(not_allowed());
                }

                // `file_name` is the half that can be `None` here: it normalizes a `.` tail
                // away, so only a `..` tail reaches this, and `parent` is `None` only for
                // `/`, which resolves and never gets here at all.
                let Some((parent, file_name)) = path.parent().zip(path.file_name()) else {
                    crate::AuditEvent::denied(
                        Access::Write.operation(),
                        &path.display().to_string(),
                        "path names no file to write",
                    )
                    .emit();
                    return Err(not_allowed());
                };

                match parent.canonicalize() {
                    Ok(dir) => dir.join(file_name),
                    // The concealment decision is about the path the caller asked for; the
                    // parent is what the message names, a `write` told it cannot find the
                    // file it is creating having nothing to act on.
                    Err(source) => {
                        return Err(self.conceal_unless_granted(
                            path,
                            parent,
                            source,
                            &self.writable,
                            Access::Write,
                        ));
                    }
                }
            }
        };

        permit(resolved, &self.writable, path, Access::Write)
    }
}

/// Whether resolution failed because the name does not denote a file, rather than because
/// something refused the lookup.
///
/// The split is what the agent acts on: a wrong name is for it to fix, where EACCES or the
/// `ELOOP` of a swapped leaf it cannot. ENOTDIR and ENAMETOOLONG are as much a wrong name as
/// ENOENT, and reading back as refusals is what sent the model asking for a wider grant
/// (#180). By errno because `ErrorKind` has no stable spelling for ENAMETOOLONG.
fn names_nothing(source: &std::io::Error) -> bool {
    matches!(
        source.raw_os_error(),
        Some(libc::ENOENT | libc::ENOTDIR | libc::ENAMETOOLONG)
    )
}

/// Resolve every root that currently exists, discarding the rest.
fn canonical_roots<'a>(roots: impl IntoIterator<Item = &'a Path>) -> Vec<PathBuf> {
    roots
        .into_iter()
        .filter_map(|root| root.canonicalize().ok())
        .collect()
}

/// Whether `resolved` sits inside one of `roots`.
///
/// `Path::starts_with` compares whole components and not string prefixes, so `/work-secrets`
/// does not match the root `/work`. Audit-free, so the walk can reuse the rule without
/// recording a decision per entry.
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
///
/// The path is proven inside a root by now, so there is nothing left to conceal: a file
/// deleted since the check is an absence, while `ELOOP` from `O_NOFOLLOW` is the swap.
fn open(
    options: &mut std::fs::OpenOptions,
    resolved: &Path,
    requested: &Path,
) -> Result<std::fs::File, SandboxError> {
    use std::os::unix::fs::OpenOptionsExt;

    options
        .custom_flags(libc::O_NOFOLLOW)
        .open(resolved)
        .map_err(|source| {
            let requested = requested.to_path_buf();
            if names_nothing(&source) {
                SandboxError::NotFound { requested, source }
            } else {
                SandboxError::Unresolvable { requested, source }
            }
        })
}

/// The files a walk returned, and whether it stopped before the tree ended.
///
/// A bool and not a count: the walk stops at the cap, so it never learns how much was left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadableWalk {
    /// Readable regular files beneath the root, sorted.
    pub files: Vec<PathBuf>,
    /// Whether the cap stopped the walk with tree left unvisited.
    pub truncated: bool,
}

/// Inline because `open` runs after the check has passed: no public call can lose the
/// check-to-open race on purpose.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_approved_path_opens_as_not_found() {
        let root = tempfile::tempdir().unwrap();
        let gone = root.path().join("deleted-after-the-check");

        let error = open(std::fs::OpenOptions::new().read(true), &gone, &gone).unwrap_err();

        assert!(
            matches!(error, SandboxError::NotFound { .. }),
            "got {error:?}"
        );
    }

    /// The leaf-swap the `O_NOFOLLOW` flag exists to catch stays a refusal.
    #[cfg(unix)]
    #[test]
    fn a_swapped_leaf_opens_as_unresolvable() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target.txt");
        std::fs::write(&target, b"x").unwrap();
        let link = root.path().join("swapped");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let error = open(std::fs::OpenOptions::new().read(true), &link, &link).unwrap_err();

        assert!(
            matches!(error, SandboxError::Unresolvable { .. }),
            "got {error:?}"
        );
    }
}
