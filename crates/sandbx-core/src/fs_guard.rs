use std::path::{Path, PathBuf};

use crate::{SandboxError, SandboxPolicy};

/// Checks paths against a [`SandboxPolicy`] before sandbx's own code touches them.
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
    ///
    /// Which axis feeds which list is not decided here: every grant is sorted by
    /// what [`Axis::grants`] says it confers. That is what keeps this layer and
    /// the kernel layer enforcing one policy — chaining the axes by hand is how
    /// the execute axis came to be missing from `readable`, so that the native
    /// `read` tool refused a file `bash` could `cat` under the same policy (#50).
    ///
    /// There is no `executable` list because nothing in-process execs anything —
    /// `bash` spawns, and the kernel governs that. The execute axis still feeds
    /// `readable`, because reading is part of what it grants.
    ///
    /// [`Axis::grants`]: crate::Axis::grants
    pub fn new(policy: &SandboxPolicy) -> Self {
        let mut readable = Vec::new();
        let mut writable = Vec::new();

        for (axis, path) in policy.granted_paths() {
            // Destructured, not read field by field — see `Grants`. `execute` is
            // explicitly discarded: nothing in-process execs anything.
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
            .is_some_and(|existing| within(&existing, roots));

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
    ///
    /// `max_files` bounds the walk itself, not the result: it stops as soon as a
    /// file would be the `max_files + 1`th, so a caller's cost is bounded in
    /// time and in memory. Trimming afterwards would bound neither, since the
    /// whole tree would already have been visited and held. The returned
    /// [`ReadableWalk`] says whether anything was left behind.
    pub fn walk_readable(
        &self,
        root: &Path,
        max_files: usize,
    ) -> Result<ReadableWalk, SandboxError> {
        // One check for the root, which also records one audit decision for the
        // walk. Checking every entry would emit thousands of "agent read this"
        // records for files never opened, corrupting the trail it feeds.
        let root = self.check_read(root)?;

        let mut files = Vec::new();
        let mut stack = vec![root];
        // Set only when a file is left behind, which is why the cap is checked
        // where a file enters the result rather than once per directory:
        // directories do not count toward it, and a tree that exactly fits has
        // nothing left to report.
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

                // `dir` is canonical and `read_dir` never yields `.` or `..`, so
                // a non-symlink child of it is canonical too — no need to pay
                // `canonicalize` per entry. Only a symlink can leave the root,
                // and only those are re-checked.
                if file_type.is_symlink() {
                    let link = entry.path();
                    // Resolved here rather than through `check_read`, which would
                    // emit an `allowed` record per symlink and undo the single
                    // decision above. A dangling link is skipped silently —
                    // nothing to read, no decision to record — but one that
                    // escapes the roots is still recorded, since an escape
                    // attempt is exactly what the trail exists to show.
                    let Ok(resolved) = link.canonicalize() else {
                        continue;
                    };
                    if !within(&resolved, &self.readable) {
                        crate::AuditEvent::denied(
                            "read",
                            &link.display().to_string(),
                            "outside every allowed root",
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
    /// Unlike reads, the target need not exist yet — writes create files. Only
    /// the parent directory is resolved, and the filename is appended to that
    /// resolved parent, so `..` in the path is still collapsed before the check.
    pub fn check_write(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        let resolved = match canonicalize(path) {
            Ok(existing) => existing,
            Err(_) => {
                let not_allowed = || SandboxError::PathNotAllowed {
                    requested: path.to_path_buf(),
                };

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
                    return Err(not_allowed());
                }

                // Both halves must be present to rebuild the path, and the only
                // inputs where they disagree are `.`/`..`-tailed — refused either
                // way, so one failure covers both.
                let (parent, file_name) = path
                    .parent()
                    .zip(path.file_name())
                    .ok_or_else(not_allowed)?;
                canonicalize(parent)?.join(file_name)
            }
        };

        permit(resolved, &self.writable, path, "write")
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
/// `Path::starts_with` compares whole components, not string prefixes:
/// `/work-secrets` must not match the root `/work`, which a string prefix would
/// allow. Audit-free, so the walk can reuse the membership rule without
/// recording a decision per entry.
fn within(resolved: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| resolved.starts_with(root))
}

/// Allow `resolved` only if it sits inside one of `roots`, recording the verdict.
fn permit(
    resolved: PathBuf,
    roots: &[PathBuf],
    requested: &Path,
    operation: &str,
) -> Result<PathBuf, SandboxError> {
    let subject = requested.display().to_string();

    if within(&resolved, roots) {
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

/// The files a walk returned, and whether it stopped before the tree ended.
///
/// The flag is a bool rather than a count of what was skipped: the walk stops
/// at the cap, so it never learns how much tree was left. A cap that trims a
/// list it already holds can say "200 of 4000" — being unable to is the cost of
/// bounding the work instead of the answer, and worth it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadableWalk {
    /// Readable regular files beneath the root, sorted.
    pub files: Vec<PathBuf>,
    /// Whether the cap stopped the walk with tree left unvisited.
    pub truncated: bool,
}
