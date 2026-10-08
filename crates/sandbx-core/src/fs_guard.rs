//! The in-process filesystem gate: the policy check, and the accesses it guards.
//!
//! Over the 400-line budget on purpose: check, access and record are one sequence, and a
//! split puts the record in a different file from the check it has to agree with.
//! `decision=` names the access, not the verdict; see `context/guide-logging.md`.
//!
//! A root is confirmed against its grant's pin per access, not once at construction, so the
//! window is the two syscalls between the confirmation and the open.

use std::path::{Path, PathBuf};

use crate::policy::Confirmation;
use crate::{Access, ObjectId, SandboxError, SandboxPolicy, VettedPath};

/// Checks paths against a [`SandboxPolicy`] before sandbx's own code touches them.
///
/// The in-process complement to the kernel enforcement on child processes: Rust tools
/// (`read`, `write`, `edit`) never spawn anything, so Landlock never sees them. Every checked
/// path is canonicalized before comparison, so neither `..` nor a symlink can present a path
/// that merely looks inside an allowed root. The roots are the policy's grants whole, pin
/// included, so a root is in bounds only while it still holds the object that was vetted.
#[derive(Debug, Clone)]
pub struct FsGuard {
    readable: Vec<VettedPath>,
    writable: Vec<VettedPath>,
}

impl FsGuard {
    /// Sort `policy`'s grants into the two lists a check compares against.
    ///
    /// No I/O: a grant is already resolved and already pinned, so resolving it again here
    /// would answer with whatever its spelling names now. Which axis feeds which list is
    /// [`Axis::grants`](crate::Axis::grants)'s to say — no `executable` list, nothing
    /// in-process execs, but execute feeds `readable`.
    pub fn new(policy: &SandboxPolicy) -> Self {
        let mut readable = Vec::new();
        let mut writable = Vec::new();

        for (axis, granted) in policy.granted_paths() {
            let crate::Grants {
                read,
                write,
                execute: _,
            } = axis.grants();

            if read {
                readable.push(granted.clone());
            }
            if write {
                writable.push(granted.clone());
            }
        }

        Self { readable, writable }
    }

    /// Permit reading `path`, which must already exist, returning its resolved location.
    ///
    /// Records a refusal and nothing else — the `allowed` belongs to the access that follows,
    /// so prefer [`open_read`](FsGuard::open_read) or [`read_dir`](FsGuard::read_dir).
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
    /// The nearest ancestor that does resolve decides, and must speak for the path below it
    /// (`reaches_plainly`): inside a confirmed root the caller could already enumerate the
    /// area, so "no such file" is honest. Anywhere else `deny` answers, so a name under a
    /// root that has moved tells the caller only that it moved, whether the name is there or
    /// not — and the record stays `denied` either way.
    ///
    /// The root is measured before the spelling is judged. Under `reaches_plainly` the
    /// measurement would be skipped for exactly the paths it has most to say about.
    ///
    /// `failed` is the component resolution tripped on, the parent for a write, and is named
    /// only on the granted path, where it is inside the roots already.
    fn conceal_unless_granted(
        &self,
        requested: &Path,
        failed: &Path,
        source: std::io::Error,
        roots: &[VettedPath],
        access: Access,
    ) -> SandboxError {
        let (ancestor, granted_area) = nearest_area(requested, roots);

        if let Containment::Outside(moved) = granted_area {
            return deny(moved, requested, access);
        }

        // Inside a confirmed root, where the ancestor still has to speak for the path below
        // it; a symlink or a `..` in between means it does not.
        if !ancestor.is_some_and(|ancestor| reaches_plainly(requested, ancestor)) {
            return deny(None, requested, access);
        }

        let subject = requested.display().to_string();
        let failed = failed.to_path_buf();
        if names_nothing(&source) {
            crate::AuditEvent::absent(access.operation(), &subject).emit();
            return SandboxError::NotFound {
                requested: failed,
                source,
            };
        }

        crate::AuditEvent::denied(access.operation(), &subject, UNRESOLVABLE).emit();
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
        open(
            std::fs::OpenOptions::new().read(true),
            &resolved,
            path,
            Access::Read,
        )
    }

    /// Read the entries of `path`, refusing anything the policy does not allow.
    ///
    /// Here and not in the caller because the audit target is this crate's alone. It closes
    /// no check-to-use window that [`check_read`](FsGuard::check_read) leaves open — a
    /// directory read has no `O_NOFOLLOW` handle form — only the gap to the trail. The outer
    /// result is the policy's, the inner the host's; the caller reports them apart.
    pub fn read_dir(&self, path: &Path) -> Result<std::io::Result<std::fs::ReadDir>, SandboxError> {
        let resolved = self.check_read(path)?;

        Ok(record(
            std::fs::read_dir(&resolved),
            Access::Read,
            path,
            listed_nothing,
        ))
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
            Access::Write,
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
    ///
    /// The widest confirmation window of the six tools: `root` is confirmed once, for the
    /// whole walk, since one record covers the walk and re-confirming per directory would
    /// have to refuse mid-result.
    pub fn walk_readable(
        &self,
        root: &Path,
        max_files: usize,
    ) -> Result<ReadableWalk, SandboxError> {
        // One record for the walk, naming the root: per entry would name thousands of files
        // it only listed. A caller that then reads them — `grep` — adds its own per open.
        let requested = root;
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
                    // The reason comes off the same measurement that refused, as everywhere
                    // else: a link into a moved root is not out of bounds, and a trail
                    // calling it that hides the substitution behind the commonest refusal.
                    if let Containment::Outside(moved) = contains(&resolved, &self.readable) {
                        let reason = match moved {
                            Some(_) => ROOT_REPLACED,
                            None => Access::Read.outside(),
                        };
                        crate::AuditEvent::denied(
                            Access::Read.operation(),
                            &link.display().to_string(),
                            reason,
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
        // Directly, not through `record`: the walk skips what it cannot read, so by here
        // there is no outcome but success left to sort.
        crate::AuditEvent::allowed(Access::Read.operation(), &requested.display().to_string())
            .emit();
        Ok(ReadableWalk { files, truncated })
    }

    /// Permit writing `path`, returning its resolved location.
    ///
    /// The target need not exist, writes creating files; only the parent is resolved, with
    /// the filename appended, so `..` is collapsed first either way. Records a refusal and
    /// nothing else; prefer [`open_write`](FsGuard::open_write).
    pub fn check_write(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        let resolved = match path.canonicalize() {
            Ok(existing) => existing,
            Err(_) => {
                let not_allowed = || SandboxError::PathNotAllowed {
                    requested: path.to_path_buf(),
                    access: Access::Write,
                };

                // The root answers first. Both reasons below are chosen by what sits at the
                // path, so under a substituted root they report what the substitute holds
                // instead of refusing it, and the two read apart where they must read alike.
                if let (_, Containment::Outside(Some(moved))) = nearest_area(path, &self.writable) {
                    return Err(deny(Some(moved), path, Access::Write));
                }

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

                // `file_name` normalizes a `.` tail away, so only a `..` tail reaches this.
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
                    // Concealment is decided on the caller's path; the parent is what the
                    // message names, the missing directory being what there is to act on.
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

/// A path that exists and still would not resolve: an unreadable parent, or a leaf swapped
/// for a symlink. One string, so the gate and the access record it alike.
const UNRESOLVABLE: &str = "path does not resolve";

/// A granted root that no longer holds the object it was vetted on. One string, so the gate
/// and the access record it alike.
const ROOT_REPLACED: &str = "granted root is not the object it was vetted on";

/// An access the policy permitted on a path that resolved, which the host refused anyway:
/// a full disk, a read-only mount, a directory opened as a file. Not `UNRESOLVABLE`, which
/// an operator counting refusals reads as a traversal attempt.
const INCOMPLETE: &str = "access did not complete";

/// Whether resolution failed because the name denotes no file, rather than because something
/// refused the lookup.
///
/// A wrong name is the caller's to fix; EACCES and the `ELOOP` of a swapped leaf are not, and
/// stay refusals. ENOTDIR and ENAMETOOLONG are as much a wrong name as ENOENT (#180). By
/// errno because `ErrorKind` has no stable spelling for ENAMETOOLONG.
fn names_nothing(source: &std::io::Error) -> bool {
    matches!(
        source.raw_os_error(),
        Some(libc::ENOENT | libc::ENOTDIR | libc::ENAMETOOLONG)
    )
}

/// The same question for a directory read, which ENOTDIR answers the other way.
///
/// In a lookup that errno is a component that turned out to be a regular file, so the name
/// denotes nothing; on an approved `read_dir`'s leaf it is the leaf, which `check_read` had
/// just resolved — there, and not a directory.
fn listed_nothing(source: &std::io::Error) -> bool {
    names_nothing(source) && source.raw_os_error() != Some(libc::ENOTDIR)
}

/// Whether `requested` reaches past `ancestor` by components that are what they look like.
///
/// Only `ancestor` resolved, so it speaks for `requested` only this far. A symlink below it
/// points anywhere: ENOENT is then its *target's* absence, and a dangling link planted in a
/// granted root would answer "does this host path exist" for any target. A `..` leaks
/// nothing — resolution never passed it — but would name an out-of-grant path as absent.
fn reaches_plainly(requested: &Path, ancestor: &Path) -> bool {
    !requested
        .components()
        .any(|part| part == std::path::Component::ParentDir)
        && requested
            .ancestors()
            .take_while(|step| *step != ancestor)
            .all(|step| !step.symlink_metadata().is_ok_and(|at| at.is_symlink()))
}

/// Where the deepest part of `requested` that resolves sits, and which part that was.
///
/// A path that does not resolve is judged by its nearest resolving ancestor, so the root under
/// it is measured here rather than in each caller — and measured before any reason drawn from
/// the leaf, which under a substituted root would be a reason the substitute chose.
fn nearest_area<'a>(requested: &'a Path, roots: &[VettedPath]) -> (Option<&'a Path>, Containment) {
    let Some((ancestor, existing)) = requested
        .ancestors()
        .skip(1)
        .find_map(|ancestor| Some((ancestor, ancestor.canonicalize().ok()?)))
    else {
        return (None, Containment::Outside(None));
    };

    (Some(ancestor), contains(&existing, roots))
}

/// Where `resolved` sits relative to a set of granted roots.
enum Containment {
    /// Inside a root that still holds the object the policy granted it on.
    Inside,
    /// Inside no such root. A root that matched the spelling but has moved is carried out, so
    /// the refusal can name it off this measurement: taking a second one to find out which
    /// root moved can disagree with the first, and would report a moved root as merely out of
    /// bounds.
    Outside(Option<Replacement>),
}

/// A granted root whose spelling matched and whose object did not.
struct Replacement {
    granted: PathBuf,
    vetted: ObjectId,
    opened: ObjectId,
}

/// Find the root that covers `resolved`, confirming each candidate's object as it goes.
///
/// `Path::starts_with` compares whole components and not string prefixes, so `/work-secrets`
/// does not match the root `/work`. The first root that is both lexical and confirmed wins: nested and sibling grants overlap,
/// and a moved root must not deny a path another root still covers. A root that cannot be
/// measured at all accuses nothing and is passed over — it also grants nothing, having no
/// confirmed object for a path to be inside of.
fn contains(resolved: &Path, roots: &[VettedPath]) -> Containment {
    let mut moved = None;

    for root in roots
        .iter()
        .filter(|root| resolved.starts_with(root.path()))
    {
        match root.confirm() {
            Confirmation::Vetted => return Containment::Inside,
            Confirmation::Replaced(opened) => {
                moved.get_or_insert_with(|| Replacement {
                    granted: root.path().to_path_buf(),
                    vetted: root.object(),
                    opened,
                });
            }
            Confirmation::Unmeasurable => {}
        }
    }

    Containment::Outside(moved)
}

/// Refuse `requested`, recording which of the two reasons the gate decided on.
///
/// One function for both, so a path under a substituted root answers alike whether or not it
/// exists: a `NotFound` for the absent against a refusal for the present would be a one-bit
/// oracle for what the substitute holds.
fn deny(moved: Option<Replacement>, requested: &Path, access: Access) -> SandboxError {
    let subject = requested.display().to_string();

    let Some(Replacement {
        granted,
        vetted,
        opened,
    }) = moved
    else {
        crate::AuditEvent::denied(access.operation(), &subject, access.outside()).emit();
        return SandboxError::PathNotAllowed {
            requested: requested.to_path_buf(),
            access,
        };
    };

    crate::AuditEvent::denied(access.operation(), &subject, ROOT_REPLACED).emit();
    SandboxError::RootReplaced {
        granted,
        vetted,
        opened,
    }
}

/// Allow `resolved` only if it sits inside one of `roots`, recording a refusal.
///
/// Only a refusal: passing the gate is not yet an access, so the `allowed` belongs to the
/// entry point that performs one, and a bare check that succeeds records nothing (#182).
///
/// `roots` has to be the set `access` names: a denial reports the access, so handing it the
/// other axis's roots would record a true verdict with a false reason.
fn permit(
    resolved: PathBuf,
    roots: &[VettedPath],
    requested: &Path,
    access: Access,
) -> Result<PathBuf, SandboxError> {
    match contains(&resolved, roots) {
        Containment::Inside => Ok(resolved),
        Containment::Outside(moved) => Err(deny(moved, requested, access)),
    }
}

/// Record what an approved path's access actually did, and nothing about the verdict.
///
/// Which errnos count as absence is the caller's — `names_nothing` for a path lookup,
/// `listed_nothing` for a directory read — so the record and the error the caller returns
/// cannot disagree about whether the path was there.
fn record<T>(
    outcome: std::io::Result<T>,
    access: Access,
    requested: &Path,
    absent: fn(&std::io::Error) -> bool,
) -> std::io::Result<T> {
    let subject = requested.display().to_string();
    let tool = access.operation();

    match &outcome {
        Ok(_) => crate::AuditEvent::allowed(tool, &subject).emit(),
        Err(source) if absent(source) => crate::AuditEvent::absent(tool, &subject).emit(),
        Err(source) => crate::AuditEvent::denied(tool, &subject, reason(source)).emit(),
    }

    outcome
}

/// The `reason=` an access on an approved path carries when it did not happen.
///
/// `ELOOP` is the leaf swapped since the check, the one post-gate failure that really is a
/// resolution failure; the rest found the path and stopped there.
fn reason(source: &std::io::Error) -> &'static str {
    if source.raw_os_error() == Some(libc::ELOOP) {
        UNRESOLVABLE
    } else {
        INCOMPLETE
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
    access: Access,
) -> Result<std::fs::File, SandboxError> {
    use std::os::unix::fs::OpenOptionsExt;

    let opened = options.custom_flags(libc::O_NOFOLLOW).open(resolved);

    record(opened, access, requested, names_nothing).map_err(|source| classify(source, requested))
}

/// Sort an error from an already-approved access into absence or refusal.
fn classify(source: std::io::Error, requested: &Path) -> SandboxError {
    let requested = requested.to_path_buf();
    if names_nothing(&source) {
        SandboxError::NotFound { requested, source }
    } else {
        SandboxError::Unresolvable { requested, source }
    }
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

        let error = open(
            std::fs::OpenOptions::new().read(true),
            &gone,
            &gone,
            Access::Read,
        )
        .unwrap_err();

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

        let error = open(
            std::fs::OpenOptions::new().read(true),
            &link,
            &link,
            Access::Read,
        )
        .unwrap_err();

        assert!(
            matches!(error, SandboxError::Unresolvable { .. }),
            "got {error:?}"
        );
    }
}
