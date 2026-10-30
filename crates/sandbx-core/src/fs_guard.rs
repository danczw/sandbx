//! The in-process filesystem gate: the policy check, and the accesses it guards. A root is
//! confirmed against its grant's pin per access, and a permitted access then resolves
//! beneath a descriptor the guard holds on that root — so the object confirmed and the
//! object reached are the same one, and the confirmation-to-open window is closed rather
//! than narrowed. `openat2` is Linux 5.6; below it, and for a grant naming a file rather
//! than a directory, the access goes by path and the window is confirmation to open (#230).
//!
//! One module on purpose: check, access and record are one sequence, and a
//! split puts the record in a different file from the check it has to agree with.

use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, OpenOptions, ReadDir};
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::{env, fs, io};

use nix::fcntl::{OFlag, OpenHow, ResolveFlag};

use crate::policy::Confirmation;
use crate::{Access, ObjectId, SandboxError, SandboxPolicy, VettedPath};

/// How a permitted access resolves the rest of its path: beneath a held descriptor, or by
/// the path again. `RESOLVE_NO_SYMLINKS` beside `RESOLVE_BENEATH` because `BENEATH` alone
/// follows a link that stays inside the root, which would open an object the confirmation
/// did not measure. No false positives: what is handed to the kernel is the canonical
/// path's remainder, so it holds no link to refuse.
const BENEATH: ResolveFlag = ResolveFlag::RESOLVE_BENEATH.union(ResolveFlag::RESOLVE_NO_SYMLINKS);

/// Checks paths against a [`SandboxPolicy`] before sandbx's own code touches them: the
/// in-process complement to kernel enforcement, since Rust tools (`read`, `write`, `edit`)
/// never spawn anything, so Landlock never sees them. Every checked path is canonicalized
/// before comparison, so neither `..` nor a symlink can present a path that merely looks
/// inside an allowed root. The roots are the policy's grants whole, pin included, so a
/// root is in bounds only while it still holds the object that was vetted.
#[derive(Debug, Clone)]
pub struct FsGuard {
    readable: Vec<Root>,
    writable: Vec<Root>,
}

/// A granted root, and the descriptor a permitted access resolves beneath.
///
/// `dir` is `None` for three causes: a kernel without `openat2`, a grant naming a file
/// rather than a directory, and a granted name that no longer reaches the directory it was
/// vetted on. All three mean the same thing to an *access* — resolve by path, bounded by the
/// confirmation alone, which is what every access did before #230 — which is why nothing
/// below this point distinguishes them. [`open_root`] does, because at construction the
/// third is a substitution and the other two are not: see [`Rooting`].
#[derive(Debug, Clone)]
struct Root {
    vetted: VettedPath,
    /// Shared rather than owned: [`FsGuard`] is `Clone`, and a tool call clones one per
    /// `spawn_blocking`, so an `OwnedFd` field would cost a `dup` per call or the derive.
    dir: Option<Arc<OwnedFd>>,
}

impl FsGuard {
    /// Sort `policy`'s grants into the two lists a check compares against, opening a
    /// descriptor per granted directory to resolve its accesses beneath.
    ///
    /// The grant itself is never re-resolved: the descriptor is opened on the path the
    /// policy already canonicalized, so this answers about that object and not about
    /// whatever the spelling names now. Which axis feeds which list is
    /// [`Axis::grants`](crate::Axis::grants)'s to say — no `executable` list, since nothing
    /// in-process execs, but execute feeds `readable`.
    ///
    /// Infallible, and one dead root denies only itself: a root that has gone is already
    /// refused by the check, nothing resolving inside a path that does not resolve, so
    /// there is nothing for construction to refuse and the surviving grants still work.
    pub fn new(policy: &SandboxPolicy) -> Self {
        Self::with_rooting(policy, None, openat2_support())
    }

    /// [`new`](Self::new), naming the session whose accesses this guard will bound.
    ///
    /// Only the `rooted_access` degradation reads it, and only to say which session lost a
    /// root's descriptor. A separate constructor rather than a setter because the record is
    /// written *here*: a guard built first and told its session afterwards has already
    /// reported, so the setter shape cannot be made correct (#249).
    pub fn for_session(policy: &SandboxPolicy, session: &str) -> Self {
        Self::with_rooting(policy, Some(session), openat2_support())
    }

    /// [`new`](Self::new), with the kernel's answer supplied rather than asked.
    ///
    /// Split so the fallback is reachable from a test: no CI runner is below the 5.6 that
    /// `openat2` needs, so the by-path branch is otherwise exercised nowhere.
    fn with_rooting(policy: &SandboxPolicy, session: Option<&str>, kernel: Openat2) -> Self {
        let mut readable = Vec::new();
        let mut writable = Vec::new();
        // One record per *root*, not per grant entry. `granted_paths` yields a path once per
        // axis, and the shipped CLI puts every `--allow-write` on two of them — so recording
        // per entry would report one substituted root twice and an operator counting them
        // would overcount on the ordinary shape.
        let mut told = Vec::new();

        for (axis, granted) in policy.granted_paths() {
            let crate::Grants {
                read,
                write,
                execute: _,
            } = axis.grants();

            // One open per grant entry, then shared: a path granted on two axes is two
            // entries here and so two descriptors — policy-level duplication, not this
            // loop's to collapse.
            let dir = match (kernel == Openat2::Present).then(|| open_root(granted)) {
                Some(Rooting::Beneath(dir)) => Some(Arc::new(dir)),
                Some(Rooting::Unpinned) => {
                    // At `INFO`, like every other degraded step: nothing the agent asked for
                    // was refused, and the grant is still bounded by the per-access
                    // confirmation — it has only lost the descriptor that would have made a
                    // swap unreachable rather than merely refused. Naming the root discloses
                    // nothing: it is a path the operator granted.
                    if !told.iter().any(|path| path == granted.path()) {
                        let detail = format!(
                            "{} no longer reaches the directory it was vetted on; its \
                             accesses resolve by path, bounded by the per-access \
                             confirmation alone",
                            granted.path().display()
                        );
                        // No run to name: the guard is built before anything is spawned, and
                        // this weakens every access for the session rather than one spawn.
                        crate::AuditEvent::degraded("rooted_access", None, session, &detail).emit();
                        told.push(granted.path().to_path_buf());
                    }
                    None
                }
                Some(Rooting::ByPath) | None => None,
            };
            let root = Root {
                vetted: granted.clone(),
                dir,
            };

            if read {
                readable.push(root.clone());
            }
            if write {
                writable.push(root);
            }
        }

        Self { readable, writable }
    }

    /// Permit reading `path`, which must already exist, returning its resolved location.
    /// Records a refusal and nothing else — the `allowed` belongs to the access that follows,
    /// so prefer [`open_read`](FsGuard::open_read) or [`read_dir`](FsGuard::read_dir).
    pub fn check_read(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        self.permit_read(path).map(|permitted| permitted.resolved)
    }

    /// [`check_read`](Self::check_read)'s verdict, keeping the root the access resolves
    /// beneath. The whole of the check is here; the public form drops the descriptor
    /// because it hands back a path and so performs no access to root.
    fn permit_read(&self, path: &Path) -> Result<Permitted, SandboxError> {
        match path.canonicalize() {
            Ok(resolved) => permit(resolved, &self.readable, path, Access::Read),
            // Why a path failed to resolve is information: ENOENT against EACCES over
            // arbitrary paths reads back as a map of the host.
            Err(source) => {
                Err(self.conceal_unless_granted(path, path, source, &self.readable, Access::Read))
            }
        }
    }

    /// Report why a path could not be resolved, but only inside a granted area. The nearest
    /// ancestor that does resolve decides, and must speak for the path below it
    /// (`reaches_plainly`): inside a confirmed root the caller could already enumerate the area,
    /// so "no such file" is honest; anywhere else `deny` answers, present and absent alike. The
    /// root is measured first, before any reason the leaf would name
    /// (`context/decision-policy.md`). `failed` is the component resolution tripped
    /// on — the parent for a write — and is named only on the granted path, already inside the
    /// roots.
    fn conceal_unless_granted(
        &self,
        requested: &Path,
        failed: &Path,
        source: io::Error,
        roots: &[Root],
        access: Access,
    ) -> SandboxError {
        if let Some(moved) = moved_root(requested, roots) {
            return deny(Some(moved), requested, access);
        }

        let (ancestor, granted_area) = nearest_area(requested, roots);

        // The ancestor resolves, so what it reached is the substitute's choice too, and the
        // reason it would name is one the spelling above has already declined to give.
        if matches!(granted_area, Containment::Outside(_)) {
            return deny(None, requested, access);
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

    /// Open `path` for reading, refusing anything the policy does not allow. Prefer this to
    /// [`check_read`](FsGuard::check_read) wherever the caller will open the file anyway:
    /// returning a path means re-resolving it, and in between the leaf can be swapped for a
    /// symlink out of the roots. `O_NOFOLLOW` fails such an open with `ELOOP`, but guards the
    /// final component only; a swapped parent needs `openat`-chain resolution.
    pub fn open_read(&self, path: &Path) -> Result<File, SandboxError> {
        let permitted = self.permit_read(path)?;

        let Some(root) = &permitted.root else {
            return open(
                OpenOptions::new().read(true),
                &permitted.resolved,
                path,
                Access::Read,
            );
        };

        let opened = beneath(
            root,
            &permitted.resolved,
            OFlag::O_RDONLY,
            nix::sys::stat::Mode::empty(),
        );

        record(opened.map(File::from), Access::Read, path, names_nothing)
            .map_err(|source| classify(source, path))
    }

    /// Read the entries of `path`, refusing anything the policy does not allow. Here and not
    /// in the caller because the audit target is this crate's alone. The outer result is
    /// the policy's, the inner the host's; the caller reports them apart.
    ///
    /// Where the grant holds a descriptor the directory is opened beneath it, so the listing
    /// comes off the object the check confirmed rather than off a second resolution of the
    /// path. `O_DIRECTORY` without `O_NOFOLLOW`: the resolve flags already refuse a link, and
    /// `O_NOFOLLOW` would report one as `ENOTDIR`, which `listed_nothing` reads as a
    /// directory that is really a file — true of a regular leaf and false of a link.
    pub fn read_dir(&self, path: &Path) -> Result<io::Result<Listing>, SandboxError> {
        let permitted = self.permit_read(path)?;

        let Some(root) = &permitted.root else {
            return Ok(record(
                fs::read_dir(&permitted.resolved).and_then(listing_by_path),
                Access::Read,
                path,
                listed_nothing,
            ));
        };

        let opened = beneath(
            root,
            &permitted.resolved,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            nix::sys::stat::Mode::empty(),
        );

        Ok(record(
            opened.and_then(listing),
            Access::Read,
            path,
            listed_nothing,
        ))
    }

    /// Open `path` for writing, creating or truncating it; closes the check-to-open window
    /// as [`open_read`](FsGuard::open_read) does.
    pub fn open_write(&self, path: &Path) -> Result<File, SandboxError> {
        let permitted = self.permit_write(path)?;

        if let Some(root) = &permitted.root {
            let opened = beneath(
                root,
                &permitted.resolved,
                OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_TRUNC,
                // `OpenOptions`' own default, not a choice: `OpenHow` zeroes the mode, so
                // omitting it creates every file `0o000` and the handle already open hides it.
                nix::sys::stat::Mode::from_bits_truncate(0o666),
            );

            return record(opened.map(File::from), Access::Write, path, names_nothing)
                .map_err(|source| classify(source, path));
        }

        let resolved = permitted.resolved;
        open(
            OpenOptions::new().write(true).create(true).truncate(true),
            &resolved,
            path,
            Access::Write,
        )
    }

    /// Every regular file beneath `root` that this guard permits reading. A symlink inside a
    /// readable directory can point anywhere, so a symlinked directory is never descended —
    /// which also makes the walk cycle-safe — and a symlinked file is included only if it
    /// resolves inside an allowed root. Regular files only, since a FIFO with no writer would
    /// block forever; sorted, `read_dir` order being filesystem-dependent. `max_files` bounds
    /// the walk, not the result: it stops at the `max_files + 1`th file,
    /// where trimming afterwards would bound neither time nor memory. The widest confirmation
    /// window of the five tools: `root` is confirmed once for the whole walk, one record
    /// covering it, and re-confirming per directory would refuse mid-result.
    pub fn walk_readable(
        &self,
        root: &Path,
        max_files: usize,
    ) -> Result<ReadableWalk, SandboxError> {
        // One record for the walk, naming the root: per entry would name thousands of files
        // it only listed. A caller that then reads them — `grep` — adds its own per open.
        let requested = root;
        let permitted = self.permit_read(root)?;

        if let Some(rooted) = &permitted.root {
            let top = beneath(
                rooted,
                &permitted.resolved,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY,
                nix::sys::stat::Mode::empty(),
            );

            // Only `EXDEV` refuses, and only because it is the one refusal a by-path descent
            // cannot make: a component renamed out from under the root between the check and
            // this open, which recorded as a successful read of an empty tree would hide the
            // substitution this closes. Every other failure answers as it did before —
            // a walk root that is a regular file or unreadable yields no files rather than an
            // error — so the two descents cannot disagree about anything but the escape.
            let walked = match top {
                Ok(top) => self.walk_beneath(top, &permitted.resolved, max_files),
                Err(source) if source.raw_os_error() == Some(libc::EXDEV) => {
                    crate::AuditEvent::denied(
                        Access::Read.operation(),
                        &requested.display().to_string(),
                        ESCAPED,
                    )
                    .emit();
                    return Err(classify(source, requested));
                }
                Err(_) => ReadableWalk {
                    files: Vec::new(),
                    truncated: false,
                },
            };

            crate::AuditEvent::allowed(Access::Read.operation(), &requested.display().to_string())
                .emit();
            return Ok(walked);
        }

        let root = permitted.resolved;
        let mut files = Vec::new();
        let mut stack = vec![root];
        // Set where a file enters the result, so directories do not count toward the cap
        // and a tree that exactly fits reports nothing.
        let mut truncated = false;

        'walk: while let Some(dir) = stack.pop() {
            // An unreadable subdirectory is skipped, not fatal.
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };

            for entry in entries.flatten() {
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };

                // `dir` is canonical and `read_dir` never yields `.` or `..`, so a non-symlink
                // child is canonical too — hence no `canonicalize` per entry, and only a
                // symlink can leave the root.
                if file_type.is_symlink() {
                    let link = entry.path();
                    // Not through `check_read`, which would emit an `allowed` record per
                    // symlink and undo the single decision above.
                    let Ok(resolved) = link.canonicalize() else {
                        continue;
                    };
                    // The link's own spelling answers first: inside the confirm-to-walk window
                    // the entries are the substitute's, so a resolved reason is one it chose.
                    let placement = match moved_root(&link, &self.readable) {
                        Some(moved) => Containment::Outside(Some(moved)),
                        None => contains(&resolved, &self.readable),
                    };
                    if let Containment::Outside(moved) = placement {
                        let reason = moved.map_or(Access::Read.outside(), |_| ROOT_REPLACED);
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

    /// [`walk_readable`](Self::walk_readable)'s descent, by descriptor rather than by path.
    ///
    /// The symlink arm stays by path on purpose: it is the verdict deciding whether a link
    /// leaves the granted set, which is the concealment rule's and not this descent's, and
    /// the files it yields are opened later through [`open_read`](Self::open_read), rooted
    /// there.
    fn walk_beneath(&self, top: OwnedFd, at: &Path, max_files: usize) -> ReadableWalk {
        use std::os::unix::ffi::OsStrExt;

        let mut files = Vec::new();
        let mut truncated = false;

        // A stack entry costs an `Arc` clone of its *parent*, never a descriptor of its own,
        // and the child is opened when it is popped. Opening at push time would hold one
        // descriptor per pending sibling, so a wide tree runs out of them and loses whole
        // subtrees with nothing marking the result partial — which the by-path stack could
        // not do, `std::fs::read_dir` holding one directory at a time. Popping bounds the
        // live set by the tree's depth instead: siblings share one parent handle.
        let mut stack: Vec<(Arc<OwnedFd>, Option<Vec<u8>>, PathBuf)> =
            vec![(Arc::new(top), None, at.to_path_buf())];

        'walk: while let Some((parent, name, at)) = stack.pop() {
            let dir = match name {
                // The walk root, already open.
                None => parent,
                Some(name) => match open_dir_at(&parent, &name) {
                    Ok(opened) => Arc::new(opened),
                    // An unreadable subdirectory is skipped, not fatal, as it was by path.
                    Err(_) => continue,
                },
            };

            // `try_clone` because listing consumes a descriptor and this one is also the
            // parent its own subdirectories are opened beneath.
            let Ok(for_listing) = dir.try_clone() else {
                continue;
            };
            let Ok(entries) = entries_at(for_listing) else {
                continue;
            };

            for (name, kind) in entries {
                let child = at.join(OsStr::from_bytes(&name));

                match kind {
                    Some(nix::dir::Type::Symlink) => {
                        if let Some(resolved) = self.walked_link(&child) {
                            if files.len() == max_files {
                                truncated = true;
                                break 'walk;
                            }
                            files.push(resolved);
                        }
                    }
                    Some(nix::dir::Type::Directory) => {
                        stack.push((Arc::clone(&dir), Some(name), child));
                    }
                    Some(nix::dir::Type::File) => {
                        if files.len() == max_files {
                            truncated = true;
                            break 'walk;
                        }
                        files.push(child);
                    }
                    // A FIFO with no writer blocks forever, and a device is not a file the
                    // tools read; an unclassifiable entry is neither descended nor collected.
                    _ => {}
                }
            }
        }

        files.sort();
        ReadableWalk { files, truncated }
    }

    /// Where a symlink found in a walk resolves, if the granted set still covers it.
    ///
    /// Records its own refusal and returns `None`: a walk has no caller to tell, so the
    /// trail is the whole report, and a link into a moved root recorded as merely out of
    /// bounds would hide the substitution.
    fn walked_link(&self, link: &Path) -> Option<PathBuf> {
        let resolved = link.canonicalize().ok()?;

        // The link's own spelling answers first: inside the confirm-to-walk window the
        // entries are the substitute's, so a resolved reason is one it chose.
        let placement = match moved_root(link, &self.readable) {
            Some(moved) => Containment::Outside(Some(moved)),
            None => contains(&resolved, &self.readable),
        };

        if let Containment::Outside(moved) = placement {
            let reason = moved.map_or(Access::Read.outside(), |_| ROOT_REPLACED);
            crate::AuditEvent::denied(
                Access::Read.operation(),
                &link.display().to_string(),
                reason,
            )
            .emit();
            return None;
        }

        resolved.is_file().then_some(resolved)
    }

    /// Permit writing `path`, returning its resolved location. The target need not exist,
    /// writes creating files; only the parent is resolved, with the filename appended, so
    /// `..` is collapsed first either way. Records a refusal and nothing else; prefer
    /// [`open_write`](FsGuard::open_write).
    pub fn check_write(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        self.permit_write(path).map(|permitted| permitted.resolved)
    }

    /// [`check_write`](Self::check_write)'s verdict, keeping the root the access resolves
    /// beneath — the write half of [`permit_read`](Self::permit_read).
    fn permit_write(&self, path: &Path) -> Result<Permitted, SandboxError> {
        let resolved = match path.canonicalize() {
            Ok(existing) => existing,
            Err(_) => {
                let refuse = |reason| {
                    crate::AuditEvent::denied(
                        Access::Write.operation(),
                        &path.display().to_string(),
                        reason,
                    )
                    .emit();
                    SandboxError::PathNotAllowed {
                        requested: path.to_path_buf(),
                        access: Access::Write,
                    }
                };

                // The root answers first: both reasons below are chosen by what sits at the
                // path, so under a substituted root they report what the substitute holds.
                if let Some(moved) = moved_root(path, &self.writable) {
                    return Err(deny(Some(moved), path, Access::Write));
                }

                // `canonicalize` fails the same way on a nonexistent path and a dangling
                // symlink; resolving only the parent would approve the link, whose write
                // then follows it out of the root.
                if path.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
                    return Err(refuse("symlink leaf may resolve outside the writable root"));
                }

                // `file_name` normalizes a `.` tail away, so only a `..` tail reaches this.
                let Some((parent, file_name)) = path.parent().zip(path.file_name()) else {
                    return Err(refuse("path names no file to write"));
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

/// A permitted access whose resolution left the root it was rooted at — the swap window
/// #230 closes, caught in the act. `RESOLVE_BENEATH` answers `EXDEV` only for a `rename(2)`
/// moving a component out from under the descriptor mid-resolution, the remainder handed to
/// the kernel being canonical and so holding no `..` and no link of its own. Its own string,
/// not `UNRESOLVABLE`: an operator counting substitution attempts would otherwise read this
/// as a dangling symlink.
const ESCAPED: &str = "resolution left the granted root since the check";

/// Whether resolution failed because the name denotes no file, rather than because
/// something refused the lookup. A wrong name is the caller's to fix; EACCES and the
/// `ELOOP` of a swapped leaf are not, and stay refusals. ENOTDIR and ENAMETOOLONG are as
/// much a wrong name as ENOENT (#180). By errno because `ErrorKind` has no stable spelling
/// for ENAMETOOLONG.
fn names_nothing(source: &io::Error) -> bool {
    matches!(
        source.raw_os_error(),
        Some(libc::ENOENT | libc::ENOTDIR | libc::ENAMETOOLONG)
    )
}

/// The same question for a directory read, which ENOTDIR answers the other way. In a
/// lookup that errno is a component that turned out to be a regular file, so the name
/// denotes nothing; on an approved `read_dir`'s leaf it is the leaf, which `check_read`
/// had just resolved — there, and not a directory.
fn listed_nothing(source: &io::Error) -> bool {
    names_nothing(source) && source.raw_os_error() != Some(libc::ENOTDIR)
}

/// Whether `requested` reaches past `ancestor` by components that are what they look like.
/// Only `ancestor` resolved, so it speaks for `requested` only this far. A symlink below it
/// points anywhere: ENOENT is then its *target's* absence, and a dangling link planted in a
/// granted root would answer "does this host path exist" for any target. A `..` leaks
/// nothing — resolution never passed it — but would name an out-of-grant path as absent.
fn reaches_plainly(requested: &Path, ancestor: &Path) -> bool {
    !requested
        .components()
        .any(|part| part == Component::ParentDir)
        && requested
            .ancestors()
            .take_while(|step| *step != ancestor)
            .all(|step| !step.symlink_metadata().is_ok_and(|at| at.is_symlink()))
}

/// Where the deepest part of `requested` that resolves sits, and which part that was. A
/// path that does not resolve is judged by its nearest resolving ancestor, so the root
/// under it is measured here and before any reason the leaf would name.
fn nearest_area<'a>(requested: &'a Path, roots: &[Root]) -> (Option<&'a Path>, Containment) {
    let Some((ancestor, existing)) = requested
        .ancestors()
        .skip(1)
        .find_map(|ancestor| Some((ancestor, ancestor.canonicalize().ok()?)))
    else {
        return (None, Containment::Outside(None));
    };

    (Some(ancestor), contains(&existing, roots))
}

/// Open `granted` as a directory to resolve accesses beneath, or `None` if it is not one.
///
/// `O_DIRECTORY` and `O_NOFOLLOW` together, and neither is optional. `O_NOFOLLOW` is what
/// makes a granted name replaced by a symlink refuse here rather than root the resolution
/// at whatever the link points to; `O_DIRECTORY` is what makes `O_NOFOLLOW` bite, since
/// `O_PATH | O_NOFOLLOW` alone returns a handle to the link itself. The opposite choice
/// from [`VettedPath::confirm`], which omits `O_NOFOLLOW` on purpose: it asks what object
/// the name holds, and this asks for a directory to resolve beneath.
///
/// Through `OpenOptions` rather than `openat2`: a grant is absolute, so there is no
/// descriptor to resolve it beneath, and `OpenOptions` sets `O_CLOEXEC` itself.
fn open_root(granted: &VettedPath) -> Rooting {
    use std::os::unix::fs::OpenOptionsExt;

    let open = |flags| {
        OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(granted.path())
            .ok()
            .map(OwnedFd::from)
    };

    // Measured through the name first, exactly as `VettedPath::confirm` does and for the
    // same reason: without `O_NOFOLLOW` this reports whatever object the name now holds,
    // which is what tells a substitution from a grant that simply never named a directory.
    // Opening strictly first cannot: a symlink and a regular file both fail it, and a
    // legitimate `--allow-read /etc/hosts` fails it identically to an attacker's swap.
    let Some(named) = open(libc::O_PATH) else {
        // The name resolves to nothing, which the check refuses on its own.
        return Rooting::ByPath;
    };

    let Ok(object) = ObjectId::of_fd(&named) else {
        // An `fstat` failing on a handle we hold is the host's business, and says nothing
        // about whether the name was substituted.
        return Rooting::ByPath;
    };

    // The descriptor is measured against the pin before it is kept, because this open and
    // the per-access confirmation are two different moments. A granted name holding an
    // attacker's object while this runs, restored before the first access, would confirm
    // against the pin and still resolve every access beneath the substitute — the one way a
    // held descriptor could be worse than the path it replaced.
    if object != granted.object() {
        return Rooting::Unpinned;
    }

    let Ok(at) = nix::sys::stat::fstat(&named) else {
        return Rooting::ByPath;
    };

    if at.st_mode & libc::S_IFMT != libc::S_IFDIR {
        // A grant naming a file, which is legal — `--allow-write /dev/null`, and every path
        // the resolver binds over. There is no directory to resolve beneath and nothing was
        // substituted, so this is the one silent cause left.
        return Rooting::ByPath;
    }

    // The vetted object is a directory and the name still holds it, so the strict open can
    // only fail if the name reaches it *through a link* — a substitution of the name rather
    // than of the object, which `O_NOFOLLOW` is here to refuse.
    match open(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW) {
        Some(dir) => Rooting::Beneath(dir),
        None => Rooting::Unpinned,
    }
}

/// Whether a grant got a descriptor to resolve its accesses beneath, and if not, whether
/// that is worth telling the operator about.
enum Rooting {
    /// Accesses resolve beneath this.
    Beneath(OwnedFd),
    /// Nothing to resolve beneath, and nothing substituted: the grant does not name a
    /// directory, or the name reaches nothing at all, which the check refuses anyway. A
    /// file grant is legal and ordinary, so this one is silent.
    ByPath,
    /// The granted name no longer reaches the directory it was vetted on — another object
    /// at that name, or the vetted one only through a link. Either way there is no
    /// descriptor worth keeping, and unlike [`ByPath`](Self::ByPath) this is a
    /// *substitution*, costing that root its mitigation for the session — hence a record.
    Unpinned,
}

/// `/` as a bare directory descriptor, for the capability probe alone.
///
/// No pin to measure it against, and none wanted: the probe asks what the kernel can do and
/// not what any grant holds, which is why it is `/` and not one of the policy's roots.
fn probe_subject() -> Option<OwnedFd> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open("/")
        .ok()
        .map(OwnedFd::from)
}

/// What the probe said of this kernel's `openat2` with the resolve flags [`FsGuard`] roots
/// its accesses with. `Present` is "not shown absent", not a measured yes: only the errnos
/// [`openat2_support_from`] names are a capability verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Openat2 {
    /// Accesses resolve beneath a descriptor held on their root.
    Present,
    /// Accesses resolve by path, bounded by the per-access confirmation alone.
    Absent,
}

/// Whether this kernel resolves beneath a descriptor, asked once per [`FsGuard`].
fn openat2_support() -> Openat2 {
    openat2_support_from(|| {
        let slash = probe_subject().ok_or(nix::errno::Errno::ENOTDIR)?;
        kernel_probe(&slash)
    })
}

/// Ask the kernel the question an access will ask, in a form that commits to nothing.
///
/// `openat2` on `"."` beneath a descriptor, with the resolve flags every access uses: a
/// probe asking anything narrower could answer differently from the call it stands in for.
fn kernel_probe(dir: &OwnedFd) -> nix::Result<OwnedFd> {
    let how = OpenHow::new()
        .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
        .resolve(BENEATH);

    nix::fcntl::openat2(dir, ".", how)
}

/// Whether `probe`'s answer says this kernel has `openat2` with the resolve flags.
///
/// Split from the kernel it asks because the decision is which errnos are a *capability*
/// verdict, and no CI runner is old enough to produce them. Only the four below are:
/// anything else — `EACCES` on `/`, say — says nothing about `openat2` and must leave
/// rooting on, since switching it off for every root on an unrelated errno is a hole both
/// test suites would pass.
fn openat2_support_from(probe: impl FnOnce() -> nix::Result<OwnedFd>) -> Openat2 {
    match probe() {
        Ok(_) => Openat2::Present,
        Err(
            nix::errno::Errno::ENOSYS
            | nix::errno::Errno::EINVAL
            | nix::errno::Errno::E2BIG
            | nix::errno::Errno::EOPNOTSUPP,
        ) => Openat2::Absent,
        Err(_) => Openat2::Present,
    }
}

/// What a directory holds, as one listing read off a single descriptor.
///
/// Owned rather than an iterator because the entries come from a descriptor opened beneath
/// a granted root: `std::fs::ReadDir` can only be built from a path, so handing one back
/// would mean resolving the directory a second time — the window the descriptor closes.
/// `.` and `..` are not entries here: `readdir(2)` reports both and `std` filters them, so
/// a listing built off a descriptor has to filter them too or every directory grows two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// Every entry the directory held, in the order the filesystem reported them.
    pub entries: Vec<Listed>,
}

/// One entry of a [`Listing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// The entry's name within its directory, never a path.
    pub name: OsString,
    /// Whether the entry is a directory, following no symlink to decide.
    pub directory: bool,
}

/// A path the policy allows, and the granted root an access resolves it beneath.
struct Permitted {
    resolved: PathBuf,
    root: Option<Rooted>,
}

/// The descriptor a permitted access resolves beneath, with the granted path it was opened
/// on — which is what the remainder is measured against.
struct Rooted {
    dir: Arc<OwnedFd>,
    granted: PathBuf,
}

/// Open `resolved` beneath the root it was permitted under, rather than by its own path.
///
/// The relative part comes off the *canonical* resolution and never off the caller's
/// spelling, so what the kernel resolves holds no `..`, no `.` and no symlink — which is
/// why [`BENEATH`]'s `RESOLVE_NO_SYMLINKS` costs nothing. An empty remainder means the
/// grant itself, which `openat2` will not take, so it becomes `"."`.
fn beneath(
    root: &Rooted,
    resolved: &Path,
    flags: OFlag,
    mode: nix::sys::stat::Mode,
) -> io::Result<OwnedFd> {
    let rest = resolved.strip_prefix(&root.granted).unwrap_or(resolved);
    let rest = match rest.as_os_str().is_empty() {
        true => Path::new("."),
        false => rest,
    };

    let how = OpenHow::new()
        // `O_CLOEXEC` by hand: `OpenOptions` adds it and `openat2` does not, and without it
        // the agent's own commands inherit every handle an access opens.
        .flags(flags | OFlag::O_CLOEXEC)
        .mode(mode)
        .resolve(BENEATH);

    nix::fcntl::openat2(root.dir.as_ref(), rest, how).map_err(io::Error::from)
}

/// The same listing from a `std` iterator, for the grants with no descriptor to read off.
///
/// `std` already filters `.` and `..` and already falls back to `lstat` on `DT_UNKNOWN`, so
/// this is the shorter half: the two branches differ in where the entries come from and
/// agree on what a [`Listed`] means.
fn listing_by_path(entries: ReadDir) -> io::Result<Listing> {
    entries
        .map(|entry| {
            let entry = entry?;
            Ok(Listed {
                directory: entry.file_type().is_ok_and(|kind| kind.is_dir()),
                name: entry.file_name(),
            })
        })
        .collect::<io::Result<Vec<_>>>()
        .map(|entries| Listing { entries })
}

/// Read every entry of the directory `dir` holds open, as a [`Listing`].
fn listing(dir: OwnedFd) -> io::Result<Listing> {
    use std::os::unix::ffi::OsStrExt;

    let entries = entries_at(dir)?
        .into_iter()
        .map(|(name, kind)| Listed {
            name: OsStr::from_bytes(&name).to_owned(),
            directory: kind == Some(nix::dir::Type::Directory),
        })
        .collect();

    Ok(Listing { entries })
}

/// Every entry of the directory `dir` holds open, with its type, dropping `.` and `..`.
///
/// Two passes, because the `fstatat` the second needs borrows the directory that `iter`
/// borrows mutably: names and whatever the `dirent` carried first, then the unknowns.
/// `None` out means the type could not be established at all, which every caller reads as
/// neither a directory to descend nor a file to collect — the safe answer for both.
fn entries_at(dir: OwnedFd) -> io::Result<Vec<(Vec<u8>, Option<nix::dir::Type>)>> {
    let mut dir = nix::dir::Dir::from_fd(dir)?;

    // `flatten`, not `?`: one unreadable `dirent` costs that entry and not the whole
    // directory, which is what the by-path walk's `entries.flatten()` did. Aborting here
    // would discard the entries already read and mark nothing partial.
    let mut entries = Vec::new();
    for entry in dir.iter().flatten() {
        let name = entry.file_name().to_bytes().to_vec();
        if name == b"." || name == b".." {
            continue;
        }
        entries.push((name, entry.file_type()));
    }

    Ok(entries
        .into_iter()
        .map(|(name, kind)| match kind {
            Some(kind) => (name, Some(kind)),
            None => {
                let kind = stat_kind(&dir, &name);
                (name, kind)
            }
        })
        .collect())
}

/// The type of `name` under `dir`, following no link to find out.
///
/// The `DT_UNKNOWN` fallback, which `std::fs::DirEntry::file_type` performs for free and
/// `nix`'s does not: without it a filesystem that reports no type in the `dirent` — XFS
/// without `ftype=1`, some network filesystems — leaves every entry unclassified.
fn stat_kind(dir: &nix::dir::Dir, name: &[u8]) -> Option<nix::dir::Type> {
    let name = CString::new(name).ok()?;
    let at = nix::sys::stat::fstatat(
        dir,
        name.as_c_str(),
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .ok()?;

    match at.st_mode & libc::S_IFMT {
        libc::S_IFDIR => Some(nix::dir::Type::Directory),
        libc::S_IFREG => Some(nix::dir::Type::File),
        libc::S_IFLNK => Some(nix::dir::Type::Symlink),
        _ => None,
    }
}

/// Open the single component `name` as a directory beneath `parent`.
///
/// One component, so the resolve flags have nothing to traverse: they are here because a
/// `name` that became a symlink to a directory must refuse rather than be descended, which
/// is the same rule the walk's own symlink test states for the entries it can classify.
fn open_dir_at(parent: &OwnedFd, name: &[u8]) -> io::Result<OwnedFd> {
    let name = CString::new(name).map_err(io::Error::other)?;
    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
        .resolve(BENEATH);

    nix::fcntl::openat2(parent, name.as_c_str(), how).map_err(io::Error::from)
}

/// Where `resolved` sits relative to a set of granted roots.
enum Containment {
    /// Inside a root that still holds the object the policy granted it on, carrying that
    /// root's descriptor where it has one — what the access then resolves beneath.
    Inside(Option<Rooted>),
    /// Inside no such root, carrying the root that matched the spelling but had moved: a
    /// second measurement to find out which can disagree with the first.
    Outside(Option<Replacement>),
}

/// A granted root whose spelling matched and whose object did not.
struct Replacement {
    granted: PathBuf,
    vetted: ObjectId,
    opened: ObjectId,
}

/// The root the requested spelling names, when it no longer holds the object it was vetted
/// on. Lexical, not by nearest resolving ancestor, since a measurement after resolution is
/// one the substitute chose. Two forms cover what one cannot: `starts_with` compares whole
/// components, so `root/link/../..` names the root while collapsing out of it, while
/// `other/../root` matches only once collapsed (`context/decision-policy.md`).
fn moved_root(requested: &Path, roots: &[Root]) -> Option<Replacement> {
    let collapsed = collapsed(requested).filter(|form| form != requested);

    [Some(requested), collapsed.as_deref()]
        .into_iter()
        .flatten()
        .find_map(|form| match contains(form, roots) {
            Containment::Outside(moved) => moved,
            Containment::Inside(_) => None,
        })
}

/// `requested` made absolute with `.` and `..` resolved away, without touching the
/// filesystem. Not a `canonicalize`: a `..` above a symlink collapses to the link's parent
/// here, and to its target's parent in the kernel, hence one of two forms tested, not a
/// replacement for the spelling. `None` where there is no cwd to make `requested` absolute.
fn collapsed(requested: &Path) -> Option<PathBuf> {
    let absolute = match requested.is_absolute() {
        true => requested.to_path_buf(),
        false => env::current_dir().ok()?.join(requested),
    };

    let mut form = PathBuf::new();
    for part in absolute.components() {
        match part {
            Component::ParentDir => {
                form.pop();
            }
            Component::CurDir => {}
            named => form.push(named),
        }
    }

    Some(form)
}

/// Find the root that covers `resolved`, confirming each candidate's object as it goes.
/// `Path::starts_with` compares whole components, not string prefixes, so `/work-secrets`
/// does not match the root `/work`. The first root both lexical and confirmed wins: nested
/// and sibling grants overlap, so a moved root must not deny a path another root still
/// covers. One that cannot be measured accuses nothing and grants nothing.
fn contains(resolved: &Path, roots: &[Root]) -> Containment {
    let mut moved = None;
    let mut confirmed = None;

    for root in roots
        .iter()
        .filter(|root| resolved.starts_with(root.vetted.path()))
    {
        match root.vetted.confirm() {
            // The first confirmed root settles the verdict, but the scan continues for one
            // that also holds a descriptor: overlapping grants mean the root that matched
            // first may be the one with no directory to resolve beneath, and taking its
            // answer would send an access by path that another root could have rooted.
            // Verdict-neutral — `Inside` either way.
            Confirmation::Vetted => match &root.dir {
                Some(dir) => {
                    return Containment::Inside(Some(Rooted {
                        dir: Arc::clone(dir),
                        granted: root.vetted.path().to_path_buf(),
                    }));
                }
                None => confirmed = Some(()),
            },
            Confirmation::Replaced(opened) => {
                moved.get_or_insert_with(|| Replacement {
                    granted: root.vetted.path().to_path_buf(),
                    vetted: root.vetted.object(),
                    opened,
                });
            }
            Confirmation::Unmeasurable => {}
        }
    }

    match confirmed {
        Some(()) => Containment::Inside(None),
        None => Containment::Outside(moved),
    }
}

/// Refuse `requested`, recording which of the two reasons the gate decided on. One
/// function for both, so a path under a substituted root answers alike whether or not it
/// exists — present and absent reading apart would be a one-bit oracle.
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

/// Allow `resolved` only if it sits inside one of `roots`, recording a refusal. Only a
/// refusal: passing the gate is not yet an access, so the `allowed` belongs to the entry
/// point that performs one, and a bare check that succeeds records nothing (#182). `roots`
/// has to be the set `access` names: a denial reports the access, so handing it the other
/// axis's roots would record a true verdict with a false reason.
fn permit(
    resolved: PathBuf,
    roots: &[Root],
    requested: &Path,
    access: Access,
) -> Result<Permitted, SandboxError> {
    // Before the resolution is judged: a link out of a substituted root lands wherever the
    // substitute points, and an `Ok` there beside an absent name's refusal is a bit about it.
    if let Some(moved) = moved_root(requested, roots) {
        return Err(deny(Some(moved), requested, access));
    }

    // And no reason comes off the resolution: a link planted in a root that *confirms*
    // resolves into one that does not, which is the same bit the other way round.
    match contains(&resolved, roots) {
        Containment::Inside(root) => Ok(Permitted { resolved, root }),
        Containment::Outside(_) => Err(deny(None, requested, access)),
    }
}

/// Record what an approved path's access actually did, and nothing about the verdict.
/// Which errnos count as absence is the caller's — `names_nothing` for a path lookup,
/// `listed_nothing` for a directory read — so the record and the error the caller returns
/// cannot disagree about whether the path was there.
fn record<T>(
    outcome: io::Result<T>,
    access: Access,
    requested: &Path,
    absent: fn(&io::Error) -> bool,
) -> io::Result<T> {
    let subject = requested.display().to_string();
    let tool = access.operation();

    match &outcome {
        Ok(_) => crate::AuditEvent::allowed(tool, &subject).emit(),
        Err(source) if absent(source) => crate::AuditEvent::absent(tool, &subject).emit(),
        Err(source) => crate::AuditEvent::denied(tool, &subject, reason(source)).emit(),
    }

    outcome
}

/// The `reason=` an access on an approved path carries when it did not happen: `ELOOP` is
/// the leaf swapped since the check, the one post-gate failure that really is a resolution
/// failure, the rest having found the path and stopped there.
fn reason(source: &io::Error) -> &'static str {
    match source.raw_os_error() {
        Some(libc::EXDEV) => ESCAPED,
        Some(libc::ELOOP) => UNRESOLVABLE,
        _ => INCOMPLETE,
    }
}

/// Open an already-approved path without following a symlink at the leaf, which — the
/// path having been canonical when checked — was swapped in after the check. The path is
/// proven inside a root by now, so there is nothing left to conceal: a file deleted since
/// the check is an absence, while `ELOOP` from `O_NOFOLLOW` is the swap.
fn open(
    options: &mut OpenOptions,
    resolved: &Path,
    requested: &Path,
    access: Access,
) -> Result<File, SandboxError> {
    use std::os::unix::fs::OpenOptionsExt;

    let opened = options.custom_flags(libc::O_NOFOLLOW).open(resolved);

    record(opened, access, requested, names_nothing).map_err(|source| classify(source, requested))
}

/// Sort an error from an already-approved access into absence or refusal.
fn classify(source: io::Error, requested: &Path) -> SandboxError {
    let requested = requested.to_path_buf();
    if names_nothing(&source) {
        SandboxError::NotFound { requested, source }
    } else {
        SandboxError::Unresolvable { requested, source }
    }
}

/// The files a walk returned, and whether it stopped before the tree ended. A bool and
/// not a count: the walk stops at the cap, so it never learns how much was left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadableWalk {
    /// Readable regular files beneath the root, sorted.
    pub files: Vec<PathBuf>,
    /// Whether the cap stopped the walk with tree left unvisited.
    pub truncated: bool,
}

/// Reaches private items because `open` runs after the check has passed: no public call
/// can lose the check-to-open race on purpose.
#[cfg(test)]
#[path = "fs_guard_tests.rs"]
mod tests;
