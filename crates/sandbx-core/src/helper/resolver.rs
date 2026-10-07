//! Installing a bounded resolver: one ordered mount sequence, in a mount namespace of the
//! command's own.
//!
//! What gets installed is [`crate::resolver`]'s; this is the part that touches the kernel, and
//! the order is the whole of it — `MS_REC | MS_PRIVATE` on `/` before any mount, or every bind
//! below propagates to the host's `/etc` and sandbx has rewritten the machine's resolution.
//!
//! Runs in stage 1, after `isolate` has unshared `CLONE_NEWNS` and before stage 2 exists, so
//! the command inherits the mounts and seccomp is not yet installed to deny `mount(2)`. Stage 2
//! cannot do this: `apply` has no namespace to put them in.

use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use nix::mount::{MsFlags, mount};

use crate::SandboxError;
use crate::resolver::File;

/// Permissions on the directory the three bodies are written to before they are mounted, and
/// on the tmpfs mounted over it.
///
/// The files are only ever read through the bind mounts, which carry their own inode
/// permissions; this is what keeps the window before the tmpfs is detached from being a
/// world-readable one.
const SOURCE_DIR_MODE: u32 = 0o700;

/// Permissions on each written body. Read by the command as the same uid that wrote it, the
/// user namespace mapping that uid to itself.
const SOURCE_FILE_MODE: u32 = 0o600;

/// Install `files` as the command's resolution, or say why it could not.
///
/// A no-op for `None`, which is the only reason `isolate` may leave `CLONE_NEWNS` out: both
/// come from the same [`bounds_resolution`], so a namespace this needs cannot be one that was
/// never unshared.
///
/// Takes what was already resolved rather than the policy: the lookups have to happen before
/// the unshare, and this has to happen after it.
///
/// [`bounds_resolution`]: crate::SandboxPolicy::bounds_resolution
pub(super) fn bound_resolution(files: Option<[File; 3]>) -> Result<(), SandboxError> {
    let Some(files) = files else {
        return Ok(());
    };

    detach_mount_propagation()?;

    let source = source_dir()?;

    // Every mount is attempted before the source goes, and the source goes on every path out:
    // each bind holds its own reference to the tmpfs, so detaching it takes away the last path
    // by which anything could reach the bodies and leaves what the command reads untouched.
    let installed = files.iter().try_for_each(|file| install(&source, file));
    remove_source(&source);

    installed
}

/// Make `/` and everything under it private, recursively.
///
/// Before any mount of ours: a mount namespace from `unshare` inherits the propagation type of
/// what it copied, and a host whose `/` is shared — systemd makes it so — would receive every
/// bind below into its own `/etc`. The run would then have replaced the machine's resolver
/// configuration, which is both an escape and a wrecked host.
///
/// `MS_REC`, because the propagation type is per mount and `/etc` may be a mount of its own.
fn detach_mount_propagation() -> Result<(), SandboxError> {
    mount(
        None::<&Path>,
        Path::new("/"),
        None::<&Path>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&Path>,
    )
    .map_err(|errno| SandboxError::NamespaceSetupFailed {
        detail: match errno {
            nix::errno::Errno::EPERM => {
                "kernel refused to detach mount propagation, so bounding resolution would \
                 replace the host's own /etc; refusing rather than doing that"
            }
            _ => "could not detach mount propagation from the host",
        },
    })
}

/// Write `file`'s body and bind-mount it over its `/etc` counterpart.
///
/// Skips a target that does not exist, or is a symlink, unless the file says it must refuse —
/// a bind mount needs the target to be there already, and `crate::resolver::File::required` is
/// where the difference between "nothing to bound here" and "nothing can be bounded" is decided.
fn install(source: &Path, file: &File) -> Result<(), SandboxError> {
    let name = file.target.file_name().unwrap_or(file.target.as_os_str());
    let written = source.join(name);

    let Ok(target) = std::fs::symlink_metadata(file.target) else {
        return match file.required {
            false => Ok(()),
            true => Err(absent(file.target)),
        };
    };

    // `mount(2)` resolves the target path, so a bind over a symlink lands on what the link
    // points to and leaves the link itself an ordinary dentry — one that a policy granting
    // write under `/etc` can unlink and replace with a hosts file of the command's own, the
    // read-only remount below being on a path nothing then opens. NixOS links every `/etc`
    // entry into the store, so this is a host shape and not a contrived one.
    //
    // `resolv.conf` is exempt, systemd-resolved making it a symlink nearly everywhere: a
    // forged one names a nameserver that no policy bounding resolution can reach, every shape
    // that could reach one being refused before the run starts.
    if target.is_symlink() && file.required {
        return Err(symlinked(file.target));
    }

    write_body(&written, &file.body)?;

    mount(
        Some(written.as_path()),
        file.target,
        None::<&Path>,
        MsFlags::MS_BIND,
        None::<&Path>,
    )
    .map_err(|_| mount_failed(file.target))?;

    // A second call, `MS_RDONLY` not taking effect on the bind itself. Not cosmetic: with the
    // mount writable, a policy that also grants write under `/etc` would let the command
    // append a line to its own hosts file and resolve anything it liked. Stage 2's filter
    // denies `mount(2)`, so this is the last word on it.
    mount(
        None::<&Path>,
        file.target,
        None::<&Path>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&Path>,
    )
    .map_err(|_| mount_failed(file.target))
}

/// Why a host with no `target` cannot bound resolution, and what would let it.
fn absent(target: &Path) -> SandboxError {
    SandboxError::NamespaceSetupFailed {
        detail: match target.to_str() {
            Some("/etc/hosts") => {
                "this host has no /etc/hosts, and that file is the whole of a bounded \
                 resolver, so --allow-dns cannot be honoured here"
            }
            _ => {
                "this host has no /etc/nsswitch.conf, so glibc would keep its built-in dns \
                 source and resolve a name --allow-dns never listed; an empty file at that \
                 path is enough, and is what a musl-only image is missing"
            }
        },
    }
}

/// Why a symlinked `target` cannot bound resolution.
fn symlinked(target: &Path) -> SandboxError {
    SandboxError::NamespaceSetupFailed {
        detail: match target.to_str() {
            Some("/etc/hosts") => {
                "/etc/hosts is a symlink on this host, so replacing it would leave the link \
                 itself writable under a write grant on /etc — refusing rather than claiming \
                 a bound the command could undo"
            }
            _ => {
                "/etc/nsswitch.conf is a symlink on this host, so replacing it would leave \
                 the link itself writable under a write grant on /etc, and a restored dns \
                 source resolves every name"
            }
        },
    }
}

/// Why a bind over `target` failed, naming the consequence rather than the call.
///
/// Which file, rather than the errno: `NamespaceSetupFailed` carries a `&'static str`, and
/// the three mounts fail for different reasons about resolution.
fn mount_failed(target: &Path) -> SandboxError {
    SandboxError::NamespaceSetupFailed {
        detail: match target.to_str() {
            Some("/etc/hosts") => "could not replace /etc/hosts with the resolved names",
            Some("/etc/nsswitch.conf") => {
                "could not replace /etc/nsswitch.conf, which is what leaves glibc no dns \
                 source to resolve an unlisted name by"
            }
            _ => "could not replace /etc/resolv.conf",
        },
    }
}

/// Write `body` to `path`, readable by nothing but this uid.
fn write_body(path: &Path, body: &str) -> Result<(), SandboxError> {
    use std::io::Write as _;

    let refused = |_| SandboxError::NamespaceSetupFailed {
        detail: "could not write the files that bound resolution",
    };

    std::fs::OpenOptions::new()
        .write(true)
        // `create_new`, so an existing name — a symlink planted at a predictable path — is a
        // refusal rather than a write through it.
        .create_new(true)
        .mode(SOURCE_FILE_MODE)
        .open(path)
        .and_then(|mut file| file.write_all(body.as_bytes()))
        .map_err(refused)
}

/// A tmpfs of this namespace's own to write the three bodies into, before they are bind-mounted.
///
/// A tmpfs and not a plain directory, because the bodies must never be *unlinked* while the
/// binds are up: `/proc/self/fd` reads an unlinked file's path back with `" (deleted)"`
/// appended, so the command would see its own `/etc/hosts` under a path no policy names, and
/// anything comparing a descriptor against the path it was opened by is comparing two
/// different strings. `remove_source` takes the bodies out of reach without unlinking them.
///
/// Under `std::env::temp_dir`, which needs no grant: nothing of this outlives the mounts, and
/// the command never reads it by name. Created rather than opened, so a name already taken is
/// a refusal, and named for this process *and* the clock, so a name a local user can predict
/// is not one they can plant ahead of a run.
fn source_dir() -> Result<PathBuf, SandboxError> {
    let path = std::env::temp_dir().join(format!(
        "sandbx-resolver-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.subsec_nanos())
    ));

    std::fs::DirBuilder::new()
        .mode(SOURCE_DIR_MODE)
        .create(&path)
        .map_err(|_| SandboxError::NamespaceSetupFailed {
            detail: "could not create a directory to write the files that bound resolution",
        })?;

    mount(
        Some(Path::new("tmpfs")),
        path.as_path(),
        Some(Path::new("tmpfs")),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(format!("mode={SOURCE_DIR_MODE:o}").as_str()),
    )
    .map_err(|_| {
        // The directory was created and nothing is mounted on it, so this is the one path out
        // that `bound_resolution`'s `remove_source` does not cover.
        let _ = std::fs::remove_dir(&path);

        SandboxError::NamespaceSetupFailed {
            detail: "could not mount a tmpfs to write the files that bound resolution into",
        }
    })?;

    Ok(path)
}

/// Detach the tmpfs the bodies were written to, and remove the directory it was mounted on.
///
/// Best-effort, and after the mounts: each bind over `/etc` holds its own reference to that
/// filesystem, so the command goes on reading the bodies while no process — this namespace's
/// or the host's — has a path to them any more. Lazily, because the binds are references to
/// it; and *not* by unlinking, for the reason `source_dir` gives.
///
/// A failure leaves an empty 0700 directory in `/tmp` and changes nothing the policy claims,
/// so it is not worth failing a run that is otherwise fully bounded.
fn remove_source(source: &Path) {
    let _ = nix::mount::umount2(source, nix::mount::MntFlags::MNT_DETACH);
    let _ = std::fs::remove_dir(source);
}
