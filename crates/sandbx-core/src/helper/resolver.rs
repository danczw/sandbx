//! Installing what [`crate::resolver`] rendered: one ordered mount sequence.
//!
//! The order is the whole of it. `MS_REC | MS_PRIVATE` on `/` before any bind, so the mounts
//! are this namespace's own whatever the host's propagation. Runs in stage 1, after `isolate`
//! unshared `CLONE_NEWNS` and before stage 2 exists, so the command inherits the mounts and
//! `mount(2)` is not yet denied; stage 2 could not, `apply` having no namespace to put them in.

use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use nix::mount::{MsFlags, mount};

use crate::SandboxError;
use crate::resolver::File;

/// Permissions on the directory the three bodies are written to, and on the tmpfs over it.
/// Nothing reads them by that path — the binds carry their own inode permissions.
const SOURCE_DIR_MODE: u32 = 0o700;

/// Permissions on each written body, read by the command as the uid that wrote it.
const SOURCE_FILE_MODE: u32 = 0o600;

/// Install `files` as the command's resolution, or say why it could not.
///
/// `None` is the no-op, and the only reason `isolate` may leave `CLONE_NEWNS` out: both read
/// the same [`bounds_resolution`]. Takes what was already resolved rather than the policy —
/// the bodies it installs are rendered from those lookups, which therefore precede it.
///
/// [`bounds_resolution`]: crate::SandboxPolicy::bounds_resolution
pub(super) fn bound_resolution(files: Option<[File; 3]>) -> Result<(), SandboxError> {
    let Some(files) = files else {
        return Ok(());
    };

    detach_mount_propagation()?;

    let source = source_dir()?;

    // The source goes on every path out, and only after the mounts: each bind holds its own
    // reference to the tmpfs, so detaching it leaves what the command reads untouched.
    let installed = files.iter().try_for_each(|file| install(&source, file));
    remove_source(&source);

    installed
}

/// Make `/` and everything under it private, recursively.
///
/// Two things, both before any bind of ours. It stops a mount the host makes *later* from
/// appearing inside: `unshare` leaves a shared `/` a slave, and a slave still receives its
/// master's events. And it makes the outbound half ours rather than a side effect of the copy —
/// a shared `/` is turned slave only because the user namespace was unshared in the same call.
/// `MS_REC`, the type being per mount and `/etc` possibly a mount of its own.
///
/// `EACCES` as much as `EPERM`: a host restricting unprivileged user namespaces — Ubuntu's
/// `kernel.apparmor_restrict_unprivileged_userns` — lets the `unshare` succeed and then denies
/// `CAP_SYS_ADMIN` inside it, which the mount reports as `EACCES`. Refused either way, never
/// run unbounded.
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
            nix::errno::Errno::EACCES => {
                "a host policy denies CAP_SYS_ADMIN inside an unprivileged user namespace, so \
                 resolution cannot be bounded; refusing rather than resolving every name"
            }
            nix::errno::Errno::EPERM => {
                "the kernel refused to detach mount propagation, so resolution cannot be \
                 bounded; refusing rather than resolving every name"
            }
            _ => "could not detach mount propagation from the host",
        },
    })
}

/// Write `file`'s body and bind-mount it over its `/etc` counterpart.
///
/// A bind needs its target to exist already, so an absent one is skipped unless
/// `crate::resolver::File::required` says that leaves resolution unbounded. A symlinked one is
/// bound over its target rather than skipped — see the branch below.
fn install(source: &Path, file: &File) -> Result<(), SandboxError> {
    let name = file.target.file_name().unwrap_or(file.target.as_os_str());
    let written = source.join(name);

    let absent_target = |file: &File| match file.required {
        false => Ok(()),
        true => Err(absent(file.target)),
    };

    let Ok(target) = std::fs::symlink_metadata(file.target) else {
        return absent_target(file);
    };

    // A dangling link is the absent case, not a present one: `symlink_metadata` succeeds on
    // it, and `mount(2)` would then resolve it to nothing and refuse a run that `required:
    // false` says may proceed. An image whose `/run` is not populated yet has one.
    if target.is_symlink() && !file.target.exists() {
        return absent_target(file);
    }

    // `mount(2)` resolves the target, so a bind over a symlink lands on what it points to and
    // leaves the link an ordinary dentry — unlinkable under a write grant on `/etc`, and
    // replaceable with a hosts file of the command's own. NixOS links every `/etc` entry.
    // `resolv.conf` is exempt: a forged one names a nameserver that no policy bounding
    // resolution can reach, every shape that could reach one being refused before the run.
    //
    // So it is bound and not skipped, though `ruleset::rights::opens_as_itself` installs no
    // rule for it: the asymmetry is the point. A command whose other grants reach the resolved
    // path then reads sandbx's body there instead of the host's real one.
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

    // A second call, `MS_RDONLY` not taking effect on the bind itself. Not cosmetic: writable,
    // a policy granting write under `/etc` would let the command append its own names. Stage
    // 2's filter denies `mount(2)`, so this is the last word on it.
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
        // `create_new`, so a planted symlink is a refusal rather than a write through it.
        .create_new(true)
        .mode(SOURCE_FILE_MODE)
        .open(path)
        .and_then(|mut file| file.write_all(body.as_bytes()))
        .map_err(refused)
}

/// A tmpfs of this namespace's own to write the three bodies into, before they are bind-mounted.
///
/// A tmpfs and not a plain directory because the bodies must never be *unlinked* while the
/// binds are up: `/proc/self/fd` reads an unlinked file's path back with `" (deleted)"`
/// appended, which is the spelling `ruleset::opened::open_grant` compares a granted path
/// against — so every grant naming one of the three would be refused. `remove_source` takes
/// them out of reach without unlinking them.
///
/// Created rather than opened, so a name already taken is a refusal, and named for the clock
/// as well as this process, so a predictable name is not one a local user can plant first.
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
        // The one path out that `bound_resolution`'s `remove_source` does not cover.
        let _ = std::fs::remove_dir(&path);

        SandboxError::NamespaceSetupFailed {
            detail: "could not mount a tmpfs to write the files that bound resolution into",
        }
    })?;

    Ok(path)
}

/// Detach the tmpfs the bodies were written to, and remove the directory it was mounted on.
///
/// `MNT_DETACH`, the binds being references to it, and *not* by unlinking, for the reason
/// `source_dir` gives: the command goes on reading the bodies while nothing has a path to
/// them. Best-effort, a failure leaving an empty 0700 directory and nothing the policy claims.
fn remove_source(source: &Path) {
    let _ = nix::mount::umount2(source, nix::mount::MntFlags::MNT_DETACH);
    let _ = std::fs::remove_dir(source);
}
