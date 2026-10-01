use crate::{HelperArgs, SandboxError};

/// The Landlock ABI [`apply`] hard-requires, and the newest one it negotiates for.
///
/// `SECURITY.md` claims "Landlock, ABI 5 minimum" and refusal to run on a kernel
/// older than 6.10; this pair is the only place that floor is *enforced*. The
/// same number is also stated in prose in `README.md`, in this crate's
/// `Cargo.toml` and in `ci.yml`, and nothing checks those against this value —
/// so they move in the same change.
///
/// ABI 5 is a floor rather than a preference. Landlock leaves any access type
/// *not* in the handled set unrestricted everywhere, so pinning a lower ABI does
/// not enforce less — it leaves whole categories unguarded. That is how
/// `truncate(2)` was once permitted on any file regardless of policy. So
/// [`BASELINE_ABI`] is attached under `CompatLevel::HardRequirement`, making an
/// older kernel a refusal instead of a silent hole.
///
/// [`LATEST_ABI`] is the opposite: handled best-effort, so rights the running
/// kernel happens to have are enforced and the rest are dropped rather than
/// failing the whole ruleset.
///
/// Changing either value changes what sandbx promises, so `SECURITY.md` and the
/// kernel floor quoted in `README.md` move in the same change.
pub(crate) const BASELINE_ABI: landlock::ABI = landlock::ABI::V5; // Linux 6.10: Truncate, Refer, IoctlDev

/// Newest ABI [`apply`] negotiates for, best-effort. See [`BASELINE_ABI`].
pub(crate) const LATEST_ABI: landlock::ABI = landlock::ABI::V9; // Linux 6.15: ResolveUnix

/// Supervise a sandboxed command: build the namespaces, then run the inner stage
/// inside them.
///
/// This is stage 1 of two. It creates the kernel namespaces the command will live
/// in, hardens the process state that is inherited across `exec`, and then re-execs
/// this same binary once more — into [`exec_inner`], which applies the restrictions
/// that must not touch this process and becomes the command.
///
/// The second re-exec exists for one reason: `unshare(CLONE_NEWPID)` does not move
/// the caller into the new PID namespace, only its children. So the *next* process
/// is PID 1 of it, and spawning one is what the fix for #28 needs. Doing that with
/// `fork` would mean `unsafe` and an async-signal-safety hazard in the
/// `fork`/`exec` window; letting `Command::spawn` do the forking keeps every call
/// here a safe one, which is why `unsafe_code = "forbid"` still holds.
///
/// Intended to run in a freshly executed helper process, never inside sandbx:
/// the namespaces and the capability drops are irreversible for this process, so
/// doing them in sandbx would cage the harness itself.
///
/// On success this never returns: it exits with whatever the command exited with.
/// Any return is an error, and the caller must exit non-zero rather than continue —
/// a helper that fell through to running the command unrestricted would be the
/// exact failure the sandbox exists to prevent.
pub fn exec_sandboxed(argv: &[String]) -> Result<std::convert::Infallible, SandboxError> {
    // Decoded for this stage's own use — it needs to know whether the policy
    // grants network before choosing the unshare flags. What gets passed on is the
    // argv it was given, verbatim: a re-encode here would be a second chance for
    // the policy to drift on its way to the stage that enforces it.
    let request = HelperArgs::decode(argv)?;

    // Resolved before the namespaces exist, so a failure to find our own binary
    // happens while nothing has been changed yet.
    let exe = crate::command::current_exe()?;

    prepare_supervisor(&request.policy)?;

    // The workspace bans `Command::new` so nothing can spawn around the sandbox.
    // This is sanctioned: what it spawns is this same binary in inner mode, which
    // restricts itself before becoming the command.
    let spawned = {
        #[allow(clippy::disallowed_methods)]
        std::process::Command::new(exe)
            .arg(crate::HELPER_INNER_FLAG)
            // So the inner stage can confirm we are still here before it hands
            // control to the command. Our own pid, in host numbering, which is
            // what the inner stage will read back out of `/proc`.
            .arg(std::process::id().to_string())
            .args(argv)
            .spawn()
    };

    let mut child = spawned.map_err(|source| SandboxError::SpawnFailed {
        detail: "could not start the inner sandbox stage",
        source,
    })?;

    let status = child.wait().map_err(|source| SandboxError::SpawnFailed {
        detail: "could not wait for the sandboxed command",
        source,
    })?;

    relay(status)
}

/// Exit the way the inner stage exited.
///
/// The caller reads this process's status as the command's, so anything less than
/// a faithful relay would misreport what happened: a signalled death reported as
/// an exit code loses the fact that it was killed, and `sandbx-cli` and the `bash`
/// tool both branch on that distinction.
///
/// Re-raising rather than exiting with `128 + signal` is what makes the status
/// genuinely *signalled* rather than merely numbered like one. It cannot always
/// work, because two dispositions are not ours: Rust's runtime sets `SIGPIPE` to
/// `SIG_IGN`, and installs a `SIGSEGV`/`SIGBUS` handler to report stack overflow.
/// Raising one of those at ourselves therefore returns instead of killing us, and
/// the numbered form is what the caller sees — which is how a shell encodes the
/// same fact, and what `sandbx-cli` derives from a signalled status regardless.
/// Resetting the disposition first would make it exact, and needs `sigaction`,
/// which is `unsafe` and so not available to this crate.
fn relay(status: std::process::ExitStatus) -> Result<std::convert::Infallible, SandboxError> {
    use std::os::unix::process::ExitStatusExt;

    if let Some(code) = status.code() {
        std::process::exit(code);
    }

    if let Some(signal) = status.signal() {
        if let Ok(signal) = nix::sys::signal::Signal::try_from(signal) {
            let _ = nix::sys::signal::raise(signal);
        }
        std::process::exit(128 + signal);
    }

    // Neither an exit code nor a signal: nothing sensible to relay, so refuse
    // rather than invent a success.
    std::process::exit(1)
}

/// Build the namespaces and drop what must be dropped before the `exec`.
///
/// Split out from [`apply`] because these two steps are the ones that have to
/// happen in the *supervisor*, not in the stage that becomes the command:
///
/// - the namespaces, because `CLONE_NEWPID` only places this process's children,
///   so unsharing here is what makes the inner stage PID 1;
/// - the capability drops, because `PR_CAPBSET_DROP` needs `CAP_SETPCAP` in the
///   effective set, which an unprivileged process only ever holds inside a user
///   namespace it just created. All four sets and `RLIMIT_CORE` are inherited
///   across `fork` and `exec`, so dropping them here still covers the command.
fn prepare_supervisor(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    isolate(policy)?;

    // After the unshare, not before: entering a fresh user namespace grants the
    // full capability set *within it*, so dropping earlier would be undone.
    harden_process_state()?;

    // Here as well as in the inner stage, so that *every* `exec` this design
    // performs is covered by it rather than only the last one.
    //
    // Splitting the helper in two added an `execve` — this stage into the inner
    // one — that sits after the capability sets are cleared. Without this, what
    // stops a capability being regained across it is that the binary being
    // executed is our own, unprivileged and without file capabilities, plus uid 0
    // being unmapped in the fresh user namespace. Both hold, which is why this is
    // hardening and not a fix. But it makes the guarantee rest on properties of
    // the binary and the uid map rather than on a flag that states it directly,
    // and the flag costs one syscall.
    //
    // Deliberately not removed from the inner stage. It is irreversible and
    // inherited, so the second call is a no-op — but the inner stage must not
    // depend on a caller having set it, since seccomp will not install without it.
    set_no_new_privs()
}

/// Die when the supervisor dies (#28).
///
/// This process is PID 1 of a fresh PID namespace, and the kernel SIGKILLs every
/// remaining process in a namespace whose init exits. So making this process die
/// with its supervisor is what turns the timeout's kill from advisory into
/// unconditional: whatever the command spawned, however it detached itself, it
/// goes when this process goes.
///
/// Two independent paths reach us, deliberately. The supervisor stays in the
/// process group sandbx kills, and so do we — but the command we are about to
/// become may call `setsid` and leave it, which is the whole of #28. The parent
/// death signal does not care: it fires on the supervisor's death, not on group
/// membership, and it survives `execve` of an ordinary binary. Keeping both means
/// neither one is a single point of failure — worth having, because the kernel
/// clears this signal for a secure `exec` (a setuid target or one with file
/// capabilities), where the group kill is then what still reaps us.
///
/// Set before anything else in this stage, so the window in which the supervisor
/// could die unnoticed is as short as the kernel allows. The window is not closed
/// by this alone; `confirm_supervisor` is what closes it.
fn bind_lifetime_to_supervisor() -> Result<(), SandboxError> {
    nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL).map_err(|errno| {
        SandboxError::NamespaceSetupFailed {
            detail: match errno {
                nix::errno::Errno::EPERM => {
                    "kernel refused a parent death signal; the sandboxed command \
                     could outlive the call that started it"
                }
                _ => "could not bind the command's lifetime to its supervisor",
            },
        }
    })
}

/// Refuse to run unless the supervisor is still our parent.
///
/// This is what closes the window [`bind_lifetime_to_supervisor`] cannot: if the
/// supervisor died before the parent death signal was armed, nothing will ever kill
/// this process, and the command would run to completion as PID 1 of a namespace no
/// one is watching. Ordering is what makes the pair complete — arm first, then
/// check. A death before the check is caught by the check; a death after it is
/// caught by the signal that is already armed.
///
/// `getppid` is no use here: this process is PID 1 of a namespace whose parent lives
/// outside it, so the kernel has no number to report and returns 0. `/proc` is still
/// the host's procfs, though — it is not remounted, because that would need
/// `mount(2)`, which the filter denies — so its `ppid` field names the supervisor in
/// host numbering, which is exactly what was passed in.
///
/// Pid reuse cannot produce a false pass: the comparison is against the kernel's
/// live parent link, and an orphan is reparented to init or a subreaper, neither of
/// which can be the pid of a supervisor that just spawned us.
///
/// Runs before Landlock and seccomp, so it needs no grant for `/proc` and no
/// privilege.
fn confirm_supervisor(expected: &str) -> Result<(), SandboxError> {
    let gone = SandboxError::NamespaceSetupFailed {
        detail: "the supervisor process is gone; refusing to run the command \
                 where nothing can reap it",
    };

    let unreadable = SandboxError::NamespaceSetupFailed {
        detail: "could not read this process's parent to confirm the supervisor \
                 is still watching it",
    };

    let stat = std::fs::read_to_string("/proc/self/stat").map_err(|_| unreadable)?;

    // Field 4 of `/proc/pid/stat`, counting from 1. Split after the *last* `)`
    // rather than on whitespace from the start: field 2 is the executable name,
    // unquoted and free to contain spaces and parentheses of its own, so counting
    // from the left is how this kind of parse goes wrong.
    let parent = stat
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(1));

    match parent {
        Some(parent) if parent == expected => Ok(()),
        _ => Err(gone),
    }
}

/// Apply a policy to *this* process, then become the requested command.
///
/// Stage 2 of two, running as the first child of [`exec_sandboxed`] and therefore
/// as PID 1 of the PID namespace it created. Everything here is irreversible and
/// inherited across `exec`, which is what makes the restrictions stick to the real
/// command rather than to this process alone.
///
/// Because this process is fresh, it is single-threaded, and the restriction code
/// runs in an ordinary context — no `fork`/`exec` window, so no
/// async-signal-safety constraint and no `unsafe`.
///
/// On success this never returns: the process image is replaced. Any return is an
/// error, and the caller must exit non-zero rather than continue — a helper that
/// fell through to running the command unrestricted would be the exact failure the
/// sandbox exists to prevent.
pub(crate) fn exec_inner(argv: &[String]) -> Result<std::convert::Infallible, SandboxError> {
    // The supervisor's pid is a positional token ahead of the policy, not part of
    // it: `HelperArgs` describes what the command may do, and this describes who is
    // watching. Keeping them apart leaves the policy grammar and its round-trip
    // untouched, and means a caller reaching `exec_inner` directly cannot pass a
    // policy that smuggles one in.
    let (supervisor, argv) = argv.split_first().ok_or(SandboxError::BadHelperArgs {
        detail: "inner helper mode without a supervisor pid",
    })?;

    let request = HelperArgs::decode(argv)?;

    bind_lifetime_to_supervisor()?;
    confirm_supervisor(supervisor)?;

    apply(&request.policy)?;

    // The workspace bans `Command::new` so nothing can spawn around the sandbox.
    // This is the one sanctioned call: `apply` has already restricted this
    // process, so the command inherits the cage rather than escaping it. The
    // allow is per-call-site, not crate-wide, so any other use still fails the
    // lint.
    let error = {
        use std::os::unix::process::CommandExt;
        #[allow(clippy::disallowed_methods)]
        std::process::Command::new(&request.program)
            .args(&request.args)
            .exec()
    };

    Err(SandboxError::SpawnFailed {
        detail: "could not execute the sandboxed command",
        source: error,
    })
}

/// The Landlock rights an axis grants on a target, narrowed to what that target
/// can carry.
///
/// Pure and total: three axes times a file or a directory is six answers, every
/// one of them assertable with no privilege and no filesystem. The narrowing used
/// to sit in [`fs_rules`] next to the `is_dir()` that drives it, which fused the
/// decision to a probe and so made the file case reachable only by creating a
/// real file on disk (#52).
///
/// Derived from [`Axis::grants`], so a new axis needs no edit here. Before this
/// derived, the axes were a literal list of `(paths, rights)` pairs, and an axis
/// left out of that list did not fail to compile: its paths were never iterated,
/// no rule was installed for them, and the grant was silently absent (#51).
///
/// The three primitives, and why each is a subtraction rather than a plain set:
///
/// - **read** is `from_read` minus `Execute`. `from_read` bundles `Execute` in
///   with `ReadFile`/`ReadDir`, so granting it raw would hand out the right to
///   *run* whatever the path contains, which no axis but `ReadExecute` says (#19).
/// - **write** is `from_all` minus the whole read set, not just `Execute`.
///   `from_all` includes `ReadFile`/`ReadDir`, so taking only `Execute` away left
///   a write grant conferring read at the kernel while `FsGuard` refused it —
///   one policy, two answers, and the write-only drop directory
///   `writable_paths` promises was readable in the child (#49).
/// - **execute** is the single bit, which is why it can be added back on top of
///   read without widening anything else.
///
/// Directory-only rights (`ReadDir`, `MakeDir`, …) are invalid on a regular file
/// and the kernel rejects the whole ruleset if one is attached to it. A policy may
/// name either, so the rights are narrowed to what the target can actually carry.
/// Intersecting rather than substituting keeps that a restriction: a file can
/// never end up with more than the directory case.
///
/// [`Axis::grants`]: crate::Axis::grants
fn rights_for(axis: crate::Axis, target_is_dir: bool) -> landlock::BitFlags<landlock::AccessFs> {
    use landlock::{Access, AccessFs};

    let read_rights = AccessFs::from_read(LATEST_ABI) & !AccessFs::Execute;
    let write_rights = AccessFs::from_all(LATEST_ABI) & !AccessFs::from_read(LATEST_ABI);

    // Destructured, not read field by field — see `Grants`.
    let crate::Grants {
        read,
        write,
        execute,
    } = axis.grants();

    let mut rights = landlock::BitFlags::EMPTY;

    if read {
        rights |= read_rights;
    }
    if write {
        rights |= write_rights;
    }
    if execute {
        rights |= AccessFs::Execute;
    }

    if target_is_dir {
        rights
    } else {
        rights & AccessFs::from_file(LATEST_ABI)
    }
}

/// The Landlock rules [`apply`] will install, as data.
///
/// Split out so the whole filesystem mapping can be asserted without root, a
/// network namespace or a Landlock-capable kernel — `apply` itself needs all
/// three, which is why it went untested for so long (#52). The only thing this
/// touches outside the policy is whether each path is a directory, and that is
/// precisely what decides the narrowing below.
///
/// What a grant confers is [`rights_for`]'s business; all this adds is the one
/// probe that decision needs — whether the target is a directory.
///
/// `is_dir()` reports `false` for every error it meets, which would silently drop
/// directory-only rights. That is latent rather than live: a path `is_dir()` could
/// not inspect — a dangling symlink, an unsearchable parent — is also a path
/// [`apply`]'s next line cannot open, so `PathFd::new` turns it into a refusal
/// before the narrowed rule reaches the kernel. Propagating it here would add a
/// `Result` to the seam for an error the following line already catches.
///
/// A path that changes kind between the probe and the open fails safe in both
/// directions: a directory taken for a file loses directory-only rights, which is
/// a restriction, and a file taken for a directory makes the kernel reject the
/// whole ruleset, which is a refusal.
fn fs_rules(
    policy: &crate::SandboxPolicy,
) -> Vec<(&std::path::Path, landlock::BitFlags<landlock::AccessFs>)> {
    policy
        .granted_paths()
        .map(|(axis, path)| (path, rights_for(axis, path.is_dir())))
        .collect()
}

fn apply(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    use landlock::{
        Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };

    // The namespaces and the capability drops already happened, in the supervisor
    // that spawned this process — see `prepare_supervisor`. Both are inherited, so
    // what is left here is everything that must apply to the command itself and
    // could not be done in a process that still had to spawn one.

    // Installing a seccomp filter requires either CAP_SYS_ADMIN or no_new_privs.
    // Set it explicitly: this process holds no capabilities at all, the supervisor
    // having dropped them. It is irreversible and inherited across exec, which is
    // what makes the filter stick to the real command.
    set_no_new_privs()?;

    deny_dangerous_syscalls(policy)?;

    // Negotiate rather than pin: `handle_access` accumulates (`|=`), so the
    // baseline can be a hard requirement while newer rights stay best-effort.
    // Why ABI 5 is the floor is documented on `BASELINE_ABI`.
    let mut ruleset = Ruleset::default()
        // Refuse a kernel that cannot enforce the baseline, rather than running
        // with a silent hole in it.
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(BASELINE_ABI))
        .map_err(landlock_failed)?
        // Anything newer is a bonus: handled where the kernel has it, dropped
        // where it does not.
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(LATEST_ABI))
        .map_err(landlock_failed)?
        .create()
        .map_err(landlock_failed)?;

    // `fs_rules` decides what to install; this loop only opens the paths.
    for (path, rights) in fs_rules(policy) {
        let fd = PathFd::new(path).map_err(landlock_failed)?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, rights))
            .map_err(landlock_failed)?;
    }

    let status = ruleset.restrict_self().map_err(landlock_failed)?;

    // The kernel may accept a ruleset and enforce only part of it. Partial
    // enforcement is treated as failure: it would leave the caller believing in
    // restrictions that are not actually in place.
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(SandboxError::Unsupported {
            detail: "kernel accepted the ruleset but enforced none of it",
        });
    }

    Ok(())
}

/// Drop capabilities and disable core dumps.
///
/// Landlock and seccomp bound what the sandboxed command can *do*; this bounds
/// what a descendant that somehow survives the kill (#28) can still reach.
/// None of it needs privilege to apply in the general case: every one of these
/// calls only ever removes a right this process already holds, never grants
/// one.
///
/// Deliberately does NOT set `PR_SET_DUMPABLE`: the kernel resets that flag to
/// dumpable on every `execve` of an ordinary (non-setuid, no file-capability)
/// binary — see `setup_new_exec` in `fs/exec.c` — so setting it here would
/// only affect this process's own brief pre-exec window, not the command it
/// is about to become. Applying it would be a claim `SECURITY.md` cannot back
/// up, not real hardening; core dumps are already fully covered below via
/// `RLIMIT_CORE`, which — unlike the dumpable flag — does persist across exec.
///
/// The capability *bounding* set is best-effort, and deliberately so. Dropping
/// it needs `CAP_SETPCAP`, which an unprivileged process holds only inside a
/// user namespace it created itself — and not even there when an LSM strips
/// capabilities from such a namespace. AppArmor's
/// `restrict_unprivileged_userns` (default on Ubuntu 24.04+, and set on
/// GitHub's runners) does exactly that: `isolate`'s `unshare` succeeds,
/// but `PR_CAPBSET_DROP` then returns `EPERM`. Treating that as a refusal
/// would take the sandbox away entirely on the most common Linux desktop and
/// CI hosts, in exchange for a bit that cannot be spent: once the four sets
/// below are empty and `no_new_privs` is set, the kernel caps the permitted
/// set of an `execve`d binary at the old one and refuses to raise inheritable
/// or ambient, so a leftover bounding bit can never become privilege. So it is
/// attempted and logged, not enforced — and `SECURITY.md` claims it as
/// best-effort rather than as part of the boundary.
///
/// Order matters within this function: the bounding set is dropped *before*
/// the effective set, not after. `PR_CAPBSET_DROP` itself requires
/// `CAP_SETPCAP` in the effective set — clearing effective first would remove
/// the very right this function needs to drop the bounding set at all.
fn harden_process_state() -> Result<(), SandboxError> {
    use caps::CapSet;

    if let Err(error) = caps::clear(None, CapSet::Bounding) {
        tracing::debug!(
            target: crate::AUDIT_TARGET,
            "could not drop the capability bounding set, leaving it as inherited: {error}"
        );
    }

    for set in [
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
        CapSet::Ambient,
    ] {
        caps::clear(None, set).map_err(hardening_failed)?;
    }

    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0).map_err(
        |errno| SandboxError::ProcessHardening {
            detail: format!("could not set RLIMIT_CORE: {errno}"),
        },
    )?;

    Ok(())
}

/// Set `no_new_privs`, refusing if the kernel will not.
///
/// Shared by both stages. Irreversible and inherited across `exec`, and a
/// precondition for installing a seccomp filter without `CAP_SYS_ADMIN` — so a
/// failure here is a refusal, not something to carry on from.
fn set_no_new_privs() -> Result<(), SandboxError> {
    nix::sys::prctl::set_no_new_privs().map_err(|errno| SandboxError::Seccomp {
        detail: format!("could not set no_new_privs: {errno}"),
    })
}

fn hardening_failed(source: impl std::fmt::Display) -> SandboxError {
    SandboxError::ProcessHardening {
        detail: source.to_string(),
    }
}

/// Syscalls blocked for every sandboxed command, regardless of policy.
///
/// A denylist, not an allowlist. An allowlist is the stronger shape, but sandbx
/// runs arbitrary commands — shells, compilers, package managers — whose syscall
/// use is unbounded, so enumerating it would break real tools constantly. This
/// mirrors what container runtimes settle on for the same reason.
///
/// Landlock cannot express any of these: they are not filesystem access. That is
/// why both layers exist rather than one.
///
/// Lifted out of [`deny_dangerous_syscalls`] so a test can assert the list still
/// contains what `SECURITY.md` claims it does. The filter is built from this and
/// nothing else, so the two cannot drift.
pub const BLOCKED_SYSCALLS: &[libc::c_long] = &[
    // Inspect or modify other processes.
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    // Reshape the filesystem out from under Landlock.
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    // Escape or re-create namespaces, including the netns just entered.
    libc::SYS_setns,
    libc::SYS_unshare,
    // Load code into the kernel.
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_bpf,
    libc::SYS_kexec_load,
    // Kernel keyring: credentials live here.
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_keyctl,
    // Tracing infrastructure, a known side-channel surface.
    libc::SYS_perf_event_open,
    // Handles on another process. `pidfd_getfd` takes a descriptor *out* of a
    // process that holds one — a socket, an open file above the policy — which is
    // not filesystem access, so Landlock cannot express it and `ptrace` being
    // denied does not cover it. `pidfd_open` is how the handle is obtained in the
    // first place, so both go.
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_getfd,
    // userfaultfd hands the faulting process control over when a page fault
    // resolves, which turns any check-then-use in the kernel into an arbitrarily
    // wide window. It is a recurring ingredient in kernel exploits and no coding
    // tool needs it.
    libc::SYS_userfaultfd,
    // io_uring runs operations from a submission queue without issuing the
    // matching syscalls, so a ring set up here would be a route around every
    // rule in this filter — including the `socket(AF_UNIX)` denial that
    // `deny_dangerous_syscalls` adds on top of this list.
    // Deny the ring itself. A coding agent has no need for it, and container
    // runtimes disable it in their default profiles for the same reason.
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    // An anonymous in-memory file has no path on any filesystem, and Landlock
    // binds its rules to inodes and paths — so a payload staged in a memfd sits
    // outside everything the filesystem layer can see. Denying the syscall is the
    // only layer that reaches it.
    //
    // This one has a real compatibility cost, unlike the rest of this list, though
    // a narrower one than it first looked: the heavy users are container runtimes
    // (runc keeps a sealed memfd copy of its own binary and re-execs it from
    // `/proc/self/fd/<n>` as its CVE-2019-5736 self-protection), systemd and snapd.
    // A coding tool does none of that, and running a container runtime in here is
    // already impossible — `unshare` is denied above. An ordinary program can still
    // call it deliberately, which is the case to watch.
    //
    // It is denied because no caller needs it yet, so the restrictive default is
    // the one to start from and loosen on evidence — if a real tool turns out to
    // break, that evidence is a reason to revisit this, possibly as its own policy
    // axis.
    libc::SYS_memfd_create,
    // Whole-machine effects.
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
];

/// The seccomp denylist [`deny_dangerous_syscalls`] will install, as data.
///
/// Split out for the same reason as [`fs_rules`] (#52).
///
/// An empty rule vector means "match this syscall unconditionally", so every
/// listed number takes the filter's match action and everything else is allowed.
fn blocked_syscalls(
    policy: &crate::SandboxPolicy,
) -> Result<std::collections::BTreeMap<libc::c_long, Vec<seccompiler::SeccompRule>>, SandboxError> {
    use std::collections::BTreeMap;

    use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompRule};

    let mut rules = BLOCKED_SYSCALLS
        .iter()
        .copied()
        .map(|nr| (nr, Vec::new()))
        .collect::<BTreeMap<_, _>>();

    // Unix sockets are their own axis, not a sub-case of network. A netns
    // isolates only *abstract* unix sockets; pathname sockets live in the
    // filesystem and cross it freely, so a command that can dial systemd's bus,
    // docker.sock or an ssh-agent can have them act outside the sandbox — which
    // is an escape, not egress. Deliberately not tied to `allows_network`, so
    // granting the internet does not grant this (#8).
    //
    // All-or-nothing: seccomp compares register values, and the path passed to
    // `connect` is behind a pointer it cannot follow. Landlock gained a
    // path-scoped right in ABI V9 (Linux 6.15), which `apply` already handles
    // best-effort; a per-socket grant can follow once that exists in practice.
    //
    // `socketpair` is deliberately left alone: it creates an anonymous pair with
    // no filesystem path, cannot reach a host daemon, and is used routinely by
    // shells. Blocking it would break real tools for no security gain.
    if !policy.allows_unix_sockets() {
        let af_unix = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_UNIX as u64,
        )
        .map_err(seccomp_failed)?;
        rules.insert(
            libc::SYS_socket,
            vec![SeccompRule::new(vec![af_unix]).map_err(seccomp_failed)?],
        );
    }

    Ok(rules)
}

/// Compile [`blocked_syscalls`] into a seccomp filter and install it.
///
/// Blocked calls return `EPERM` rather than killing the process. The syscall
/// does not execute either way; `EPERM` is what tools already expect on hardened
/// systems, so they fail that operation instead of dying mid-run.
fn deny_dangerous_syscalls(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

    let filter = SeccompFilter::new(
        blocked_syscalls(policy)?,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH.try_into().map_err(seccomp_failed)?,
    )
    .map_err(seccomp_failed)?;

    let program: BpfProgram = filter.try_into().map_err(seccomp_failed)?;
    seccompiler::apply_filter(&program).map_err(seccomp_failed)
}

fn seccomp_failed(source: impl std::fmt::Display) -> SandboxError {
    SandboxError::Seccomp {
        detail: source.to_string(),
    }
}

/// Put this process into fresh kernel namespaces.
///
/// Denying network means an empty one: a fresh netns has only a (down) loopback
/// interface and no route anywhere, so there is no network to reach rather than a
/// filtered one. That is stronger than Landlock's network rules, which only cover
/// TCP bind/connect and would leave UDP and raw sockets untouched.
///
/// `CLONE_NEWUSER` is requested alongside because creating any other namespace
/// otherwise needs `CAP_SYS_ADMIN`; a user namespace grants that capability
/// *within the new namespaces only*, which is what lets this work unprivileged.
/// Some distributions restrict unprivileged user namespaces (e.g. AppArmor's
/// `kernel.apparmor_restrict_unprivileged_userns`), and there the call fails —
/// which surfaces as a refusal, never as a silent fallback.
///
/// One `unshare` for all of them rather than one per namespace: the kernel applies
/// the flags together, so there is no window in which the process holds some of the
/// isolation and not the rest, and no second failure path to unwind.
fn isolate(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    use nix::sched::{CloneFlags, unshare};
    use nix::unistd::{getgid, getuid};

    // The PID namespace is unconditional: a guarantee about process lifetime that
    // depended on a policy flag would not be a guarantee. It is also why the user
    // namespace is now unconditional, where it used to come along only when
    // network was denied.
    let mut flags = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWPID;
    if !policy.allows_network() {
        flags |= CloneFlags::CLONE_NEWNET;
    }

    // Captured before the unshare: afterwards this process reads back as the
    // overflow uid, and it is the *real* identity we want to map to itself.
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();

    unshare(flags).map_err(|errno| SandboxError::NamespaceSetupFailed {
        detail: match errno {
            nix::errno::Errno::EPERM => {
                "kernel refused an unprivileged user namespace; unprivileged \
                 userns may be disabled (see kernel.unprivileged_userns_clone \
                 and kernel.apparmor_restrict_unprivileged_userns)"
            }
            _ => "could not create the sandbox namespaces",
        },
    })?;

    map_identity_into_userns(uid, gid);
    Ok(())
}

/// Map the real uid/gid to themselves inside the fresh user namespace.
///
/// Without this the namespace has no map, so the process reads back as the
/// overflow uid (`nobody`) even though its on-host identity is unchanged — a
/// file it writes is still owned by the real user. Tools that branch on
/// `getuid()` see a value that does not match reality; mapping the identity to
/// itself makes the namespace transparent without granting anything, since the
/// process already acts as this uid on the host.
///
/// Best-effort, deliberately. This is not a security control — running as the
/// overflow `nobody` is if anything *more* restrictive, and it is what happened
/// before this map existed. Some environments create the namespace but deny the
/// map: AppArmor's `restrict_unprivileged_userns` (default on Ubuntu 24.04+)
/// leaves an unprivileged userns without `CAP_SETUID`, so the write is refused.
/// Aborting the sandbox there would trade a truthful uid for no sandbox at all,
/// which is the wrong way round — so a failed write leaves the process as
/// `nobody` and the command still runs fully confined.
fn map_identity_into_userns(uid: u32, gid: u32) {
    // `setgroups` must be denied before an unprivileged `gid_map` write, or the
    // kernel rejects it. Denying it is correct anyway: this maps a single gid,
    // so there are no supplementary groups to set. If any write fails the rest
    // are skipped and the namespace simply stays unmapped.
    let mapped = std::fs::write("/proc/self/setgroups", "deny")
        .and_then(|()| std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1")))
        .and_then(|()| std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1")));

    if let Err(error) = mapped {
        tracing::debug!(
            target: crate::AUDIT_TARGET,
            "could not map user namespace identity, running as nobody: {error}"
        );
    }
}

fn landlock_failed(source: impl std::fmt::Display) -> SandboxError {
    // Carry the kernel's own reason: "refused" without a cause is unactionable
    // for whoever has to work out which path or access right it objected to.
    SandboxError::Landlock {
        detail: source.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxPolicy;
    use landlock::AccessFs;

    /// Keep the returned handle bound for the whole test: dropping it deletes
    /// the directory, and `fs_rules` would then take its regular-file branch.
    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// A regular file, since files and directories take different rights.
    fn plain_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let file = dir.path().join("plain.txt");
        std::fs::write(&file, b"x").unwrap();
        file
    }

    /// The single rule produced for `path`.
    ///
    /// Insists on exactly one. Landlock unions the rules for a path, so a path
    /// granted on two axes has no one answer — and silently returning whichever
    /// axis came first would let a test assert against a rule it did not mean.
    fn rule(policy: &SandboxPolicy, path: &std::path::Path) -> landlock::BitFlags<AccessFs> {
        let matches: Vec<_> = fs_rules(policy)
            .into_iter()
            .filter(|(p, _)| *p == path)
            .map(|(_, rights)| rights)
            .collect();

        assert_eq!(
            matches.len(),
            1,
            "expected exactly one rule for {}, got {}",
            path.display(),
            matches.len()
        );
        matches[0]
    }

    /// Every right installed is the one the axis table says, not a second
    /// opinion about it.
    ///
    /// The tests below pin the three axes that exist today by hand; this one is
    /// stated over `Axis::ALL`, so an axis whose rights are never derived — the
    /// failure mode of #51, where the flag round-trips perfectly while granting
    /// nothing — fails here.
    #[test]
    fn rights_follow_the_axis_table() {
        for axis in crate::Axis::ALL {
            let grants = axis.grants();
            let rights = rights_for(axis, true);

            assert!(
                !rights.is_empty(),
                "{axis:?} derives no rights at all, so the grant is silently absent"
            );

            for (right, granted, name) in [
                (AccessFs::ReadFile, grants.read, "read"),
                (AccessFs::ReadDir, grants.read, "read"),
                (AccessFs::WriteFile, grants.write, "write"),
                (AccessFs::MakeDir, grants.write, "write"),
                (AccessFs::Execute, grants.execute, "execute"),
            ] {
                assert_eq!(
                    rights.contains(right),
                    granted,
                    "{axis:?} grants {name}={granted}, but the kernel layer \
                     disagrees about {right:?}"
                );
            }
        }
    }

    /// Every axis keeps its grant on a regular file, minus what a file cannot
    /// carry.
    ///
    /// Directory-only rights (`ReadDir`, `MakeDir`, …) are invalid on a regular
    /// file and the kernel rejects the whole ruleset if one is attached to it, so
    /// a policy naming a file must come out narrowed. Stated over `Axis::ALL`
    /// against the table, and pure: until the narrowing moved into `rights_for`
    /// it could only be exercised by creating a real file on disk (#52).
    #[test]
    fn rights_for_narrows_a_regular_file() {
        for axis in crate::Axis::ALL {
            let grants = axis.grants();
            let on_dir = rights_for(axis, true);
            let on_file = rights_for(axis, false);

            // Narrowing is an intersection, so a file can never end up with
            // more than the directory case.
            assert!(
                on_dir.contains(on_file),
                "{axis:?} on a file gained a right the directory case did not have"
            );

            // But it must not narrow to nothing: a grant that installs an empty
            // right set is a permission silently absent.
            assert!(
                !on_file.is_empty(),
                "{axis:?} on a file derives no rights at all"
            );

            for right in [AccessFs::ReadDir, AccessFs::MakeDir] {
                assert!(
                    !on_file.contains(right),
                    "{axis:?} kept {right:?} on a regular file, which invalidates \
                     the whole ruleset"
                );
            }

            for (right, granted, name) in [
                (AccessFs::ReadFile, grants.read, "read"),
                (AccessFs::WriteFile, grants.write, "write"),
                (AccessFs::Execute, grants.execute, "execute"),
            ] {
                assert_eq!(
                    on_file.contains(right),
                    granted,
                    "{axis:?} grants {name}={granted}, but the file case disagrees \
                     about {right:?}"
                );
            }
        }
    }

    /// Reading must never confer the right to *run* what it can see.
    ///
    /// `AccessFs::from_read` bundles `Execute` with `ReadFile`/`ReadDir`, so this
    /// is a subtraction that has to happen rather than a default (#19).
    #[test]
    fn a_read_grant_never_carries_execute() {
        for target_is_dir in [true, false] {
            let rights = rights_for(crate::Axis::Read, target_is_dir);
            assert!(
                !rights.contains(AccessFs::Execute),
                "a read grant handed out Execute (target_is_dir={target_is_dir})"
            );
            assert!(rights.contains(AccessFs::ReadFile));
        }
    }

    /// The execute axis is the only one that carries it.
    #[test]
    fn only_the_execute_axis_carries_execute() {
        let rights = rights_for(crate::Axis::ReadExecute, true);
        assert!(rights.contains(AccessFs::Execute));
        // Read comes with it by design — see `SandboxPolicy::executable_paths`.
        assert!(rights.contains(AccessFs::ReadFile));
        // But not write.
        assert!(!rights.contains(AccessFs::WriteFile));
    }

    /// A write grant carries neither read nor execute.
    ///
    /// `SandboxPolicy::writable_paths` promises "writable does not imply
    /// readable", and `FsGuard` always kept that promise; the kernel layer did
    /// not, because `from_all` includes `ReadFile`/`ReadDir` and only `Execute`
    /// was being subtracted. Subtracting the whole read set makes a write-only
    /// drop directory genuinely unreadable on both layers (#49).
    #[test]
    fn a_write_grant_carries_neither_read_nor_execute() {
        let rights = rights_for(crate::Axis::Write, true);
        assert!(rights.contains(AccessFs::WriteFile));
        assert!(
            !rights.contains(AccessFs::ReadFile) && !rights.contains(AccessFs::ReadDir),
            "a write-only grant handed out read, so the drop directory is readable"
        );
        assert!(!rights.contains(AccessFs::Execute));
    }

    /// Directory-only rights are invalid on a regular file, and the kernel
    /// rejects the whole ruleset if one is attached to it — so a file rule must
    /// come out narrowed.
    #[test]
    fn a_rule_on_a_regular_file_drops_directory_only_rights() {
        let dir = tempdir();
        let file = plain_file(&dir);
        let policy = SandboxPolicy::default()
            .allow_write(dir.path())
            .allow_write(&file);

        let on_dir = rule(&policy, dir.path());
        let on_file = rule(&policy, &file);

        assert!(
            on_dir.contains(AccessFs::MakeDir),
            "a directory should keep directory-only rights"
        );
        assert!(
            !on_file.contains(AccessFs::MakeDir),
            "a regular file kept a directory-only right, which invalidates the ruleset"
        );
        // Narrowing is an intersection, so the file can never gain anything the
        // directory case did not already have.
        assert!(on_dir.contains(on_file));
    }

    /// Default-deny: nothing granted means nothing installed.
    #[test]
    fn a_policy_with_no_paths_produces_no_rules() {
        assert!(fs_rules(&SandboxPolicy::default()).is_empty());
    }

    /// One rule per *grant*, not per path: a path granted on two axes yields two
    /// rules, which the kernel unions. A grant dropped here is a permission the
    /// command silently does not get.
    #[test]
    fn every_grant_produces_a_rule_even_for_a_repeated_path() {
        let dir = tempdir();
        let file = plain_file(&dir);
        let policy = SandboxPolicy::default()
            .allow_read(&file)
            .allow_write(dir.path())
            .allow_read_execute(dir.path());

        assert_eq!(fs_rules(&policy).len(), 3);
    }

    /// The filter is built from `BLOCKED_SYSCALLS` and nothing else, so the two
    /// cannot drift.
    #[test]
    fn blocked_syscalls_covers_the_whole_denylist() {
        let blocked = blocked_syscalls(&SandboxPolicy::default()).unwrap();

        for nr in BLOCKED_SYSCALLS {
            let rules = blocked
                .get(nr)
                .unwrap_or_else(|| panic!("{nr} missing from the filter"));

            // An entry with rules is matched only for those argument values, so
            // the syscall stays reachable for every other. A listed number must
            // be blocked unconditionally, or the denial is narrower than the
            // list claims.
            assert!(
                rules.is_empty(),
                "{nr} is filtered conditionally, but the denylist claims it outright"
            );
        }
    }

    /// `socket` is blocked conditionally — on the `AF_UNIX` argument — and only
    /// when the policy withholds unix sockets. Until now that was verifiable
    /// only by spawning a real sandboxed process.
    #[test]
    fn socket_is_blocked_only_while_unix_sockets_are_withheld() {
        let denied = blocked_syscalls(&SandboxPolicy::default()).unwrap();
        assert!(
            denied.contains_key(&libc::SYS_socket),
            "socket() must be filtered when unix sockets are not granted"
        );
        assert_eq!(
            denied[&libc::SYS_socket].len(),
            1,
            "the socket entry must be conditional, not an unconditional block"
        );

        let granted = blocked_syscalls(&SandboxPolicy::default().allow_unix_sockets()).unwrap();
        assert!(
            !granted.contains_key(&libc::SYS_socket),
            "granting unix sockets must lift the socket() filter"
        );
    }
}
