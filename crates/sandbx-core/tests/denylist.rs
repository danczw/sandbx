//! Does the seccomp denylist still contain what the security docs claim?
//!
//! `SECURITY.md` tells users which syscall classes a sandboxed command cannot
//! reach. Nothing until now tied that claim to the code: `enforcement.rs`
//! probes exactly two of the denials end to end (`io_uring_setup` and the
//! conditional `socket(AF_UNIX)` rule), so an entry could be dropped from the
//! list and every test would still pass while the policy went on promising it.
//! This repo treats a security doc that overstates the sandbox as a defect in
//! its own right, so assert the list directly.
//!
//! This is a weaker kind of evidence than `enforcement.rs` gives, and worth
//! being clear about: it proves the number is in the list the filter is built
//! from, not that the kernel refused the call. It is the same trade
//! `capability_coverage.rs` makes, and it is what is available for syscalls with
//! no safe wrapper in this crate's dependencies — `sandbx-core` forbids
//! `unsafe`, so a probe cannot simply issue the raw syscall.
//!
//! Deliberately *not* behind `sandbox-integration`: it spawns nothing and needs
//! no Landlock, so it runs everywhere, including hosts where the enforcement
//! suite cannot run at all.
#![cfg(target_os = "linux")]

use sandbx_core::BLOCKED_SYSCALLS;

/// Every syscall the docs say is denied, paired with the name to report when it
/// is missing. Adding a syscall to the denylist means adding it here too.
const CLAIMED: &[(&str, libc::c_long)] = &[
    // Inspect or modify other processes.
    ("ptrace", libc::SYS_ptrace),
    ("process_vm_readv", libc::SYS_process_vm_readv),
    ("process_vm_writev", libc::SYS_process_vm_writev),
    // Reshape the filesystem out from under Landlock.
    ("mount", libc::SYS_mount),
    ("umount2", libc::SYS_umount2),
    ("pivot_root", libc::SYS_pivot_root),
    ("chroot", libc::SYS_chroot),
    // Escape or re-create namespaces.
    ("setns", libc::SYS_setns),
    ("unshare", libc::SYS_unshare),
    // Load code into the kernel.
    ("init_module", libc::SYS_init_module),
    ("finit_module", libc::SYS_finit_module),
    ("delete_module", libc::SYS_delete_module),
    ("bpf", libc::SYS_bpf),
    ("kexec_load", libc::SYS_kexec_load),
    // Kernel keyring.
    ("add_key", libc::SYS_add_key),
    ("request_key", libc::SYS_request_key),
    ("keyctl", libc::SYS_keyctl),
    // Tracing infrastructure.
    ("perf_event_open", libc::SYS_perf_event_open),
    // A route around every other rule in the filter.
    ("io_uring_setup", libc::SYS_io_uring_setup),
    ("io_uring_enter", libc::SYS_io_uring_enter),
    ("io_uring_register", libc::SYS_io_uring_register),
    // Anonymous in-memory files, which have no path for Landlock to match.
    ("memfd_create", libc::SYS_memfd_create),
    // Handles on other processes, and fault handling that hands an attacker the
    // pause. None of these have a safe wrapper in this crate's dependencies, so
    // the list is the only evidence there is for them — see the module docs.
    ("userfaultfd", libc::SYS_userfaultfd),
    ("pidfd_open", libc::SYS_pidfd_open),
    ("pidfd_getfd", libc::SYS_pidfd_getfd),
    // Whole-machine effects.
    ("reboot", libc::SYS_reboot),
    ("swapon", libc::SYS_swapon),
    ("swapoff", libc::SYS_swapoff),
];

#[test]
fn every_claimed_syscall_is_actually_denied() {
    let missing: Vec<&str> = CLAIMED
        .iter()
        .filter(|(_, nr)| !BLOCKED_SYSCALLS.contains(nr))
        .map(|(name, _)| *name)
        .collect();

    assert!(
        missing.is_empty(),
        "these syscalls are documented as denied but are not in \
         BLOCKED_SYSCALLS: {missing:?}. The filter is built from that list, so \
         they are permitted inside the sandbox and the security docs now \
         overstate the boundary. Fix by restoring the entries in \
         crates/sandbx-core/src/helper.rs — or, if the removal was deliberate, \
         drop the claim from SECURITY.md in the same change."
    );
}

/// A duplicate is otherwise invisible: `deny_dangerous_syscalls` collects the
/// list into a `BTreeMap`, which silently keeps one entry per syscall number. A
/// repeated name is harmless at runtime but means the list has been edited
/// carelessly, which is not what this list should tolerate.
#[test]
fn the_denylist_has_no_duplicate_entries() {
    let mut seen = BLOCKED_SYSCALLS.to_vec();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();

    assert_eq!(
        seen.len(),
        before,
        "BLOCKED_SYSCALLS lists the same syscall more than once; the filter \
         deduplicates it, so the extra entry is dead weight in a list that is \
         read as a security claim"
    );
}
