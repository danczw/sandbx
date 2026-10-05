//! Does the seccomp denylist still contain what the security docs claim?
//!
//! `enforcement_syscalls.rs` probes only four of the entries end to end, so another could
//! leave the list with every test still passing while `SECURITY.md` went on promising it.
//! Weaker evidence than a probe — the number is in the list the filter is built
//! from, not refused by the kernel — and all that is available for syscalls with no
//! safe wrapper, since `sandbx-core` forbids `unsafe`. Not behind
//! `sandbox-integration`: it spawns nothing, so it runs where the enforcement suite
//! cannot.
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
    // Handles on other processes, and fault handling that hands an attacker the pause.
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
         crates/sandbx-core/src/helper/seccomp.rs — or, if the removal was \
         deliberate, \
         drop the claim from SECURITY.md in the same change."
    );
}

/// A duplicate is otherwise invisible: `deny_dangerous_syscalls` collects the list
/// into a `BTreeMap`, which keeps one entry per syscall number.
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
