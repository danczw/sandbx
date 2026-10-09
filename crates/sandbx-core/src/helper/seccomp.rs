//! The seccomp syscall filter applied to the sandboxed command.
//!
//! Covers the escapes Landlock cannot see: a syscall that reaches the kernel without naming
//! a path. `rules` holds what is denied; this file holds how it reaches the kernel.
//!
//! Stacked filters, not one: a seccompiler filter carries a single match action, and `clone3`
//! must answer `ENOSYS` while everything else answers `EPERM`. Three on x86_64, where the x32
//! gate also applies; two elsewhere. The kernel takes the most severe verdict across every
//! installed filter.

use crate::SandboxError;

mod rules;

pub use rules::BLOCKED_SYSCALLS;
use rules::blocked_syscalls;

/// `__X32_SYSCALL_BIT` from `asm/unistd.h`: the bit an x32 syscall number carries.
///
/// x32 reports `AUDIT_ARCH_X86_64`, so it passes the filter's architecture gate, but its
/// numbers are the native ones with this bit set — and four denylisted calls (`ptrace`,
/// `kexec_load`, `process_vm_readv`, `process_vm_writev`) sit at *different* numbers again in
/// the x32 table. So the whole ABI is refused rather than enumerated (#117).
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Compile [`blocked_syscalls`] into the BPF program [`deny_dangerous_syscalls`] installs.
///
/// Blocked calls return `EPERM` rather than killing the process: the syscall does not run
/// either way, and `EPERM` is what tools already expect on hardened systems, so they fail
/// that operation instead of dying mid-run.
fn compiled_filter(policy: &crate::SandboxPolicy) -> Result<seccompiler::BpfProgram, SandboxError> {
    deny_with(blocked_syscalls(policy)?, libc::EPERM)
}

/// Compile `rules` into a program that answers `errno` for what it names, allowing the rest.
///
/// Takes an `errno` rather than a `SeccompAction`, so no caller can pass `Allow` here and
/// invert the filter. Split out to make the filter's polarity assertable without a kernel:
/// the two actions below are positional and of the same type, so swapping them yields a
/// filter that allows the denylist and `EPERM`s everything else. Hence the named bindings.
///
/// `seccomp/tests/denylist.rs` keeps a twin of this with the two actions swapped, which is
/// what proves those tests would notice. It only mutates the real path as long as this body
/// does nothing but call `SeccompFilter::new` — if that changes, change the twin.
fn deny_with(
    rules: std::collections::BTreeMap<libc::c_long, Vec<seccompiler::SeccompRule>>,
    errno: libc::c_int,
) -> Result<seccompiler::BpfProgram, SandboxError> {
    use seccompiler::{SeccompAction, SeccompFilter};

    // `SeccompFilter::new` takes the mismatch action before the match one: every syscall the
    // filter does not name, then the ones it does.
    let unlisted = SeccompAction::Allow;
    let listed = SeccompAction::Errno(errno as u32);

    let filter = SeccompFilter::new(
        rules,
        unlisted,
        listed,
        std::env::consts::ARCH.try_into().map_err(seccomp_failed)?,
    )
    .map_err(seccomp_failed)?;

    filter.try_into().map_err(seccomp_failed)
}

/// `clone3` answered with `ENOSYS`, which is what makes the `clone` flag rules reachable.
///
/// Its flags sit in a struct behind a pointer, so seccomp cannot read them and the syscall has
/// to go. `ENOSYS` and not `EPERM`: glibc 2.34+ calls `clone3` from `pthread_create` and falls
/// back to `clone` only on `ENOSYS`, so `EPERM` here breaks every threaded program instead of
/// routing it through the filtered `clone`.
fn clone3_filter() -> Result<seccompiler::BpfProgram, SandboxError> {
    deny_with(
        std::collections::BTreeMap::from([(libc::SYS_clone3, Vec::new())]),
        libc::ENOSYS,
    )
}

/// Kill anything arriving over the x32 ABI, identified by [`X32_SYSCALL_BIT`] in `nr`.
///
/// Hand-assembled because seccompiler's conditions address syscall *arguments*; `nr` is
/// reachable only as a filter key, and this rule is a mask over it rather than one number.
///
/// Killed, not `EPERM`'d, for the reason the architecture gate kills: a foreign ABI whose
/// syscall numbers mean something else, so no verdict per call is meaningful. Needs no
/// architecture gate of its own — the denylist filter already kills every non-native
/// architecture, and the kernel takes the most severe verdict.
///
/// A negative `nr` is excluded before the mask, or `syscall(-1)` — `0xffff_ffff`, bit 30
/// among the rest — would die by signal where every kernel answers `ENOSYS`. `do_syscall_64`
/// special-cases `nr == -1`, and x32 dispatch is `nr - BIT < X32_NR_syscalls`, so nothing
/// with the sign bit set is x32. A positive number past the end of the x32 table is killed
/// too: matching the table exactly would mean pinning its size here, and only an x32 caller
/// reaches for those numbers.
#[cfg(target_arch = "x86_64")]
fn x32_gate() -> seccompiler::BpfProgram {
    let insn = |code: u16, jt: u8, jf: u8, k: u32| seccompiler::sock_filter { code, jt, jf, k };

    // `jt`/`jf` count from the *following* instruction. Laid out so the two returns sit last:
    // both jumps forward, and the fallthrough is the allow.
    vec![
        // `nr` is the first word of `struct seccomp_data`.
        insn((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0, 0, 0),
        // Sign bit set? Not x32 — skip to the allow.
        insn(
            (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16,
            3,
            0,
            0x8000_0000,
        ),
        insn(
            (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16,
            0,
            0,
            X32_SYSCALL_BIT,
        ),
        insn(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            0,
            1,
            X32_SYSCALL_BIT,
        ),
        insn(
            (libc::BPF_RET | libc::BPF_K) as u16,
            0,
            0,
            libc::SECCOMP_RET_KILL_PROCESS,
        ),
        insn(
            (libc::BPF_RET | libc::BPF_K) as u16,
            0,
            0,
            libc::SECCOMP_RET_ALLOW,
        ),
    ]
}

/// Every filter [`deny_dangerous_syscalls`] installs, in the order it installs them.
fn installed_filters(
    policy: &crate::SandboxPolicy,
) -> Result<Vec<seccompiler::BpfProgram>, SandboxError> {
    let filters = vec![
        compiled_filter(policy)?,
        clone3_filter()?,
        #[cfg(target_arch = "x86_64")]
        x32_gate(),
    ];

    Ok(filters)
}

/// Install the filters [`installed_filters`] builds, in any order: the kernel takes the most
/// severe verdict across every installed filter, so a later one cannot loosen an earlier one.
///
/// Per-thread (`apply_filter`, not `apply_filter_all_threads`), which is sound only because
/// stage 2 is a fresh `exec` and therefore single-threaded — see [`super::exec_inner`].
pub(super) fn deny_dangerous_syscalls(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    for filter in installed_filters(policy)? {
        seccompiler::apply_filter(&filter).map_err(seccomp_failed)?;
    }

    Ok(())
}

fn seccomp_failed(source: impl std::fmt::Display) -> SandboxError {
    SandboxError::Seccomp {
        detail: source.to_string(),
    }
}

#[cfg(test)]
mod tests;
