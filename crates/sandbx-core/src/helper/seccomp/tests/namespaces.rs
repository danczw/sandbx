//! `clone`'s namespace flags and `clone3`, the routes to a namespace that are not `unshare`.

use super::*;

/// The verdict for `clone(flags, …)`.
fn clone_verdict(program: seccompiler::BpfProgramRef<'_>, flags: u64) -> u32 {
    verdict_with_args(program, libc::SYS_clone, [flags, 0, 0, 0, 0, 0])
}

/// Every namespace `unshare` is denied for is denied through `clone`'s flags too (#118), one
/// flag at a time.
///
/// Per flag rather than over the union: the rules are OR'd, so a filter that only fired when
/// every flag was set would pass a union-only test.
#[test]
fn clone_cannot_reach_a_namespace_unshare_cannot() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();

    for flag in NAMESPACE_CLONE_FLAGS {
        // `SIGCHLD` in the exit-signal byte, as a real caller passes it, so a rule that
        // matched the flags word exactly instead of masking is caught.
        let flags = *flag as u64 | libc::SIGCHLD as u64;

        assert_eq!(
            clone_verdict(&program, flags),
            EPERM,
            "clone({flag:#x}) is permitted, so the command can create a namespace \
             that `unshare` is denied for"
        );
    }
}

/// The flag rules must not cost an ordinary `fork`, which is `clone` carrying no namespace
/// flag at all. Without this, denying `clone` outright would pass the test above.
#[test]
fn clone_without_a_namespace_flag_is_allowed() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();

    for (what, flags) in [
        ("a bare fork", libc::SIGCHLD as u64),
        (
            "a thread",
            (libc::CLONE_VM | libc::CLONE_FS | libc::CLONE_FILES | libc::CLONE_THREAD) as u64,
        ),
    ] {
        assert_eq!(
            clone_verdict(&program, flags),
            ALLOW,
            "clone() for {what} is refused, so the namespace rules have widened \
             into every process creation"
        );
    }
}

/// `clone`'s flags are an `unsigned long`, but the kernel reads namespace bits out of the low
/// half only, so the comparison has to ignore the high one. A `Qword` rule would let
/// `clone(0x1_0000_0000 | CLONE_NEWUSER)` through.
#[test]
fn the_clone_flag_comparison_ignores_the_high_half() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();
    let flags = 0xdead_beef_0000_0000 | libc::CLONE_NEWUSER as u64;

    assert_eq!(
        clone_verdict(&program, flags),
        EPERM,
        "garbage in the high half of `clone`'s flags escapes the namespace rules, \
         so the comparison is 64-bit where the kernel's is 32-bit"
    );
}

/// `clone3` carries its flags in a struct seccomp cannot read, so it is refused outright — and
/// with `ENOSYS`, which is what makes the `clone` rules reachable.
///
/// glibc 2.34+ calls `clone3` from `pthread_create` and falls back to `clone` only on
/// `ENOSYS`. `EPERM` here would break every threaded program rather than routing it onto the
/// filtered `clone`.
#[test]
fn clone3_answers_enosys_so_callers_fall_back() {
    let program = clone3_filter().unwrap();

    assert_eq!(
        verdict(&program, libc::SYS_clone3),
        ENOSYS,
        "clone3 does not answer ENOSYS, so either it is reachable — and its flags \
         are unreadable to seccomp — or glibc cannot fall back and threading breaks"
    );
    assert_eq!(
        verdict(&program, libc::SYS_clone),
        ALLOW,
        "the clone3 filter also answers for clone, which must reach the flag rules \
         in the denylist filter instead"
    );
}
