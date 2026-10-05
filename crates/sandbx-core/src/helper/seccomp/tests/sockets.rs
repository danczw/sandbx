//! The conditional rules on `socket`, which is the one syscall the policy can widen.

use super::*;

#[test]
fn socket_is_blocked_only_while_unix_is_withheld() {
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

#[test]
fn socket_refuses_af_unix_and_allows_af_inet() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();

    assert_eq!(
        socket_verdict(&program, libc::AF_UNIX as u64),
        EPERM,
        "socket(AF_UNIX) is permitted, so a command can reach a pathname socket \
         outside the sandbox"
    );
    assert_eq!(
        socket_verdict(&program, libc::AF_INET as u64),
        ALLOW,
        "socket(AF_INET) is refused, so the unix-socket rule has widened into \
         every address family — the netns is what bounds IP egress, not this"
    );
}

/// `socket`'s `domain` is an `int`, so the kernel truncates it and a 64-bit comparison
/// would look at register bits the kernel discards. That makes a `Dword`-to-`Qword`
/// change a real bypass: `socket(0x1_0000_0001, …)` has the kernel see `AF_UNIX` while
/// a `Qword` filter sees a non-zero high half, finds no match, and allows it. The test
/// above leaves the high half zero and so passes against either width.
#[test]
fn the_af_unix_test_ignores_the_domains_high_half() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();
    let noise = 0xdead_beef_0000_0000 | libc::AF_UNIX as u64;

    assert_eq!(
        socket_verdict(&program, noise),
        EPERM,
        "garbage in the high half of `domain` escapes the AF_UNIX rule, so the \
         comparison is 64-bit where the kernel's is 32-bit"
    );
}

/// The second assertion is the one worth having: a grant that also widened the
/// denylist would otherwise be invisible here.
#[test]
fn granting_unix_sockets_lifts_only_the_socket_rule() {
    let program = compiled_filter(&SandboxPolicy::default().allow_unix_sockets()).unwrap();

    assert_eq!(
        socket_verdict(&program, libc::AF_UNIX as u64),
        ALLOW,
        "the policy grants unix sockets but the filter still refuses them"
    );
    assert_eq!(
        verdict(&program, libc::SYS_ptrace),
        EPERM,
        "granting unix sockets also lifted the denylist, which no policy may do"
    );
}
