//! The conditional rules on the socket-creating syscalls, which the policy both widens and
//! narrows: the unix-socket axis lifts rules on `socket`'s `domain` and on `socketpair`'s
//! `type`, and a port allowlist adds rules on `socket`'s `domain`, `type` and `protocol` —
//! plus the `MSG_FASTOPEN` rules on the send syscalls, which belong to the same claim.

use super::*;

/// A policy whose egress is confined to one TCP port, the only state that denies datagrams.
/// The port itself is irrelevant — Landlock holds the ports, seccomp sees only which *shape*
/// of socket is asked for.
fn port_list() -> SandboxPolicy {
    SandboxPolicy::default().allow_network_port(443)
}

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

    // Fourteen of the sixteen type values, `SOCK_STREAM` and `SOCK_SEQPACKET` excepted.
    assert_eq!(
        denied[&libc::SYS_socketpair].len(),
        14,
        "the socketpair entry must name the connectionless types one at a time, \
         conditions inside a rule being AND'd"
    );

    let granted = blocked_syscalls(&SandboxPolicy::default().allow_unix_sockets()).unwrap();
    assert!(
        !granted.contains_key(&libc::SYS_socket) && !granted.contains_key(&libc::SYS_socketpair),
        "granting unix sockets must lift both routes to an AF_UNIX descriptor"
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

/// `socket`'s `domain` is an `int`, so a `Dword`-to-`Qword` change is a real bypass:
/// `socket(0x1_0000_0001, …)` has the kernel see `AF_UNIX` while a `Qword` filter sees a
/// non-zero high half, finds no match, and allows it. The test above leaves the high half zero
/// and so passes against either width.
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

/// The second assertion is the one worth having: a grant that also widened the denylist would
/// otherwise be invisible here.
#[test]
fn granting_unix_sockets_lifts_only_the_unix_rules() {
    let program = compiled_filter(&SandboxPolicy::default().allow_unix_sockets()).unwrap();

    assert_eq!(
        socket_verdict(&program, libc::AF_UNIX as u64),
        ALLOW,
        "the policy grants unix sockets but the filter still refuses them"
    );
    assert_eq!(
        socketpair_verdict(&program, libc::AF_UNIX as u64, libc::SOCK_DGRAM as u64),
        ALLOW,
        "the policy grants unix sockets but a datagram pair is still refused"
    );
    assert_eq!(
        verdict(&program, libc::SYS_ptrace),
        EPERM,
        "granting unix sockets also lifted the denylist, which no policy may do"
    );
}

/// `socketpair` is the second route to an `AF_UNIX` descriptor, and it calls no `socket`, so
/// the rule above cannot see it. The reachable half is the connectionless type: `connect` on a
/// datagram pair re-targets it at a pathname socket, measured delivering outside the sandbox
/// before this rule existed. Why the other two stay permitted is in
/// `context/guide-sandboxing.md`.
#[test]
fn socketpair_refuses_a_connectionless_unix_pair() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();

    assert_eq!(
        socketpair_verdict(&program, libc::AF_UNIX as u64, libc::SOCK_DGRAM as u64),
        EPERM,
        "a datagram socketpair is permitted, so `connect` on one half reaches any \
         pathname socket without the denied `socket(AF_UNIX, …)` ever being called"
    );

    for permitted in [libc::SOCK_STREAM, libc::SOCK_SEQPACKET] {
        assert_eq!(
            socketpair_verdict(&program, libc::AF_UNIX as u64, permitted as u64),
            ALLOW,
            "socketpair({permitted}) is refused, which breaks the shells and build \
             tools that use a connected pair as a pipe"
        );
    }

    assert_eq!(
        socketpair_verdict(&program, libc::AF_INET as u64, libc::SOCK_DGRAM as u64),
        ALLOW,
        "the rule widened past AF_UNIX into a family the netns is what bounds"
    );
}

/// The allowlist shape: a connectionless type a future kernel assigns to `AF_UNIX` arrives
/// denied rather than permitted.
///
/// The flag bits are set on every case because `__sys_socketpair` masks `type` with
/// `SOCK_TYPE_MASK` before dispatching, exactly as `__sys_socket` does — an `Eq` comparison
/// here would be escaped by a `SOCK_CLOEXEC` the caller sets anyway.
#[test]
fn every_connectionless_socketpair_type_is_refused() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();
    let flags = (libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u64;

    for socket_type in 0..=super::rules::SOCK_TYPE_MASK {
        let connection_oriented =
            socket_type == libc::SOCK_STREAM as u64 || socket_type == libc::SOCK_SEQPACKET as u64;
        let expected = if connection_oriented { ALLOW } else { EPERM };

        assert_eq!(
            socketpair_verdict(&program, libc::AF_UNIX as u64, socket_type | flags),
            expected,
            "socketpair type {socket_type:#x} with the flag bits set got the wrong \
             verdict, so the comparison is not masking `type` the way the kernel does"
        );
    }
}

/// The datagram half of what a port allowlist has to deny: Landlock's port rules police TCP
/// only, so UDP left open would reach any host on any port.
#[test]
fn a_port_list_denies_udp() {
    let program = compiled_filter(&port_list()).unwrap();

    assert_eq!(
        typed_socket_verdict(&program, libc::AF_INET as u64, libc::SOCK_DGRAM as u64),
        EPERM,
        "a port allowlist permits UDP, so egress is not confined to the ports it names"
    );
}

/// Raw sockets bypass the transport layer altogether, so a port is not even a concept they
/// have. `CAP_NET_RAW` is dropped too, but the allowlist must hold on its own.
#[test]
fn a_port_list_denies_raw_sockets() {
    let program = compiled_filter(&port_list()).unwrap();

    assert_eq!(
        typed_socket_verdict(&program, libc::AF_INET as u64, libc::SOCK_RAW as u64),
        EPERM,
        "a port allowlist permits raw sockets, which carry traffic no port rule sees"
    );
}

/// The test that fails if anyone swaps `MaskedEq(SOCK_TYPE_MASK)` for `Eq`.
///
/// `socket(…, SOCK_DGRAM | SOCK_CLOEXEC)` is the spelling every modern library uses, and
/// `__sys_socket` masks the flag bits off before reading the type — so an `Eq` rule against
/// `SOCK_DGRAM` matches none of them while the kernel still hands back a datagram socket. The
/// test above leaves the flag bits clear and so passes against either operator.
#[test]
fn a_port_list_denies_udp_with_cloexec_set() {
    let program = compiled_filter(&port_list()).unwrap();

    for flags in [
        libc::SOCK_CLOEXEC,
        libc::SOCK_NONBLOCK,
        libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
    ] {
        assert_eq!(
            typed_socket_verdict(
                &program,
                libc::AF_INET as u64,
                (libc::SOCK_DGRAM | flags) as u64
            ),
            EPERM,
            "UDP escapes the denial with {flags:#x} set, so the type comparison is an \
             equality where the kernel's is masked"
        );
    }

    // `type` is an `int` too, so a `Qword` comparison would look at bits the kernel discards.
    assert_eq!(
        typed_socket_verdict(
            &program,
            libc::AF_INET as u64,
            0xdead_beef_0000_0000 | libc::SOCK_DGRAM as u64
        ),
        EPERM,
        "garbage in the high half of `type` escapes the denial, so the comparison is \
         64-bit where the kernel's is 32-bit"
    );
}

/// `SOCK_SEQPACKET` over `AF_INET` is SCTP, which Landlock's `ConnectTcp` does not police. The
/// enumeration over the whole 4-bit type field closes it, and anything else the field grows to
/// mean.
#[test]
fn a_port_list_denies_seqpacket() {
    let program = compiled_filter(&port_list()).unwrap();

    assert_eq!(
        typed_socket_verdict(&program, libc::AF_INET as u64, libc::SOCK_SEQPACKET as u64),
        EPERM,
        "a port allowlist permits SCTP, which no Landlock port rule covers"
    );
}

/// The grant has to survive the denial that protects it: `SOCK_STREAM` is the one type a
/// port allowlist is about, so denying it would make the allowlist deny everything.
#[test]
fn a_port_list_still_permits_tcp() {
    let program = compiled_filter(&port_list()).unwrap();

    for flags in [0, libc::SOCK_CLOEXEC, libc::SOCK_NONBLOCK] {
        assert_eq!(
            typed_socket_verdict(
                &program,
                libc::AF_INET as u64,
                (libc::SOCK_STREAM | flags) as u64
            ),
            ALLOW,
            "TCP is refused with {flags:#x} set, so a port allowlist reaches nothing"
        );
    }
}

/// A type denial aimed at IP egress that also caught `AF_UNIX` would narrow a grant it never
/// mentions — and `SOCK_DGRAM` and `SOCK_SEQPACKET` unix sockets are both in ordinary use.
#[test]
fn a_port_list_still_permits_unix_datagrams_when_granted() {
    let program = compiled_filter(&port_list().allow_unix_sockets()).unwrap();

    for socket_type in [libc::SOCK_DGRAM, libc::SOCK_SEQPACKET, libc::SOCK_STREAM] {
        assert_eq!(
            typed_socket_verdict(&program, libc::AF_UNIX as u64, socket_type as u64),
            ALLOW,
            "a granted unix socket of type {socket_type} was refused by the rule \
             confining IP egress to TCP"
        );
    }
}

/// The denial belongs to the port allowlist and not to network access as such: the operator
/// who asked for unrestricted egress gets it.
#[test]
fn an_unrestricted_grant_permits_udp() {
    let program = compiled_filter(&SandboxPolicy::default().allow_network()).unwrap();

    assert_eq!(
        typed_socket_verdict(&program, libc::AF_INET as u64, libc::SOCK_DGRAM as u64),
        ALLOW,
        "`--allow-network` refuses UDP, which is narrower than the flag claims"
    );
}

/// The default policy keeps datagrams for a different reason: it runs in an empty network
/// namespace, so a UDP socket has nowhere to send — and `getaddrinfo` needs `AF_NETLINK`,
/// which glibc's `__check_pf` opens as `SOCK_RAW`.
///
/// Both netlink types, because the exemption has to cover the call glibc actually makes and
/// `netlink_create` accepts either.
#[test]
fn a_denied_policy_permits_udp_in_an_empty_netns() {
    for (domain, socket_type) in [
        (libc::AF_INET, libc::SOCK_DGRAM),
        (libc::AF_NETLINK, libc::SOCK_DGRAM),
        (libc::AF_NETLINK, libc::SOCK_RAW),
    ] {
        let program = compiled_filter(&SandboxPolicy::default()).unwrap();

        assert_eq!(
            typed_socket_verdict(&program, domain as u64, socket_type as u64),
            ALLOW,
            "the default policy refuses a type {socket_type} socket in domain {domain}, \
             which the empty netns already confines and `getaddrinfo` needs"
        );
    }
}

/// `blocked_syscalls` has two producers of `SYS_socket` rules, and rules for one syscall are
/// OR'd — so an `insert` in either would wipe the other with no trace. The families are
/// disjoint, `AF_UNIX` against everything else, so neither verdict implies the other.
#[test]
fn the_unix_and_type_rules_coexist_on_one_socket_entry() {
    let program = compiled_filter(&port_list()).unwrap();

    assert_eq!(
        typed_socket_verdict(&program, libc::AF_UNIX as u64, libc::SOCK_STREAM as u64),
        EPERM,
        "the rules confining IP egress to TCP replaced the AF_UNIX denial"
    );
    assert_eq!(
        typed_socket_verdict(&program, libc::AF_INET as u64, libc::SOCK_DGRAM as u64),
        EPERM,
        "the AF_UNIX denial replaced the rules confining IP egress to TCP"
    );
}

/// The hole the type rules alone leave open. Landlock asks for `CONNECT_TCP` only where
/// `sk_is_tcp` holds — `SOCK_STREAM` *and* `IPPROTO_TCP` — so a stream socket carrying any
/// other protocol number is egress no port rule ever sees. MPTCP is the reachable one: built
/// into distribution kernels, needing no module load.
#[test]
fn a_port_list_denies_stream_protocols_other_than_tcp() {
    let program = compiled_filter(&port_list()).unwrap();

    for domain in [libc::AF_INET, libc::AF_INET6] {
        for protocol in [libc::IPPROTO_MPTCP, libc::IPPROTO_SCTP, libc::IPPROTO_DCCP] {
            assert_eq!(
                protocol_socket_verdict(
                    &program,
                    domain as u64,
                    libc::SOCK_STREAM as u64,
                    protocol as u64
                ),
                EPERM,
                "a port allowlist permits protocol {protocol} over domain {domain}, a \
                 stream socket Landlock's port rules do not police"
            );
        }
    }
}

/// Both spellings of TCP have to pass, in both families: 0 is what every library writes and
/// means the family's default for a stream socket, and `IPPROTO_TCP` is what the explicit
/// callers write.
#[test]
fn a_port_list_permits_either_spelling_of_tcp() {
    let program = compiled_filter(&port_list()).unwrap();

    for domain in [libc::AF_INET, libc::AF_INET6] {
        for protocol in [0, libc::IPPROTO_TCP] {
            assert_eq!(
                protocol_socket_verdict(
                    &program,
                    domain as u64,
                    libc::SOCK_STREAM as u64,
                    protocol as u64
                ),
                ALLOW,
                "TCP written as protocol {protocol} is refused over domain {domain}, so \
                 a port allowlist reaches nothing"
            );
        }
    }
}

/// `protocol` is an `int`, so the kernel discards the register's high half before
/// `inet_create` reads it — a `Qword` compare would miss the first case and refuse the
/// second.
#[test]
fn the_protocol_rules_ignore_the_arguments_high_half() {
    let program = compiled_filter(&port_list()).unwrap();
    let high = 0xdead_beef_0000_0000u64;

    assert_eq!(
        protocol_socket_verdict(
            &program,
            libc::AF_INET as u64,
            libc::SOCK_STREAM as u64,
            high | libc::IPPROTO_SCTP as u64
        ),
        EPERM,
        "SCTP passed by hiding the protocol number behind a high half the kernel drops"
    );
    assert_eq!(
        protocol_socket_verdict(
            &program,
            libc::AF_INET as u64,
            libc::SOCK_STREAM as u64,
            high | libc::IPPROTO_TCP as u64
        ),
        ALLOW,
        "a TCP socket was refused over bits the kernel never reads"
    );
}

/// `AF_SMC` is the hole the type and protocol rules both miss: its type is `SOCK_STREAM` and
/// its family is neither `AF_INET` nor `AF_INET6`, while `smc_connect` dials its inner TCP
/// socket with `kernel_connect`, below the hook `ConnectTcp` lives on.
///
/// `AF_SMC` is 43 (`include/linux/socket.h`); `libc` does not name it.
#[test]
fn a_port_list_denies_stream_families_that_tunnel_ip() {
    let program = compiled_filter(&port_list()).unwrap();
    const AF_SMC: u64 = 43;

    for domain in [AF_SMC, libc::AF_TIPC as u64] {
        assert_eq!(
            protocol_socket_verdict(&program, domain, libc::SOCK_STREAM as u64, 0),
            EPERM,
            "a port allowlist permits a stream socket in domain {domain}, which carries \
             IP traffic no Landlock port rule sees"
        );
    }
}

/// The same rule read from the other side: only the three families a port rule can speak
/// about survive it, so a family added to the kernel tomorrow is denied without an edit here.
#[test]
fn a_port_list_permits_stream_sockets_only_in_the_ip_families() {
    let program = compiled_filter(&port_list().allow_unix_sockets()).unwrap();

    for domain in [libc::AF_INET, libc::AF_INET6, libc::AF_UNIX] {
        assert_eq!(
            protocol_socket_verdict(&program, domain as u64, libc::SOCK_STREAM as u64, 0),
            ALLOW,
            "a stream socket in domain {domain} was refused, so a port allowlist reaches \
             nothing"
        );
    }

    for domain in [libc::AF_VSOCK, libc::AF_BLUETOOTH] {
        assert_eq!(
            protocol_socket_verdict(&program, domain as u64, libc::SOCK_STREAM as u64, 0),
            EPERM,
            "a stream socket in domain {domain} escaped the family allowlist"
        );
    }
}

/// A socket's family does not stay fixed at `socket`, where the allowlist guards it:
/// `setsockopt(fd, SOL_TCP, TCP_ULP, "smc")` re-points the descriptor at a new `AF_SMC`
/// socket, so a permitted `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)` becomes the very thing
/// the rule above refuses to create.
///
/// `TCP_ULP` is 31 (`include/uapi/linux/tcp.h`), which `libc` does not name.
#[test]
fn a_port_list_denies_the_tcp_ulp_sockopt() {
    let program = compiled_filter(&port_list()).unwrap();
    const TCP_ULP: u64 = 31;

    assert_eq!(
        verdict_with_args(
            &program,
            libc::SYS_setsockopt,
            [3, libc::IPPROTO_TCP as u64, TCP_ULP, 0, 0, 0]
        ),
        EPERM,
        "a port allowlist permits TCP_ULP, so a legal TCP socket can be converted to one \
         whose connect no Landlock port rule sees"
    );
}

/// The denial is the option and not the syscall: a program that cannot call `setsockopt`
/// cannot set `SO_REUSEADDR` or a timeout, and `TCP_NODELAY` shares the level the rule names —
/// so the `optname` half of the condition has to be doing work.
#[test]
fn a_port_list_permits_other_sockopts() {
    let program = compiled_filter(&port_list()).unwrap();

    for (level, optname) in [
        (libc::SOL_SOCKET, libc::SO_REUSEADDR),
        (libc::SOL_SOCKET, libc::SO_RCVTIMEO),
        (libc::IPPROTO_TCP, libc::TCP_NODELAY),
        (libc::IPPROTO_TCP, libc::TCP_KEEPIDLE),
    ] {
        assert_eq!(
            verdict_with_args(
                &program,
                libc::SYS_setsockopt,
                [3, level as u64, optname as u64, 0, 0, 0]
            ),
            ALLOW,
            "setsockopt({level}, {optname}) is refused, so the rule denies the syscall \
             rather than the ULP option"
        );
    }
}

/// `level` and `optname` are `int`s, so the kernel discards each register's high half before
/// `do_tcp_setsockopt` reads it — a `Qword` compare would miss both of these.
#[test]
fn the_tcp_ulp_rule_ignores_the_arguments_high_half() {
    let program = compiled_filter(&port_list()).unwrap();
    let high = 0xdead_beef_0000_0000u64;

    for (level, optname) in [
        (high | libc::IPPROTO_TCP as u64, 31),
        (libc::IPPROTO_TCP as u64, high | 31),
    ] {
        assert_eq!(
            verdict_with_args(&program, libc::SYS_setsockopt, [3, level, optname, 0, 0, 0]),
            EPERM,
            "TCP_ULP passed as ({level:#x}, {optname:#x}), hiding behind bits the kernel \
             drops, so the comparison is 64-bit where the kernel's is 32-bit"
        );
    }
}

/// The denial belongs to the port allowlist. Under the other two states there is no claim it
/// would falsify — an empty netns has nowhere for an SMC socket to dial, unrestricted egress
/// was the request — and `TCP_ULP` is how in-process kTLS is enabled.
#[test]
fn only_a_port_list_denies_the_tcp_ulp_sockopt() {
    for policy in [
        SandboxPolicy::default(),
        SandboxPolicy::default().allow_network(),
    ] {
        let program = compiled_filter(&policy).unwrap();

        assert_eq!(
            verdict_with_args(
                &program,
                libc::SYS_setsockopt,
                [3, libc::IPPROTO_TCP as u64, 31, 0, 0, 0]
            ),
            ALLOW,
            "a policy with no port allowlist refuses TCP_ULP, which is narrower than it \
             claims"
        );
    }
}

/// TCP Fast Open reaches a port without calling `connect`, so Landlock never sees it:
/// `tcp_sendmsg_fastopen` connects via `__inet_stream_connect`, and `security_socket_connect`
/// is only reached from `__sys_connect_file`.
#[test]
fn a_port_list_denies_tcp_fast_open_sends() {
    let program = compiled_filter(&port_list()).unwrap();
    let fastopen = libc::MSG_FASTOPEN as u64;

    for (syscall, flags_arg) in [
        (libc::SYS_sendto, 3),
        (libc::SYS_sendmsg, 2),
        (libc::SYS_sendmmsg, 3),
    ] {
        let mut args = [0; 6];
        args[flags_arg] = fastopen | libc::MSG_NOSIGNAL as u64;

        assert_eq!(
            verdict_with_args(&program, syscall, args),
            EPERM,
            "syscall {syscall} accepts MSG_FASTOPEN, so a port allowlist can be reached \
             past with a send that never calls connect"
        );
    }
}

/// The denial is the flag and not the syscall: an allowlisted TCP port is useless if nothing
/// can be written to it.
#[test]
fn a_port_list_permits_an_ordinary_send() {
    let program = compiled_filter(&port_list()).unwrap();

    for (syscall, flags_arg) in [
        (libc::SYS_sendto, 3),
        (libc::SYS_sendmsg, 2),
        (libc::SYS_sendmmsg, 3),
    ] {
        let mut args = [0; 6];
        args[flags_arg] = libc::MSG_NOSIGNAL as u64;

        assert_eq!(
            verdict_with_args(&program, syscall, args),
            ALLOW,
            "syscall {syscall} is refused without MSG_FASTOPEN set, so an allowlisted \
             port cannot be written to"
        );
    }
}

/// A conditional rule must never widen an unconditional denial. Asserted directly, no
/// production policy producing the collision: an empty rule vector means "match every call",
/// so appending one condition to a syscall on [`BLOCKED_SYSCALLS`] would permit every call
/// that fails the condition.
#[test]
fn a_conditional_rule_cannot_weaken_an_unconditional_denial() {
    use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition};

    let mut rules = std::collections::BTreeMap::from([(libc::SYS_socket, Vec::new())]);
    let condition = SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, 1).unwrap();

    super::rules::deny_when(&mut rules, libc::SYS_socket, vec![condition]).unwrap();

    assert!(
        rules[&libc::SYS_socket].is_empty(),
        "a condition was appended to an unconditional denial, so every call that fails \
         it is now permitted"
    );
}
