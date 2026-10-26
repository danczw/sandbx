//! Does the kernel refuse a port the allowlist does not name?
//!
//! The network half of the enforcement suite; `enforcement.rs` states the kernel floor all
//! three files run on. Under a port allowlist network is *allowed*, so there is no netns and
//! the command shares the host's — which is how it reaches a `127.0.0.1` listener this file
//! binds itself. No external network is needed.
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]

mod support;

use sandbx_core::SandboxPolicy;
use support::{allow_probe, run, runtime_paths};

/// A listener on an ephemeral loopback port, answering one connection with `payload`. The
/// probe prints what it read, so a test can assert the bytes and not the exit status alone.
fn listener(payload: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let accepting = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            use std::io::Write;
            let _ = stream.write_all(payload.as_bytes());
        }
    });

    (port, accepting)
}

/// Unblock a listener thread nothing connected to, so the test does not leak it.
fn drain(port: u16, accepting: std::thread::JoinHandle<()>) {
    let _ = std::net::TcpStream::connect(("127.0.0.1", port));
    let _ = accepting.join();
}

fn probe(policy: SandboxPolicy, transport: &str, port: u16) -> std::process::Output {
    let probe = env!("CARGO_BIN_EXE_sandbx-egress-probe");
    let policy = allow_probe(runtime_paths(policy), probe);

    run(&policy, probe, &[transport, &format!("127.0.0.1:{port}")])
}

/// Without it the refusal below could be the sandbox refusing everything: a port allowlist
/// that reaches nothing is fail-closed but useless.
#[test]
fn an_allowlisted_port_is_reachable() {
    let (port, accepting) = listener("ALLOWLISTED-PORT-ANSWERED");

    let output = probe(
        SandboxPolicy::default().allow_network_port(port),
        "tcp",
        port,
    );

    drain(port, accepting);

    assert!(
        output.status.success(),
        "an allowlisted port was unreachable, so the allowlist grants nothing: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("ALLOWLISTED-PORT-ANSWERED"),
        "the connection succeeded but read nothing from the listener"
    );
}

/// A port list that reached the kernel as "do not handle the network axis" would leave TCP
/// unrestricted while the CLI reported an allowlist, and nothing else detects that. Two
/// listeners, one allowlisted, so the refusal cannot be a run with no network at all.
#[test]
fn a_port_outside_the_allowlist_is_refused() {
    let (allowed, allowed_thread) = listener("ALLOWED-PORT");
    let (denied, denied_thread) = listener("DENIED-PORT-SECRET");

    let policy = SandboxPolicy::default().allow_network_port(allowed);
    let reached = probe(policy.clone(), "tcp", allowed);
    let refused = probe(policy, "tcp", denied);

    drain(allowed, allowed_thread);
    drain(denied, denied_thread);

    assert!(
        reached.status.success(),
        "the allowlisted port was unreachable, so the refusal below says nothing: {}",
        String::from_utf8_lossy(&reached.stderr)
    );
    assert!(
        !refused.status.success(),
        "a port the allowlist does not name was reachable, so the port rules are \
         not being enforced and egress is unrestricted"
    );
    assert!(
        !String::from_utf8_lossy(&refused.stdout).contains("DENIED-PORT-SECRET"),
        "read from a port the allowlist never named"
    );
}

/// The bare grant keeps its meaning: both ports, including the one a list would have had to
/// name.
#[test]
fn a_bare_network_grant_reaches_both_ports() {
    let (first, first_thread) = listener("FIRST-PORT");
    let (second, second_thread) = listener("SECOND-PORT");

    let policy = SandboxPolicy::default().allow_network();
    let to_first = probe(policy.clone(), "tcp", first);
    let to_second = probe(policy, "tcp", second);

    drain(first, first_thread);
    drain(second, second_thread);

    for (port, output) in [(first, to_first), (second, to_second)] {
        assert!(
            output.status.success(),
            "`--allow-network` could not reach port {port}, so it is narrower than \
             the flag claims: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Landlock's port rules police TCP alone, so without the seccomp denial a command
/// allowlisted to one TCP port could still send datagrams anywhere. Asked of the same policy
/// that reaches its TCP port, so this is the datagram refused and not a run with no network.
#[test]
fn udp_is_refused_under_a_port_allowlist() {
    let (port, accepting) = listener("TCP-STILL-WORKS");

    let policy = SandboxPolicy::default().allow_network_port(port);
    let over_tcp = probe(policy.clone(), "tcp", port);
    let over_udp = probe(policy, "udp", port);

    drain(port, accepting);

    assert!(
        over_tcp.status.success(),
        "TCP on the allowlisted port failed, so the UDP refusal says nothing: {}",
        String::from_utf8_lossy(&over_tcp.stderr)
    );
    assert!(
        !over_udp.status.success(),
        "UDP survived a port allowlist, so egress is not confined to the ports it names"
    );
}

/// `handled_net_access` asks for `BindTcp` as well as `ConnectTcp`, so an allowlist bounds
/// listening too. A cost rather than a feature: `bind(0)`, what a program wanting any free
/// local port asks for, cannot be expressed by a port list and so is refused.
#[test]
fn bind_is_confined_to_the_allowlisted_ports() {
    let (port, accepting) = listener("UNUSED");
    drain(port, accepting);

    let policy = SandboxPolicy::default().allow_network_port(port);
    let listed = probe(policy.clone(), "bind", port);
    let ephemeral = probe(policy, "bind", 0);

    // The listener is released before the probe runs, so another process may take the port
    // first. `AddrInUse` is that race; the allowlist would produce `PermissionDenied`.
    let refusal = String::from_utf8_lossy(&listed.stderr);
    assert!(
        listed.status.success() || refusal.contains("AddrInUse"),
        "an allowlisted port could not be bound, so the allowlist grants nothing: {refusal}"
    );
    assert!(
        !ephemeral.status.success(),
        "bind(0) succeeded under a port allowlist, so the kernel chose a port the \
         allowlist never named"
    );
}

/// The denial belongs to the allowlist and not to network access: an operator who asked for
/// unrestricted egress still gets datagrams, and `getaddrinfo` still has netlink.
#[test]
fn udp_survives_a_bare_network_grant() {
    let (port, accepting) = listener("UNUSED");

    let output = probe(SandboxPolicy::default().allow_network(), "udp", port);

    drain(port, accepting);

    assert!(
        output.status.success(),
        "`--allow-network` refuses UDP, which is narrower than the flag claims: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
