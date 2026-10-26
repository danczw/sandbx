//! Tries to reach a `HOST:PORT` over TCP or UDP, or to listen on it, and reports which.
//! Test-only.
//!
//! Three modes in one binary, because the port allowlist's claim covers all of them:
//! Landlock permits connect *and* bind on the named TCP ports and refuses both elsewhere,
//! and seccomp denies UDP outright.

use std::io::Read;

fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(transport), Some(target)) = (args.next(), args.next()) else {
        eprintln!("usage: egress-probe <tcp|udp|bind> <HOST:PORT>");
        return std::process::ExitCode::FAILURE;
    };

    match transport.as_str() {
        "tcp" => tcp(&target),
        "udp" => udp(&target),
        "bind" => bind(&target),
        other => {
            eprintln!("unknown transport {other}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// `BindTcp` is handled alongside `ConnectTcp`, so a port allowlist bounds which ports a
/// command may *listen* on as well as which it may reach.
fn bind(target: &str) -> std::process::ExitCode {
    match std::net::TcpListener::bind(target) {
        Ok(listener) => {
            match listener.local_addr() {
                Ok(address) => println!("TCP BIND SUCCEEDED: {address}"),
                Err(error) => println!("TCP BIND SUCCEEDED: address unknown: {error}"),
            }
            std::process::ExitCode::SUCCESS
        }
        // The `ErrorKind` as well as the message: `AddrInUse` is how a caller tells another
        // process having taken the port from the allowlist's own `PermissionDenied`.
        Err(error) => {
            eprintln!("TCP BIND DENIED: {:?}: {error}", error.kind());
            std::process::ExitCode::FAILURE
        }
    }
}

/// Reads after connecting, so a success is a round trip rather than a handshake the test
/// cannot distinguish from a connection to the wrong listener.
fn tcp(target: &str) -> std::process::ExitCode {
    match std::net::TcpStream::connect(target) {
        Ok(mut stream) => {
            let mut got = String::new();
            let _ = stream.read_to_string(&mut got);
            println!("TCP CONNECT SUCCEEDED: {got}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("TCP CONNECT DENIED: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// The `bind` failure is reported apart from the send: seccomp refuses the `socket` call
/// itself, so under a port allowlist there is never a socket to send from.
fn udp(target: &str) -> std::process::ExitCode {
    let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("UDP SOCKET DENIED: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match socket.send_to(b"probe", target) {
        Ok(_) => {
            println!("UDP SEND SUCCEEDED");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("UDP SEND DENIED: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
