//! Tries to connect to a pathname AF_UNIX socket and read from it.
//!
//! Test-only. A netns isolates only *abstract* unix sockets; pathname sockets
//! live in the filesystem and cross it freely, so this probes whether a policy
//! that denies network still lets a command reach host daemons
//! (systemd's bus, docker.sock, the ssh-agent) over a unix socket.

use std::io::Read;

fn main() -> std::process::ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: unix-probe <socket-path>");
        return std::process::ExitCode::FAILURE;
    };

    match std::os::unix::net::UnixStream::connect(&path) {
        Ok(mut stream) => {
            let mut got = String::new();
            let _ = stream.read_to_string(&mut got);
            println!("UNIX CONNECT SUCCEEDED: {got}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("UNIX CONNECT DENIED: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
