//! Tries to reach a pathname AF_UNIX socket through a `socketpair` descriptor. Test-only.
//!
//! `socketpair` returns an AF_UNIX socket without calling `socket`, so a seccomp rule on
//! `socket(AF_UNIX, …)` never sees it. A datagram pair is the connectionless case, so
//! `connect` on one half re-targets it at any path — where a stream or seqpacket pair,
//! already connected, answers EISCONN.

fn main() -> std::process::ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: socketpair-probe <socket-path>");
        return std::process::ExitCode::FAILURE;
    };

    // Both halves held, so the peer outliving the retarget is not what the result rests on.
    let (ours, _theirs) = match std::os::unix::net::UnixDatagram::pair() {
        Ok(pair) => pair,
        Err(error) => {
            eprintln!("SOCKETPAIR DENIED: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    if let Err(error) = ours.connect(&path) {
        eprintln!("UNIX CONNECT DENIED: {error}");
        return std::process::ExitCode::FAILURE;
    }

    match ours.send(b"FROM-SOCKETPAIR") {
        Ok(_) => {
            println!("UNIX SEND SUCCEEDED");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("UNIX SEND DENIED: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
