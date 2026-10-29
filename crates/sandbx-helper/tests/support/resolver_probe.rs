//! Resolves a name, connects to one, reads a file or writes one, and reports which it was.
//!
//! Several modes in one binary, bounding resolution being several claims: the granted names
//! resolve, the ungranted do not, the `/etc` files are sandbx's own, each reads back under its
//! own path, and the command cannot rewrite them to add a name.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::{env, fs};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let (Some(mode), Some(target)) = (args.next(), args.next()) else {
        eprintln!(
            "usage: resolver-probe <resolve|connect|read|fdpath|write> <NAME|NAME:PORT|PATH>"
        );
        return ExitCode::FAILURE;
    };

    match mode.as_str() {
        "resolve" => resolve(&target),
        "connect" => connect(&target),
        "read" => read(&target),
        "fdpath" => fd_path(&target),
        "write" => write(&target),
        other => {
            eprintln!("unknown mode {other}");
            ExitCode::FAILURE
        }
    }
}

/// `getaddrinfo` through `ToSocketAddrs`, which is what every command resolves with. Prints
/// the addresses, so a test can tell a name that resolved from one that resolved to nothing.
fn resolve(name: &str) -> ExitCode {
    match (name, 0u16).to_socket_addrs() {
        Ok(addresses) => {
            let found: Vec<String> = addresses.map(|socket| socket.ip().to_string()).collect();
            match found.is_empty() {
                true => {
                    eprintln!("RESOLVE EMPTY: {name}");
                    ExitCode::FAILURE
                }
                false => {
                    println!("RESOLVED {name}: {}", found.join(" "));
                    ExitCode::SUCCESS
                }
            }
        }
        Err(error) => {
            eprintln!("RESOLVE DENIED: {name}: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Resolve `NAME:PORT` and read from it, so a success is a name that resolved to an address
/// the policy could actually reach — not a lookup whose answer goes nowhere.
fn connect(target: &str) -> ExitCode {
    match TcpStream::connect(target) {
        Ok(mut stream) => {
            let mut got = String::new();
            let _ = stream.read_to_string(&mut got);
            println!("CONNECTED {target}: {got}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("CONNECT DENIED: {target}: {error}");
            ExitCode::FAILURE
        }
    }
}

fn read(path: &str) -> ExitCode {
    match fs::read_to_string(path) {
        // `print!`, so a test can compare what the command read against the file byte for byte.
        Ok(body) => {
            print!("{body}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("READ DENIED: {path}: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The path the kernel reads back for an open descriptor on `path`. What `ruleset::opened`
/// reads to vet a grant: a bind whose source had been unlinked reads
/// back with `" (deleted)"` appended, and the grant naming it would be refused.
fn fd_path(path: &str) -> ExitCode {
    let opened = File::open(path).and_then(|file| {
        use std::os::fd::AsRawFd as _;
        fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
    });

    match opened {
        Ok(read_back) => {
            println!("{}", read_back.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("FDPATH DENIED: {path}: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Appends rather than truncating: what a command wanting one more name would do.
fn write(path: &str) -> ExitCode {
    use std::io::Write as _;

    let appended = OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(b"127.0.0.9\tforged.test\n"));

    match appended {
        Ok(()) => {
            println!("WROTE {path}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("WRITE DENIED: {path}: {error}");
            ExitCode::FAILURE
        }
    }
}
