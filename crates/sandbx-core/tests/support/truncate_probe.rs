//! Calls `truncate(2)` on a path and reports whether the kernel allowed it.
//!
//! Test-only (`required-features = ["sandbox-integration"]`), so it is never
//! part of a normal build.
//!
//! A dedicated probe rather than a shell one-liner because `: > file` and
//! `truncate(1)` both go through `open(O_TRUNC)`/`ftruncate`, which Landlock's
//! `WriteFile` right already covers. Only `truncate(2)` on a *path* exercises
//! the `Truncate` right, which is the access this probe exists to test.

fn main() -> std::process::ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: truncate-probe <path>");
        return std::process::ExitCode::FAILURE;
    };

    match nix::unistd::truncate(path.as_str(), 0) {
        Ok(()) => {
            println!("TRUNCATE SUCCEEDED");
            std::process::ExitCode::SUCCESS
        }
        Err(errno) => {
            eprintln!("TRUNCATE DENIED: {errno}");
            std::process::ExitCode::FAILURE
        }
    }
}
