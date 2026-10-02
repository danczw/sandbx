//! Calls `truncate(2)` on a path; test-only
//! (`required-features = ["sandbox-integration"]`). Not a shell one-liner:
//! `: > file` and `truncate(1)` go through `open(O_TRUNC)`/`ftruncate`, covered
//! by Landlock's `WriteFile`; only `truncate(2)` on a path exercises the
//! `Truncate` right.

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
