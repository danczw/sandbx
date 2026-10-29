//! Calls `truncate(2)` on a path. Test-only.
//!
//! Not a shell one-liner: `: > file` and `truncate(1)` go through
//! `open(O_TRUNC)`/`ftruncate`, covered by Landlock's `WriteFile`; only `truncate(2)` on a
//! path exercises the `Truncate` right.

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = env::args().nth(1) else {
        eprintln!("usage: truncate-probe <path>");
        return ExitCode::FAILURE;
    };

    match nix::unistd::truncate(path.as_str(), 0) {
        Ok(()) => {
            println!("TRUNCATE SUCCEEDED");
            ExitCode::SUCCESS
        }
        Err(errno) => {
            eprintln!("TRUNCATE DENIED: {errno}");
            ExitCode::FAILURE
        }
    }
}
