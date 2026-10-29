//! Tries to create an io_uring instance. Test-only.
//!
//! io_uring dispatches queued operations without issuing the syscalls, routing around the
//! whole denylist, so `io_uring_setup` itself must be refused.

use std::process::ExitCode;

fn main() -> ExitCode {
    match io_uring::IoUring::new(8) {
        Ok(_) => {
            println!("IO_URING SETUP SUCCEEDED");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("IO_URING SETUP DENIED: {error}");
            ExitCode::FAILURE
        }
    }
}
