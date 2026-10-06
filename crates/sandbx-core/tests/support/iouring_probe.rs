//! Tries to create an io_uring instance. Test-only.
//!
//! io_uring dispatches queued operations without issuing the syscalls, routing around the
//! whole denylist, so `io_uring_setup` itself must be refused.

fn main() -> std::process::ExitCode {
    match io_uring::IoUring::new(8) {
        Ok(_) => {
            println!("IO_URING SETUP SUCCEEDED");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("IO_URING SETUP DENIED: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
