//! Tries to create an io_uring instance and reports whether the kernel allowed
//! it.
//!
//! Test-only (`required-features = ["sandbox-integration"]`), so it is never
//! part of a normal build.
//!
//! seccomp filters *syscalls*, but io_uring dispatches equivalent operations
//! from a submission queue without issuing them — so a ring set up inside the
//! sandbox is a route around the denylist, including the `socket(AF_UNIX)` rule.
//! Creating the ring needs `io_uring_setup`; this probe exists to prove that
//! syscall is refused.

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
