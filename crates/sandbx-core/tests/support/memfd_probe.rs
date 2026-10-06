//! Tries to create an anonymous in-memory file. Test-only.
//!
//! `memfd_create` returns a descriptor with no path for Landlock to match on, so the
//! syscall must be refused. The raw errno is printed, so the caller can assert `EPERM`
//! rather than any failure.

fn main() -> std::process::ExitCode {
    match nix::sys::memfd::memfd_create("sandbx-probe", nix::sys::memfd::MFdFlags::MFD_CLOEXEC) {
        Ok(_) => {
            println!("SUCCEEDED");
            std::process::ExitCode::SUCCESS
        }
        Err(errno) => {
            println!("{}", errno as i32);
            std::process::ExitCode::FAILURE
        }
    }
}
