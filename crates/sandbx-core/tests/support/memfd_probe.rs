//! Tries to create an anonymous in-memory file and reports the errno the kernel
//! answered with.
//!
//! Test-only (`required-features = ["sandbox-integration"]`), so it is never
//! part of a normal build.
//!
//! `memfd_create` hands back a file descriptor backed by RAM with no path on any
//! filesystem, which makes it the usual way to stage a payload where Landlock
//! has nothing to match on. This probe exists to prove the syscall is refused.
//! It reaches it through `nix`, already a dependency: `sandbx-core` forbids
//! `unsafe`, so a probe cannot issue the raw syscall itself.
//!
//! Prints the raw errno rather than just failing, so the caller can assert on
//! `EPERM` specifically. A non-zero exit alone would also be satisfied by the
//! call failing for some unrelated reason, which would let the test pass while
//! proving nothing about the filter.

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
