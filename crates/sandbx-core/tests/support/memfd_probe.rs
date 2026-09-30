//! Tries to create an anonymous in-memory file and reports whether the kernel
//! allowed it.
//!
//! Test-only (`required-features = ["sandbox-integration"]`), so it is never
//! part of a normal build.
//!
//! `memfd_create` hands back a file descriptor backed by RAM with no path on any
//! filesystem, which makes it the usual way to stage a payload where Landlock
//! has nothing to match on. This probe exists to prove the syscall is refused.
//! It reaches it through `nix`, already a dependency: `sandbx-core` forbids
//! `unsafe`, so a probe cannot issue the raw syscall itself.

fn main() -> std::process::ExitCode {
    match nix::sys::memfd::memfd_create("sandbx-probe", nix::sys::memfd::MFdFlags::MFD_CLOEXEC) {
        Ok(_) => {
            println!("MEMFD CREATE SUCCEEDED");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("MEMFD CREATE DENIED: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
