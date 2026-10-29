//! Unit tests for the syscall filter, split by what they gate on. [`bpf`] holds the `eval`
//! interpreter they are all read through.
//!
//! Kernel-free — the program is evaluated here rather than installed, so these run anywhere.
//! `sandbx-helper`'s `tests/enforcement_syscalls.rs` is where a live kernel refuses one.

#[path = "helper_seccomp_tests_arch.rs"]
mod arch;
#[path = "helper_seccomp_tests_bpf.rs"]
mod bpf;
#[path = "helper_seccomp_tests_denylist.rs"]
mod denylist;
#[path = "helper_seccomp_tests_namespaces.rs"]
mod namespaces;
#[path = "helper_seccomp_tests_sockets.rs"]
mod sockets;
