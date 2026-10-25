//! Unit tests for the syscall filter, split by what they gate on. [`bpf`] holds the `eval`
//! interpreter they are all read through.
//!
//! Kernel-free — the program is evaluated here rather than installed, so these run anywhere.
//! `tests/enforcement_syscalls.rs` is where a live kernel refuses a call.

mod arch;
mod bpf;
mod denylist;
mod namespaces;
mod sockets;
