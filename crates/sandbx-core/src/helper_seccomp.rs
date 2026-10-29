//! The seccomp syscall filter applied to the sandboxed command.
//!
//! Covers the escapes Landlock cannot see: a syscall that reaches the kernel without naming
//! a path. [`rules`] holds what is denied; [`filter`] holds how it reaches the kernel.

#[path = "helper_seccomp_filter.rs"]
mod filter;
#[path = "helper_seccomp_rules.rs"]
mod rules;

pub(super) use filter::deny_dangerous_syscalls;
pub use rules::BLOCKED_SYSCALLS;

#[cfg(test)]
#[path = "helper_seccomp_tests.rs"]
mod tests;
