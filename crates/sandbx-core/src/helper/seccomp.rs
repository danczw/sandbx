//! The seccomp syscall filter applied to the sandboxed command.
//!
//! Covers the escapes Landlock cannot see: a syscall that reaches the kernel without naming
//! a path. [`rules`] holds what is denied; [`filter`] holds how it reaches the kernel.

mod filter;
mod rules;

pub(super) use filter::deny_dangerous_syscalls;
pub use rules::BLOCKED_SYSCALLS;

#[cfg(test)]
mod tests;
