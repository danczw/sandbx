//! Building and applying the Landlock filesystem ruleset.
//!
//! Split along the question each half answers: [`compat`] is what *this kernel*
//! will enforce — the ABI floor, the ceiling, the ladder between them, and the
//! verdict on what came back — and [`rights`] is what the *policy* maps to,
//! kernel-independent but for the ABI it is handed. The two meet because the
//! rights a grant confers depend on which ABI was negotiated.
//!
//! [`apply`](super::apply) is what installs the result; nothing in this module
//! restricts the calling process.

mod compat;
mod rights;
#[cfg(test)]
mod tests;

pub(super) use compat::{enforcement_verdict, landlock_failed, negotiated_abi};
pub(super) use rights::fs_rules;
