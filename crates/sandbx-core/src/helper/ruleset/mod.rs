//! Building and applying the Landlock ruleset: filesystem paths, and TCP ports.
//!
//! [`compat`] is what *this kernel* will enforce: the ABI floor, the ceiling, the ladder
//! between them, the verdict on what came back. [`rights`] is what the *policy* maps to at a
//! given ABI. They meet in [`requested`](mod@requested), because the rights a grant confers
//! depend on which ABI was negotiated. [`opened`] is the one axis neither covers: which
//! directory a grant turns out to name. Nothing here restricts this process.

mod compat;
mod opened;
mod requested;
mod rights;
#[cfg(test)]
mod tests;

pub(super) use compat::{enforcement_verdict, landlock_failed};
pub(super) use opened::open_grant;
pub(super) use requested::{Requested, RequestedNet, requested};
