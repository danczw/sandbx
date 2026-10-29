//! What the sandbox refuses. [`sandbox`] holds the closed error set and the access each
//! refusal names; [`refusal`] holds what the helper reports back across the audit channel.

#[path = "error_refusal.rs"]
mod refusal;
#[path = "error_sandbox.rs"]
mod sandbox;

pub use refusal::HelperRefusal;
pub use sandbox::{Access, SandboxError};
