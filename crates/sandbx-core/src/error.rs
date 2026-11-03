//! What the sandbox refuses. [`sandbox_error`] holds the closed error set and the access
//! each refusal names; [`helper_refusal`] holds what the helper reports back across the
//! audit channel.

#[path = "helper_refusal.rs"]
mod helper_refusal;
#[path = "sandbox_error.rs"]
mod sandbox_error;

pub use helper_refusal::HelperRefusal;
pub use sandbox_error::{Access, SandboxError};
