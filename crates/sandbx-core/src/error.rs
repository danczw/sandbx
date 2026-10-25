//! What the sandbox refuses. [`sandbox`] holds the closed error set and the access each
//! refusal names; [`refusal`] holds what the helper reports back across the audit channel.

mod refusal;
mod sandbox;

pub use refusal::HelperRefusal;
pub use sandbox::{Access, SandboxError};
