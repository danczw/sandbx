//! What a run is allowed to reach: [`sandbox`] holds the axes, the network and env
//! policy and the builders that widen them; [`vetted`] holds what a path had to pass.

#[path = "policy_sandbox.rs"]
mod sandbox;
#[path = "policy_vetted.rs"]
mod vetted;

pub(crate) use sandbox::is_resolvable_name;
pub use sandbox::{Axis, DNS_NAME_LIMIT, Grants, NAMESERVER_PORT, NetworkPolicy, SandboxPolicy};
pub(crate) use vetted::Confirmation;
pub use vetted::{ObjectId, VettedPath};
