//! What a run is allowed to reach: [`sandbox_policy`] holds the axes, the network and env
//! policy and the builders that widen them; [`vetted_path`] holds what a path had to pass.

#[path = "sandbox_policy.rs"]
mod sandbox_policy;
#[path = "vetted_path.rs"]
mod vetted_path;

pub(crate) use sandbox_policy::is_resolvable_name;
pub use sandbox_policy::{
    Axis, DNS_NAME_LIMIT, GrantedPath, Grants, NAMESERVER_PORT, NetworkPolicy, SandboxPolicy,
};
pub(crate) use vetted_path::Confirmation;
pub use vetted_path::{ObjectId, VettedPath};
