//! Tools an agent can call, each confined by `sandbx-core`.
//!
//! The built-ins split across the sandbox's two halves: `bash` spawns a process and
//! the kernel confines it (Landlock, netns, seccomp); the rest touch the filesystem
//! in-process, where `FsGuard` is the only confinement. Dispatch is a closed enum,
//! not `dyn Tool`, resolved by one match over a per-tool `ToolSpec`.

mod builtin;
mod context;
mod error;
mod limits;
mod shared;
mod tools;

pub use builtin::{BuiltinTool, RiskLevel, ToolOutput};
pub use context::{DEFAULT_TIMEOUT, ExecutionContext};
pub use error::ToolError;
pub use limits::ToolLimits;

pub(crate) use builtin::ToolSpec;
pub(crate) use shared::{failed, guard_error, listing, parse, read_capped, read_file};
