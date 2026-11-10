//! Tools an agent can call, each confined by `sandbx-core`.
//!
//! The built-ins split across the sandbox's two halves: `bash` spawns a process and
//! the kernel confines it (Landlock, netns, seccomp); the rest touch the filesystem
//! in-process, where `FsGuard` is the only confinement. Dispatch is a closed enum,
//! not `dyn Tool`, resolved by one match over a per-tool `ToolSpec`: nothing picks a tool
//! at runtime that is not in the set, so the open set a trait object buys would go unused.

mod builtin_tool;
mod execution_context;
mod shared;
mod tool_error;
mod tool_limits;
mod tools;

pub use builtin_tool::{BuiltinTool, RiskLevel, ToolOutput};
pub use execution_context::{DEFAULT_TIMEOUT, ExecutionContext};
pub use tool_error::ToolError;
pub use tool_limits::ToolLimits;

pub(crate) use builtin_tool::ToolSpec;
pub(crate) use shared::{
    Cut, MAX_FILE_BYTES, Scan, failed, guard_error, listing, parse, read_capped, read_file,
    read_head,
};
pub(crate) use tool_limits::byte_marker;
