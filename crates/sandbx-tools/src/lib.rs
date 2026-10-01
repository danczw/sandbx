//! Tools an agent can call, each confined by `sandbx-core`.
//!
//! The built-ins split across the sandbox's two halves. `bash` spawns a process
//! and is confined by the kernel (Landlock, netns, seccomp). The rest touch the
//! filesystem in-process, so the kernel never sees them and `FsGuard` is what
//! keeps them inside the policy.
//!
//! Dispatch is a closed enum rather than `dyn Tool`: the set is fixed and there
//! is no plugin system, so the compiler can check exhaustiveness. That is the
//! point at which to reach for trait objects, not before.

mod context;
mod error;
mod limits;
mod tools;

pub use context::{DEFAULT_TIMEOUT, ExecutionContext};
pub use error::ToolError;
pub use limits::OutputLimits;

/// What a tool produced, as the model will see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    /// Text handed back to the model.
    pub content: String,
}

/// The tools an agent may call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinTool {
    /// Read a file.
    Read,
    /// Create or replace a file.
    Write,
    /// Run a shell command under the sandbox.
    Bash,
    /// Replace an exact string in a file.
    Edit,
    /// List a directory.
    Ls,
    /// Search file contents for a literal string.
    Grep,
    /// Find files by name.
    Find,
}

impl BuiltinTool {
    /// Every tool an agent can be offered.
    ///
    /// This is the registry: an array, because the variant set is closed and
    /// fieldless and a linear scan over seven entries resolves as fast as a map.
    pub const ALL: [Self; 7] = [
        Self::Read,
        Self::Write,
        Self::Bash,
        Self::Edit,
        Self::Ls,
        Self::Grep,
        Self::Find,
    ];

    /// Resolve the name a model called back with.
    ///
    /// Exact match only: a model asking for `Read` is not asking for `read`,
    /// and quietly accepting near-misses would hide a prompt or schema bug.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }

    /// The name the model calls this tool by.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Bash => "bash",
            Self::Edit => "edit",
            Self::Ls => "ls",
            Self::Grep => "grep",
            Self::Find => "find",
        }
    }

    /// JSON schema of this tool's arguments, derived from its input struct.
    ///
    /// Returned as `serde_json::Value` rather than `schemars::Schema`: every
    /// caller converts it on the way to a provider request, so converting here
    /// keeps a foreign type out of the signature.
    pub fn input_schema(&self) -> serde_json::Value {
        match self {
            Self::Read => schemars::schema_for!(tools::read::ReadInput).to_value(),
            Self::Write => schemars::schema_for!(tools::write::WriteInput).to_value(),
            Self::Bash => schemars::schema_for!(tools::bash::BashInput).to_value(),
            Self::Edit => schemars::schema_for!(tools::edit::EditInput).to_value(),
            Self::Ls => schemars::schema_for!(tools::ls::LsInput).to_value(),
            Self::Grep => schemars::schema_for!(tools::grep::GrepInput).to_value(),
            Self::Find => schemars::schema_for!(tools::find::FindInput).to_value(),
        }
    }

    /// Run the tool.
    ///
    /// Arguments are parsed against the schema first, so malformed input is
    /// rejected before anything touches the filesystem.
    pub fn execute(
        &self,
        input: serde_json::Value,
        ctx: &ExecutionContext,
    ) -> Result<ToolOutput, ToolError> {
        match self {
            Self::Read => tools::read::execute(parse(input)?, ctx),
            Self::Write => tools::write::execute(parse(input)?, ctx),
            Self::Bash => tools::bash::execute(parse(input)?, ctx),
            Self::Edit => tools::edit::execute(parse(input)?, ctx),
            Self::Ls => tools::ls::execute(parse(input)?, ctx),
            Self::Grep => tools::grep::execute(parse(input)?, ctx),
            Self::Find => tools::find::execute(parse(input)?, ctx),
        }
    }
}

/// Turn a guard refusal into the form the model sees.
///
/// Shared so every filesystem tool reports a refusal in the same shape.
pub(crate) fn denied(path: &std::path::Path, error: sandbx_core::SandboxError) -> ToolError {
    ToolError::Denied {
        subject: path.display().to_string(),
        reason: error.to_string(),
    }
}

/// Turn a failed filesystem operation into the form the model sees.
///
/// `verb` names what was attempted, so the subject reads the way the tool's own
/// name would (`read /etc/hosts`, `list /tmp`) rather than naming the syscall.
pub(crate) fn failed(
    verb: &str,
    path: &std::path::Path,
    error: impl std::fmt::Display,
) -> ToolError {
    ToolError::Failed {
        subject: format!("{verb} {}", path.display()),
        detail: error.to_string(),
    }
}

/// Read a file's contents through the guard.
///
/// The guard check lives here, not at the call sites, so no in-process tool can
/// read a file by forgetting it. Returns an open-handle read rather than a path:
/// a path would be re-resolved on open, leaving a window for the leaf to be
/// swapped for a symlink after the policy check.
pub(crate) fn read_file(
    path: &std::path::Path,
    ctx: &ExecutionContext,
) -> Result<String, ToolError> {
    let mut file = ctx
        .guard()
        .open_read(path)
        .map_err(|error| denied(path, error))?;

    let mut content = String::new();
    std::io::Read::read_to_string(&mut file, &mut content)
        .map_err(|error| failed("read", path, error))?;
    Ok(content)
}

/// Render a list of results, bounded, distinguishing "none" from empty output.
pub(crate) fn listing(lines: Vec<String>, ctx: &ExecutionContext) -> ToolOutput {
    if lines.is_empty() {
        return ToolOutput {
            content: "no matches".to_string(),
        };
    }

    ToolOutput {
        content: ctx.limits().take_entries(lines).join("\n"),
    }
}

/// Parse tool arguments, reporting a schema mismatch rather than a panic.
fn parse<T: serde::de::DeserializeOwned>(input: serde_json::Value) -> Result<T, ToolError> {
    serde_json::from_value(input).map_err(|error| ToolError::BadInput {
        detail: error.to_string(),
    })
}
