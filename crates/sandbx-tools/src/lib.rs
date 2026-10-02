//! Tools an agent can call, each confined by `sandbx-core`.
//!
//! The built-ins split across the sandbox's two halves: `bash` spawns a process and
//! the kernel confines it (Landlock, netns, seccomp); the rest touch the filesystem
//! in-process, where `FsGuard` is the only confinement. Dispatch is a closed enum,
//! not `dyn Tool`, resolved by one match over a per-tool `ToolSpec`.

mod context;
mod error;
mod limits;
mod tools;

pub use context::{DEFAULT_TIMEOUT, ExecutionContext};
pub use error::ToolError;
pub use limits::ToolLimits;

/// What a tool produced, as the model will see it.
///
/// The field is private so [`ToolOutput::new`] is the only way in, which makes an
/// empty result unrepresentable: the Messages API rejects a `tool_result` whose text
/// is empty, so a tool handing back `""` ends the turn with a provider error. Silent
/// successes (`touch`, `mkdir -p`, `true`) and empty files are ordinary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    content: String,
}

impl ToolOutput {
    /// Wrap text for the model, reporting an empty result instead of sending it.
    pub fn new(content: impl Into<String>) -> Self {
        let content = content.into();
        if content.trim().is_empty() {
            return Self {
                content: EMPTY_OUTPUT.to_string(),
            };
        }

        Self { content }
    }

    /// Text handed back to the model. Never empty.
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Take the text, for a caller that owns the result anyway.
    pub fn into_content(self) -> String {
        self.content
    }
}

/// Stands in for a tool that succeeded without printing anything.
const EMPTY_OUTPUT: &str = "(no output)";

/// Everything [`BuiltinTool`] knows about one tool, written once in that tool's own
/// module. The schema is a function rather than a value because `schema_for!`
/// allocates and so cannot be a `const`.
pub(crate) struct ToolSpec {
    name: &'static str,
    description: &'static str,
    schema: fn() -> serde_json::Value,
    run: fn(serde_json::Value, &ExecutionContext) -> Result<ToolOutput, ToolError>,
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
    pub const ALL: [Self; 7] = [
        Self::Read,
        Self::Write,
        Self::Bash,
        Self::Edit,
        Self::Ls,
        Self::Grep,
        Self::Find,
    ];

    /// Resolve the name a model called back with. Exact match only: accepting
    /// near-misses would hide a prompt or schema bug.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }

    /// The four facts about this tool, from the module that holds them.
    ///
    /// One match rather than four: a transposed arm cannot hand the model one tool's
    /// name with another's schema.
    fn spec(&self) -> ToolSpec {
        match self {
            Self::Read => tools::read::SPEC,
            Self::Write => tools::write::SPEC,
            Self::Bash => tools::bash::SPEC,
            Self::Edit => tools::edit::SPEC,
            Self::Ls => tools::ls::SPEC,
            Self::Grep => tools::grep::SPEC,
            Self::Find => tools::find::SPEC,
        }
    }

    /// The name the model calls this tool by.
    pub fn name(&self) -> &'static str {
        self.spec().name
    }

    /// What this tool does, in the words the model is shown. The text lives in the
    /// tool's own `SPEC`, beside the `execute` it describes, so it cannot drift from
    /// the behaviour.
    pub fn description(&self) -> &'static str {
        self.spec().description
    }

    /// JSON schema of this tool's arguments, derived from its input struct — a
    /// `serde_json::Value` because that is what a provider request carries.
    pub fn input_schema(&self) -> serde_json::Value {
        (self.spec().schema)()
    }

    /// Run the tool. Each tool's `SPEC` parses into that tool's own input struct
    /// first, so no route to the filesystem can skip the parse.
    pub fn execute(
        &self,
        input: serde_json::Value,
        ctx: &ExecutionContext,
    ) -> Result<ToolOutput, ToolError> {
        (self.spec().run)(input, ctx)
    }
}

/// Turn a guard refusal into the form the model sees, one shape for every tool.
pub(crate) fn denied(path: &std::path::Path, error: sandbx_core::SandboxError) -> ToolError {
    ToolError::Denied {
        subject: path.display().to_string(),
        reason: error.to_string(),
    }
}

/// Turn a failed filesystem operation into the form the model sees. `verb` names
/// what was attempted (`read /etc/hosts`, `list /tmp`), not the syscall.
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
/// The guard check lives here, not at the call sites, so no in-process tool can read
/// a file by forgetting it. Reads the handle the guard returns, not the path again:
/// re-resolving on open leaves a window to swap the leaf for a symlink.
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
///
/// `stopped_early` is appended after the entry cap is applied, not before: a marker
/// inside the list is a line the cap can trim away, which would leave a partial
/// search looking complete.
pub(crate) fn listing(
    lines: Vec<String>,
    ctx: &ExecutionContext,
    stopped_early: bool,
) -> ToolOutput {
    if lines.is_empty() && !stopped_early {
        return ToolOutput::new("no matches");
    }

    let mut rendered = ctx.limits().take_entries(lines);
    if stopped_early {
        rendered.push(PARTIAL_SEARCH.to_string());
    }

    ToolOutput::new(rendered.join("\n"))
}

/// Tells the model its search was abandoned, not exhausted — otherwise a scan that
/// gave up reads as one that found nothing, and the symbol looks absent.
const PARTIAL_SEARCH: &str = "... stopped early: scan limit reached, results are incomplete";

/// Parse tool arguments, reporting a schema mismatch rather than a panic.
pub(crate) fn parse<T: serde::de::DeserializeOwned>(
    input: serde_json::Value,
) -> Result<T, ToolError> {
    serde_json::from_value(input).map_err(|error| ToolError::BadInput {
        detail: error.to_string(),
    })
}
