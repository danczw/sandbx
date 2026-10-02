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
pub use limits::ToolLimits;

/// What a tool produced, as the model will see it.
///
/// The field is private so that [`ToolOutput::new`] is the only way in, which
/// is what makes an empty result unrepresentable. The Messages API rejects a
/// `tool_result` whose text content is empty, so a tool handing back `""` does
/// not produce an empty turn — it ends the turn with a provider error and the
/// transcript goes with it. A silent success (`touch`, `mkdir -p`, `true`) and
/// an empty file are both ordinary, so that floor belongs here rather than in
/// each tool's memory.
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

    /// Take the text, for a caller that owns the result anyway — the agent moves
    /// it straight into a `tool_result` block.
    pub fn into_content(self) -> String {
        self.content
    }
}

/// Stands in for a tool that succeeded without printing anything.
const EMPTY_OUTPUT: &str = "(no output)";

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

    /// What this tool does, in the words the model is shown.
    ///
    /// Lives here rather than in the agent because this is the string the model
    /// steers on, and prose kept a crate away from the behaviour it describes
    /// drifts from it (#54). The rustdoc on each `execute` stays the *why* for a
    /// reader of the code; this is the *what* for a caller of the tool, so the
    /// two say deliberately different things.
    ///
    /// Each one names the constraint that changes how the tool is called — an
    /// absolute path, a literal rather than a pattern, a match that must be
    /// unique — because a model that learns those from an error has already
    /// spent a turn.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Read => "Read a file's contents. Takes an absolute path.",
            Self::Write => {
                "Write a file, creating it or replacing its contents entirely. \
                 Takes an absolute path."
            }
            Self::Bash => {
                "Run a shell command. Use it for what the other tools do not \
                 cover; prefer a dedicated tool wherever one fits."
            }
            Self::Edit => {
                "Replace one exact occurrence of a string in a file. The text \
                 must appear exactly once — an absent or ambiguous match is an \
                 error, not a guess."
            }
            Self::Ls => "List a directory's entries. Directories are marked with a trailing slash.",
            Self::Grep => {
                "Search file contents beneath a directory for a literal string. \
                 Not a regular expression."
            }
            Self::Find => "Find files beneath a directory whose name contains a substring.",
        }
    }

    /// JSON schema of this tool's arguments, derived from its input struct.
    ///
    /// Returned as `serde_json::Value` rather than `schemars::Schema`, because
    /// that is the type the only destination wants: a tool definition in a
    /// provider request carries a JSON value, so converting here keeps a foreign
    /// type out of the signature. A caller needing `Schema`'s own API —
    /// validation, `$ref` resolution — should take the `schema_for!` call rather
    /// than re-parsing this.
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
///
/// `stopped_early` is appended after the entry cap is applied, not before: a
/// marker inside the list is a line the cap can trim away, which would leave a
/// partial search looking complete — the one thing the marker exists to prevent.
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

/// Tells the model its search was abandoned, not exhausted.
///
/// Without it a scan that gave up looks like a scan that found nothing, and the
/// model concludes the symbol is absent rather than narrowing its search.
const PARTIAL_SEARCH: &str = "... stopped early: scan limit reached, results are incomplete";

/// Parse tool arguments, reporting a schema mismatch rather than a panic.
fn parse<T: serde::de::DeserializeOwned>(input: serde_json::Value) -> Result<T, ToolError> {
    serde_json::from_value(input).map_err(|error| ToolError::BadInput {
        detail: error.to_string(),
    })
}
