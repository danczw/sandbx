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
//!
//! What a tool *is* — its name, the description the model steers on, its argument
//! schema, its executor — is one `ToolSpec` in the tool's own module, beside
//! the input struct and the `execute` those four describe. Four parallel matches
//! here let an arm be transposed into a neighbour's and still compile, which
//! happened once (#55) and went unnoticed a second time (#88). One match moves
//! all four together.

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

/// Everything [`BuiltinTool`] knows about one tool, written once in that tool's
/// own module.
///
/// Two `&'static str`s and two function pointers is a table, not a vtable with an
/// open set behind it: it is reachable only through an exhaustive match on a
/// closed, fieldless enum, so nothing becomes extensible and the compiler still
/// checks every variant is handled. The crate doc's objection to `dyn Tool` is to
/// *runtime* membership, which this does not reopen.
///
/// The schema is a function rather than a value because `schema_for!` allocates
/// and so cannot be a `const`.
pub(crate) struct ToolSpec {
    /// The name the model calls this tool by.
    name: &'static str,
    /// What this tool does, in the words the model is shown.
    description: &'static str,
    /// Builds the JSON schema of this tool's arguments.
    schema: fn() -> serde_json::Value,
    /// Parses untyped arguments into this tool's input struct, then runs it.
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

    /// The four facts about this tool, from the module that holds them.
    ///
    /// The only place a variant is tied to a tool. One match rather than four
    /// means a transposed arm relabels a variant *consistently* — it cannot hand
    /// the model one tool's name with another's schema, which is what #55 and #88
    /// each were.
    ///
    /// Returned by value: a [`ToolSpec`] is four words, and copying one out of a
    /// `const` avoids leaning on static promotion to produce a `&'static`.
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

    /// What this tool does, in the words the model is shown.
    ///
    /// Lives in this crate rather than in the agent because this is the string
    /// the model steers on, and prose kept a crate away from the behaviour it
    /// describes drifts from it (#54). The text itself is in the tool's own
    /// `SPEC`, a few lines from the `execute` it describes, so nothing restates
    /// it here. `tools`' module doc says how to write one.
    pub fn description(&self) -> &'static str {
        self.spec().description
    }

    /// JSON schema of this tool's arguments, derived from its input struct.
    ///
    /// Returned as `serde_json::Value` rather than `schemars::Schema`, because
    /// that is the type the only destination wants: a tool definition in a
    /// provider request carries a JSON value, so converting here keeps a foreign
    /// type out of the signature. A caller needing `Schema`'s own API —
    /// validation, `$ref` resolution — should take the `schema_for!` call in the
    /// tool's own module rather than re-parsing this.
    pub fn input_schema(&self) -> serde_json::Value {
        (self.spec().schema)()
    }

    /// Run the tool.
    ///
    /// Each tool's `SPEC` parses into that tool's own input struct before calling
    /// its `execute`, which takes the struct by value — so there is no route to
    /// the filesystem that skips the parse, rather than seven arms that each have
    /// to remember one.
    pub fn execute(
        &self,
        input: serde_json::Value,
        ctx: &ExecutionContext,
    ) -> Result<ToolOutput, ToolError> {
        (self.spec().run)(input, ctx)
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
pub(crate) fn parse<T: serde::de::DeserializeOwned>(
    input: serde_json::Value,
) -> Result<T, ToolError> {
    serde_json::from_value(input).map_err(|error| ToolError::BadInput {
        detail: error.to_string(),
    })
}
