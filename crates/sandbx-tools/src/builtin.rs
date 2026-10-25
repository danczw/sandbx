//! The closed enum of tools, what the model is told about one — its name, its risk,
//! its schema — and the non-empty text it gets back.

use crate::tools;
use crate::{ExecutionContext, ToolError};

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
        let mut content = content.into();
        if content.trim().is_empty() {
            content = EMPTY_OUTPUT.to_string();
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
///
/// The fields are `pub(crate)` because the seven `SPEC` literals that set them live in
/// `tools/`, no longer sharing this module — private here would reach only `builtin` and
/// below, and every literal would stop compiling. That is the same set they had as private
/// fields of the crate root, and it survives a later widening of the struct: a `pub(crate)`
/// field is invisible outside the crate even on a `pub` struct, so `run` — a direct handle
/// to each tool's executor, bypassing [`BuiltinTool`]'s match — stays crate-private either
/// way.
pub(crate) struct ToolSpec {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    pub(crate) risk: RiskLevel,
    pub(crate) schema: fn() -> serde_json::Value,
    pub(crate) run: fn(serde_json::Value, &ExecutionContext) -> Result<ToolOutput, ToolError>,
}

/// What a tool does beyond looking, for a caller deciding whether to let it run.
///
/// Ordered least to most, so a gate can admit everything at or below a level. A field of
/// `ToolSpec`, so a new tool declares its own level or fails to compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Reads the filesystem and changes nothing.
    ReadOnly,
    /// Creates or rewrites a file.
    Writes,
    /// Runs a program.
    Executes,
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

    /// The five facts about this tool, from the module that holds them.
    ///
    /// One match rather than five: a transposed arm cannot hand the model one tool's
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

    /// What this tool does beyond looking, declared in its own `SPEC`.
    pub fn risk(&self) -> RiskLevel {
        self.spec().risk
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
