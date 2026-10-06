//! What [`run_turn`] asks before it runs a tool call, and the two answers it takes.
//!
//! The types only; the decision is the caller's, passed in as a closure so this crate
//! holds no opinion about which calls are worth refusing.
//!
//! [`run_turn`]: crate::run_turn

use sandbx_tools::BuiltinTool;

/// A tool call the model asked for, resolved but not yet run.
///
/// Handed to the gate by value: three borrowed fields, and a `&ToolCall` bound would
/// need naming the lifetime at every closure.
#[derive(Debug, Clone, Copy)]
pub struct ToolCall<'a> {
    /// The tool, already resolved — a name no tool answers to never reaches a gate.
    /// `BuiltinTool::risk` is what a gate deciding by category reads.
    pub tool: BuiltinTool,
    /// The id the answer must carry back, unique within the round.
    pub id: &'a str,
    /// The arguments as the model sent them, unparsed: each tool parses its own.
    pub input: &'a serde_json::Value,
}

/// Whether a tool call may run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Run it.
    Allow,
    /// Do not run it, and tell the model why.
    Deny {
        /// What the model is told, as the text of a `tool_result` marked `is_error`.
        /// It is the only account it gets, so name what would lift the refusal.
        reason: String,
    },
}
