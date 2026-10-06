//! What [`run_turn`] asks before it runs a tool call, and the two answers it takes.
//!
//! The types only; the decision is a caller's closure, and so is its granularity —
//! `sandbx-cli`'s is per tool per run, not per call (`context/decision-approval-gate.md`).
//!
//! [`run_turn`]: crate::run_turn

use sandbx_tools::BuiltinTool;

/// A tool call the model asked for, resolved and offered but not yet run.
#[derive(Debug, Clone, Copy)]
pub struct ToolCall<'a> {
    /// The tool, resolved and known to be one the turn offered; `BuiltinTool::risk`
    /// classifies it.
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
        /// The text of a `tool_result` marked `is_error`: the model's only account, so
        /// name what would lift the refusal.
        reason: String,
    },
}
