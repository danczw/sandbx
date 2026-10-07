//! What [`run_turn`] asks before it runs a tool call, and what it reports once the call is
//! done with.
//!
//! One trait, two methods, both required: the loop knows what happened to every call and a
//! caller is the only thing that can tell an operator. See
//! `context/decision-approval-gate.md` for the granularity, which is a caller's to choose.
//!
//! [`run_turn`]: crate::run_turn

use sandbx_tools::{BuiltinTool, ToolError};

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

/// One tool call the round has finished with, however it finished.
#[derive(Debug, Clone, Copy)]
pub struct Settled<'a> {
    /// The name the model called back with, which is all there is when nothing resolves it.
    pub name: &'a str,
    /// The id the answer carries, matching the [`ToolCall`] where there was one.
    pub id: &'a str,
    /// The tool, or `None` for a name no tool answers to.
    pub tool: Option<BuiltinTool>,
    /// The arguments as the model sent them, so a report can name what the call was about.
    pub input: &'a serde_json::Value,
    /// What became of it.
    pub outcome: Outcome<'a>,
}

/// What became of one tool call.
///
/// Three of these never reach [`CallGate::approve`], so a gate that reports only its own
/// verdicts accounts for neither the refusals above it nor what the tool went on to do
/// (#169).
#[derive(Debug, Clone, Copy)]
pub enum Outcome<'a> {
    /// No tool answers to the name.
    Unknown,
    /// A tool, but not one `Turn::tools` offered.
    NotOffered,
    /// The gate's own verdict, handed back so one line per call comes from one place.
    Denied {
        /// The `reason` the gate gave.
        reason: &'a str,
    },
    /// It ran and returned output.
    Ran,
    /// It ran and the policy or the tool refused it.
    Errored(&'a ToolError),
}

/// What sits between the model and a tool.
///
/// Mandatory, so a gate-less loop cannot be had by omitting an argument, and
/// [`settled`](Self::settled) is required for the same reason: a defaulted reporter is one
/// a caller acquires silently.
///
/// Both methods run on the async task with no `spawn_blocking` of theirs, so neither may
/// wait on anything *the runtime drives* — a tokio primitive, a channel a task feeds, a
/// lock a task holds — which on a current-thread runtime deadlocks the turn being decided.
/// Blocking on a descriptor no task feeds is outside that, and is how `sandbx-cli` asks an
/// operator per call; see `context/guide-turn-loop.md`.
pub trait CallGate {
    /// Whether this call may run, asked before the tool is spawned and never racing it.
    fn approve(&mut self, call: ToolCall<'_>) -> ApprovalDecision;

    /// What became of one call, reported exactly once per `tool_use` block in the round.
    ///
    /// Not called for the one failure that ends the turn: a panicking tool is a
    /// `TurnError::ToolPanicked`, and the round has no result to report.
    fn settled(&mut self, call: Settled<'_>);
}

/// So a caller that keeps its gate can lend it, `run_turn` taking one by value.
impl<G: CallGate + ?Sized> CallGate for &mut G {
    fn approve(&mut self, call: ToolCall<'_>) -> ApprovalDecision {
        (**self).approve(call)
    }

    fn settled(&mut self, call: Settled<'_>) {
        (**self).settled(call);
    }
}
