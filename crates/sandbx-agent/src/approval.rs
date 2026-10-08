//! What [`run_turn`](crate::run_turn) asks before it runs a tool call, and what it reports
//! once the call is done with.
//!
//! Two methods, both required: the loop knows what became of every call and a caller is the
//! only thing that can tell an operator. `context/decision-approval-gate.md` has the rest.

use sandbx_tools::{BuiltinTool, ToolError};

/// A tool call the model asked for, resolved and offered but not yet run.
#[derive(Debug, Clone, Copy)]
pub struct ToolCall<'a> {
    /// The tool, resolved and known to be one the turn offered; `BuiltinTool::risk` classifies it.
    pub tool: BuiltinTool,
    /// The id the answer must carry back, unique within the round.
    pub id: &'a str,
    /// The arguments as the model sent them, unparsed: each tool parses its own.
    pub input: &'a serde_json::Value,
}

/// Whether a tool call may run, and whether the turn can go on asking.
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
    /// Do not run it, tell the model why, and end the turn there.
    ///
    /// For a gate that can no longer be *asked* — a consent channel that went away — not one
    /// that decided no: the rest of the round is refused unasked, and
    /// [`TurnStop::GateAborted`](crate::TurnStop::GateAborted) ends the turn.
    Abort {
        /// The text of a `tool_result` marked `is_error`, as in [`Deny`](Self::Deny).
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
/// verdicts accounts for neither the refusals above it nor what the tool went on to do (#169).
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
/// Mandatory, and [`settled`](Self::settled) required rather than defaulted: a reporter a
/// caller acquires by omitting an argument is one nobody chose. Both methods run on the async
/// task with no `spawn_blocking` of their own, so neither may wait on anything *the runtime
/// drives* — a tokio primitive, a channel or lock a task holds, which deadlocks a
/// current-thread runtime; a descriptor no task feeds is outside that, as `sandbx-cli` asks
/// per call.
pub trait CallGate {
    /// Whether this call may run, asked before the tool is spawned and never racing it.
    ///
    /// Not asked for calls after an [`ApprovalDecision::Abort`]: refused for its reason,
    /// still reported to [`settled`](Self::settled).
    fn approve(&mut self, call: ToolCall<'_>) -> ApprovalDecision;

    /// What became of one call, reported exactly once per `tool_use` block in the round.
    ///
    /// Not called for the *failure* that ends the turn: a panicking tool is a
    /// `TurnError::ToolPanicked`, with no result to report; an abort still is, since its
    /// round has results.
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
