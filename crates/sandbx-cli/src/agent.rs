//! `agent-run`: one prompt, one streamed answer, tool calls through the boundary.
//!
//! Single-shot and non-interactive, so there is nothing to persist between turns and
//! nobody to ask mid-turn: the approval gate is decided from argv before the first
//! request goes out.

use std::io::Write;

use sandbx_agent::{ApprovalDecision, ToolCall, Turn, TurnLimits, run_turn};
use sandbx_core::SandboxPolicy;
use sandbx_providers::{
    AgentEvent, AnthropicClient, ContentBlock, RequestMessage, Role, StopReason,
};
use sandbx_tools::{BuiltinTool, ExecutionContext, RiskLevel};

use crate::{AgentError, Grants, PolicyError};

/// The model asked when `--model` is not given.
///
/// The default lives here because `Turn::model` is a freeform string with no
/// context-window table behind it, so no layer below has an opinion to inherit.
const DEFAULT_MODEL: &str = "claude-sonnet-5";

/// The output ceiling for one turn when `--max-tokens` is not given.
const DEFAULT_MAX_TOKENS: u32 = 4096;

/// The exit code for an answer `--max-tokens` cut short.
///
/// Neither success nor failure: what reached stdout is a real answer and an incomplete
/// one, which a script consuming it has to be able to tell apart.
const TRUNCATED: i32 = 2;

/// The flag that lifts the default refusal.
///
/// Named once because a refusal is read twice — by the operator on stderr and by the
/// model in the `tool_result` — and two accounts of the same refusal must not advise
/// differently.
const ALLOW_TOOL: &str = "--allow-tool";

/// `sandbx agent-run [--allow-…] -- <prompt>`
#[derive(Debug, clap::Args)]
pub struct AgentRun {
    #[command(flatten)]
    grants: Grants,

    /// The model to ask.
    #[arg(long, value_name = "NAME", default_value = DEFAULT_MODEL)]
    model: String,

    /// Cap the tokens the model may produce in one turn.
    ///
    /// Bounds the answer, not the prompt. A turn that hits the cap stops mid-sentence
    /// and says so on stderr.
    #[arg(long = "max-tokens", value_name = "N", default_value_t = DEFAULT_MAX_TOKENS)]
    max_tokens: u32,

    /// Give the model a system prompt.
    ///
    /// Unset sends none, so the model is told only what the tools' own descriptions say.
    #[arg(long, value_name = "TEXT")]
    system: Option<String>,

    /// Let the model call a tool that does more than read. Repeatable.
    ///
    /// Without it only the read-only tools run — `read`, `ls`, `grep` and
    /// `find`. A `write`, an `edit` or a `bash` goes back to the model refused,
    /// which it is told about and may work around. Name a tool to approve it,
    /// or pass the flag bare to approve all seven.
    ///
    /// Approval is for the run, not for the call: `--allow-tool bash` lets the
    /// model run every command it chooses to, and nothing asks you in between.
    /// The policy flags are still what bounds where an approved call can reach.
    // `Option<Vec<_>>` is what gives three states, as on `--allow-network`.
    #[arg(
        long = "allow-tool",
        value_name = "TOOL",
        num_args = 0..=1,
        value_parser = tool_name,
    )]
    allow_tool: Option<Vec<BuiltinTool>>,

    /// The prompt to send.
    // `last` keeps the separator meaningful: a prompt beginning with `-` needs no
    // quoting trick. Not a `///`, which would reach `--help`.
    #[arg(last = true, required = true, value_name = "PROMPT")]
    prompt: Vec<String>,
}

impl AgentRun {
    /// The policy these flags describe.
    pub fn policy(&self) -> Result<SandboxPolicy, PolicyError> {
        self.grants.policy()
    }

    /// The model to ask.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The cap on what the model may produce in one turn.
    pub fn max_tokens(&self) -> u32 {
        self.max_tokens
    }

    /// The system prompt, or `None` to send none.
    pub fn system(&self) -> Option<&str> {
        self.system.as_deref()
    }

    /// Whether the model may call `tool` in this run.
    ///
    /// Fail-closed, because there is no operator to ask: a tool that does more than read
    /// runs only when a flag named it, or when the bare flag approved every tool. A read-
    /// only tool is approved either way, so `--allow-tool write` does not have to re-list
    /// the four it did not mean to withdraw.
    pub fn approves(&self, tool: BuiltinTool) -> bool {
        if tool.risk() == RiskLevel::ReadOnly {
            return true;
        }

        match self.allow_tool.as_deref() {
            None => false,
            // An empty `Vec` is the bare flag: every occurrence was bare, so none named a
            // tool. Which makes `--allow-tool --allow-tool write` an approval of `write`
            // alone, the broader spelling yielding the narrower set, as `--allow-network`.
            Some([]) => true,
            Some(named) => named.contains(&tool),
        }
    }

    /// The decision for one call, and the operator's line about it.
    ///
    /// The line is printed here and not from `observe`, which fires while the round is
    /// still streaming — before this runs, so it would announce a call this then refuses.
    fn gate(&self, requested: ToolCall<'_>) -> ApprovalDecision {
        let name = requested.tool.name();

        if self.approves(requested.tool) {
            eprintln!("sandbx: running {name}");
            return ApprovalDecision::Allow;
        }

        eprintln!("sandbx: refused {name}, which needs `{ALLOW_TOOL} {name}`");
        ApprovalDecision::Deny {
            reason: format!(
                "the `{name}` tool is not approved for this run: \
                 it runs only when sandbx is started with `{ALLOW_TOOL} {name}`"
            ),
        }
    }

    /// The prompt, as one string.
    ///
    /// Cannot panic: `required = true` on a `last` argument means clap rejects an empty
    /// prompt first.
    pub fn prompt(&self) -> String {
        self.prompt.join(" ")
    }

    /// Run one turn, stream the answer, and report the code to exit with.
    ///
    /// `0` for an answer the model finished, `2` for one `--max-tokens` cut off.
    ///
    /// # Errors
    ///
    /// [`AgentError::EmptyPrompt`], [`AgentError::Policy`] and [`AgentError::Provider`]
    /// all land before any request goes out; [`AgentError::Turn`] when the turn ends
    /// without an answer, and
    /// [`AgentError::Output`] when stdout would not take it. A tool that the policy
    /// refuses is none of them: it goes back to the model as a failed result, which is
    /// what lets it try something the policy allows.
    pub async fn execute(&self) -> Result<i32, AgentError> {
        let prompt = self.prompt();
        // Caught here because the API rejects an empty text block with a 400, so letting
        // it through buys a round trip to be told what was knowable before it.
        if prompt.trim().is_empty() {
            return Err(AgentError::EmptyPrompt);
        }

        // No `with_helper`: the default path re-execs this binary, and `main` dispatches
        // helper mode before parsing, so the shipped binary is its own helper.
        // Derived before the client, so a policy this refuses never reads the key.
        let ctx = ExecutionContext::new(self.policy()?);

        let client = AnthropicClient::from_env()?;

        let history = [RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text { text: prompt }],
        }];

        let turn = Turn {
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            system: self.system.clone(),
            tools: &BuiltinTool::ALL,
            history: &history,
            limits: TurnLimits::default(),
            // Nothing to thread in: a single-shot turn has no previous one.
            observed: None,
            withheld: 0,
        };

        let mut render = Render::new(std::io::stdout());
        let outcome = run_turn(
            |request| client.stream_chat(request),
            turn,
            &ctx,
            |event| render.event(event),
            |requested| self.gate(requested),
        )
        .await;

        // Closed before the turn's own error is propagated: a turn that died mid-stream
        // has already written part of an answer, and left the line it was on open.
        let code = render.finish();
        outcome?;
        code
    }
}

/// Accept a tool `--allow-tool` can actually approve, and refuse anything else.
///
/// `BuiltinTool::from_name` is exact-match, so a near miss resolves to nothing: taking
/// it would approve nothing and exit 0, leaving whoever typed `--allow-tool shell`
/// believing `bash` was approved. The CLI refuses loudly, and names what to write, for
/// the same reason `--allow-env` does.
fn tool_name(value: &str) -> Result<BuiltinTool, String> {
    BuiltinTool::from_name(value).ok_or_else(|| {
        let names: Vec<&str> = BuiltinTool::ALL.iter().map(|tool| tool.name()).collect();
        format!(
            "no tool is called `{value}`; the tools are {}",
            names.join(", ")
        )
    })
}

/// Writes a turn out: the answer on stdout, everything about it on stderr.
///
/// The split is what lets stdout be piped to something that wants the answer alone.
struct Render<W> {
    out: W,

    /// Whether the last round stopped at `max_tokens`.
    ///
    /// Last-one-wins because every round ends with a `Stop` and only the final one says
    /// how the *turn* ended — an intermediate one reports a round that then went on.
    truncated: bool,

    /// Whether stdout is part-way through a line, so it is terminated once and only if
    /// the model did not terminate it already.
    mid_line: bool,

    /// The first write that failed, kept because `observe` has no way to end the turn.
    failed: Option<std::io::Error>,
}

impl<W: Write> Render<W> {
    fn new(out: W) -> Self {
        Self {
            out,
            truncated: false,
            mid_line: false,
            failed: None,
        }
    }

    /// Put one event where it belongs.
    fn event(&mut self, event: &AgentEvent) {
        match event {
            AgentEvent::Text { delta } => {
                self.write(delta.as_bytes());
                if !delta.is_empty() {
                    self.mid_line = !delta.ends_with('\n');
                }
            }
            AgentEvent::Stop { reason } => {
                self.truncated = matches!(reason, StopReason::MaxTokens);
            }
            // A requested call is announced by `AgentRun::gate`, which knows whether it
            // ran. The cost is that a name no tool answers to reaches only the model.
            AgentEvent::ToolCallRequested { .. }
            | AgentEvent::Thinking { .. }
            | AgentEvent::Usage { .. } => {}
        }
    }

    /// Close the answer off, and report what the way it ended means for the exit code.
    fn finish(&mut self) -> Result<i32, AgentError> {
        if self.mid_line {
            self.write(b"\n");
        }

        if let Some(error) = self.failed.take() {
            return Err(AgentError::Output(error));
        }

        if self.truncated {
            // Otherwise a truncated answer reads as a complete one.
            eprintln!("sandbx: answer truncated at --max-tokens");
            return Ok(TRUNCATED);
        }

        Ok(0)
    }

    /// Flushed per call: a line-buffered stdout holds the answer back until the model
    /// happens to emit a newline, which is the difference between streaming and not.
    fn write(&mut self, bytes: &[u8]) {
        if self.failed.is_some() {
            return;
        }

        if let Err(error) = self.out.write_all(bytes).and_then(|()| self.out.flush()) {
            self.failed = Some(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(delta: &str) -> AgentEvent {
        AgentEvent::Text {
            delta: delta.to_string(),
        }
    }

    fn stop(reason: StopReason) -> AgentEvent {
        AgentEvent::Stop { reason }
    }

    /// Writes nothing and fails every time, like a pipe whose reader has gone.
    struct ClosedPipe;

    impl Write for ClosedPipe {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Everything stdout received, and what the turn would have exited with.
    fn drive(events: &[AgentEvent]) -> (String, Result<i32, AgentError>) {
        let mut render = Render::new(Vec::new());
        for event in events {
            render.event(event);
        }

        let code = render.finish();
        (String::from_utf8(render.out).expect("utf-8"), code)
    }

    #[test]
    fn a_rounds_stop_does_not_terminate_the_answer() {
        let (written, code) = drive(&[
            text("looking"),
            stop(StopReason::ToolUse),
            text(" — found it"),
            stop(StopReason::EndTurn),
        ]);

        // One trailing newline, not one per round.
        assert_eq!(written, "looking — found it\n");
        assert_eq!(code.expect("clean turn"), 0);
    }

    #[test]
    fn only_the_last_stop_decides_whether_it_was_cut() {
        let (_, intermediate) = drive(&[
            stop(StopReason::MaxTokens),
            text("and then it went on"),
            stop(StopReason::EndTurn),
        ]);
        assert_eq!(intermediate.expect("clean turn"), 0);

        let (_, last) = drive(&[stop(StopReason::EndTurn), stop(StopReason::MaxTokens)]);
        assert_eq!(last.expect("truncated turn"), TRUNCATED);
    }

    #[test]
    fn an_answer_cut_short_mid_line_is_still_terminated() {
        // No `Stop` at all: the shape of a turn that died mid-stream.
        let (written, _) = drive(&[text("partial answ")]);
        assert_eq!(written, "partial answ\n");
    }

    #[test]
    fn a_terminated_answer_is_not_terminated_twice() {
        let (written, _) = drive(&[text("hi\n"), stop(StopReason::EndTurn)]);
        assert_eq!(written, "hi\n");
    }

    #[test]
    fn an_empty_delta_leaves_the_line_where_it_was() {
        let (written, _) = drive(&[text("hi\n"), text(""), stop(StopReason::EndTurn)]);
        assert_eq!(written, "hi\n");
    }

    #[test]
    fn a_turn_that_wrote_nothing_adds_no_newline() {
        let (written, _) = drive(&[stop(StopReason::EndTurn)]);
        assert_eq!(written, "");
    }

    #[test]
    fn a_turn_nothing_can_read_is_reported_not_swallowed() {
        let mut render = Render::new(ClosedPipe);
        render.event(&text("hi"));
        render.event(&stop(StopReason::EndTurn));

        assert!(matches!(render.finish(), Err(AgentError::Output(_))));
    }
}
