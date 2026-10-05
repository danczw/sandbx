//! `agent-run`: one prompt, one streamed answer, tool calls through the boundary.
//!
//! Single-shot and non-interactive, so there is nothing to persist between turns and no
//! operator to ask before a tool runs.

use std::io::Write;

use sandbx_agent::{Turn, TurnLimits, run_turn};
use sandbx_core::SandboxPolicy;
use sandbx_providers::{
    AgentEvent, AnthropicClient, ContentBlock, RequestMessage, Role, StopReason,
};
use sandbx_tools::{BuiltinTool, ExecutionContext};

use crate::{AgentError, Grants};

/// The model asked when `--model` is not given.
///
/// The default lives here because `Turn::model` is a freeform string with no
/// context-window table behind it, so no layer below has an opinion to inherit.
const DEFAULT_MODEL: &str = "claude-sonnet-5";

/// The output ceiling for one turn when `--max-tokens` is not given.
const DEFAULT_MAX_TOKENS: u32 = 4096;

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

    /// The prompt to send.
    // `last` keeps the separator meaningful: a prompt beginning with `-` needs no
    // quoting trick. Not a `///`, which would reach `--help`.
    #[arg(last = true, required = true, value_name = "PROMPT")]
    prompt: Vec<String>,
}

impl AgentRun {
    /// The policy these flags describe.
    pub fn policy(&self) -> SandboxPolicy {
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

    /// The prompt, as one string.
    ///
    /// Cannot panic: `required = true` on a `last` argument means clap rejects an empty
    /// prompt first.
    pub fn prompt(&self) -> String {
        self.prompt.join(" ")
    }

    /// Run one turn, stream the answer, and report the code to exit with.
    ///
    /// # Errors
    ///
    /// [`AgentError::Provider`] when no API key is reachable — before any request goes
    /// out — and [`AgentError::Turn`] when the turn ends without an answer. A tool that
    /// the policy refuses is neither: it goes back to the model as a failed result, which
    /// is what lets it try something the policy allows.
    pub async fn execute(&self) -> Result<i32, AgentError> {
        let client = AnthropicClient::from_env()?;

        // No `with_helper`: the default path re-execs this binary, and `main` dispatches
        // helper mode before parsing, so the shipped binary is its own helper.
        let ctx = ExecutionContext::new(self.policy());

        let history = [RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: self.prompt(),
            }],
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

        let mut out = std::io::stdout();
        run_turn(
            |request| client.stream_chat(request),
            turn,
            &ctx,
            |event| render(event, &mut out),
        )
        .await?;

        Ok(0)
    }
}

/// Write an event out: the answer on stdout, everything about it on stderr.
///
/// The split is what lets stdout be piped to something that wants the answer alone.
fn render(event: &AgentEvent, out: &mut impl Write) {
    match event {
        // Flushed per delta: a line-buffered stdout holds the answer back until the
        // model happens to emit a newline.
        AgentEvent::Text { delta } => {
            let _ = out.write_all(delta.as_bytes());
            let _ = out.flush();
        }
        AgentEvent::ToolCallRequested { name, .. } => eprintln!("sandbx: running {name}"),
        AgentEvent::Stop { reason } => {
            let _ = out.write_all(b"\n");
            let _ = out.flush();
            // Otherwise a truncated answer reads as a complete one.
            if matches!(reason, StopReason::MaxTokens) {
                eprintln!("sandbx: answer truncated at --max-tokens");
            }
        }
        AgentEvent::Thinking { .. } | AgentEvent::Usage { .. } => {}
    }
}
