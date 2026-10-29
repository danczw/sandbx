//! `agent-run`'s argv surface, and the one sequence that consumes it.
//!
//! Single-shot: the approval gate is decided from argv before the first request goes out,
//! and `--approve call` narrows that answer per call on the controlling terminal rather
//! than widening it. `--session` carries a conversation between runs as a transcript on
//! disk, not a live session.
//!
//! One module on purpose: the pieces are already in `gate`, `prompt`, `render`, `tui`
//! and `wrapup`, and what is left is the argv surface and the one sequence that
//! consumes it. `AgentRun`'s doc comments are rendered `--help` text, not commentary.

use std::io::{IsTerminal, Write};
use std::{io, slice};

use sandbx_anthropic::AnthropicClient;
use sandbx_core::SandboxPolicy;
use sandbx_event::StopReason;
use sandbx_prompt::{ContentBlock, Prompt, RequestMessage, Role, Thinking};
use sandbx_provider::{EventStream, ProviderError};
use sandbx_session_bridge::{self as session, Merged, SessionChoice};
use sandbx_session_error::SessionError;
use sandbx_session_id::SessionId;
use sandbx_session_message::CompletedTurn;
use sandbx_session_store::Session;
use sandbx_tools::{BuiltinTool, ExecutionContext};
use sandbx_turn::{Turn, TurnLimits, TurnOutcome, TurnStop, run_turn};

use crate::{AgentError, Grants, PolicyError};

use super::gate::{self, tool_name};
use super::prompt::{APPROVE_CALL, Approve, Terminal};
use super::render::{Render, Unfinished};
use super::{orientation, wrapup};

/// The model asked when `--model` is not given.
///
/// Here because `Turn::model` is a freeform string with no context-window table behind
/// it, so no layer below has an opinion to inherit.
const DEFAULT_MODEL: &str = "claude-sonnet-5";

/// The output ceiling for one round when `--max-tokens` is not given.
const DEFAULT_MAX_TOKENS: u32 = 4096;

/// The exit code for an answer a bound cut short.
///
/// Neither success nor failure: stdout holds the text that arrived before the bound, and
/// nothing at all when the model opened with a tool call. Stderr names the bound.
pub(super) const INCOMPLETE: i32 = 2;

/// The exit code for a run whose operator could no longer be asked.
///
/// Not [`INCOMPLETE`], which means a bound the operator chose cut the turn short, and not
/// a failure: the turn ended on purpose and its work is stored. A caller branching on the
/// status has to be able to tell the three apart (#218).
pub(super) const NO_CONSENT: i32 = 3;

/// Where one run writes, and where it asks.
///
/// One argument, not two: stdout and stderr are the same operator seen twice, and a
/// question has to go somewhere stdout's piping can't reach.
struct Channels<W, E> {
    /// The answer, streamed as it arrives.
    out: W,

    /// Everything about the answer: reasoning, and how the turn ended.
    err: E,

    /// Whether `err` renders an SGR escape. Not read off `err`, which a test fakes.
    renders: bool,

    /// The controlling terminal, `Some` only under `--approve call`. No suite here opens
    /// the real device ([`Terminal::open`]), nor the stderr an account falls back to.
    terminal: Option<Terminal>,
}

/// `sandbx agent-run [--allow-…] -- <prompt>`
#[derive(Debug, clap::Args)]
pub struct AgentRun {
    #[command(flatten)]
    grants: Grants,

    /// The model to ask.
    #[arg(long, value_name = "NAME", default_value = DEFAULT_MODEL)]
    model: String,

    /// Cap the tokens the model may produce in one round.
    ///
    /// Bounds the answer, not the prompt. A round cut at the cap stops mid-sentence, and
    /// stderr says so when it is the turn's last round.
    #[arg(long = "max-tokens", value_name = "N", default_value_t = DEFAULT_MAX_TOKENS)]
    max_tokens: u32,

    /// Cap how many rounds of tool calls one turn may spend.
    ///
    /// A turn re-enters once per batch of tool calls, so this bounds how far a looping
    /// model can drive tool execution. A turn that hits the cap says so on stderr and is
    /// then asked once more, a round that may call no tool — `--no-wrap-up` refuses that
    /// one, so the cap is also the number of requests.
    #[arg(
        long = "max-rounds",
        value_name = "N",
        default_value_t = TurnLimits::default().max_rounds,
        value_parser = round_cap,
    )]
    max_rounds: usize,

    /// Do not spend one more request answering a turn that ran out of rounds.
    ///
    /// A turn that reaches `--max-rounds` is otherwise asked once more, a round that may
    /// call no tool, so the reply is prose and stdout gets an answer. This refuses that
    /// request, leaving stdout with whatever arrived before the cap. `--session` stores
    /// the tool work and resumes either way. The exit code is 2 either way.
    #[arg(long = "no-wrap-up")]
    no_wrap_up: bool,

    /// Show the model's reasoning on stderr as it arrives.
    ///
    /// Asks for a summary of it, not the reasoning itself, which the API does not return.
    /// Stderr because stdout is the answer. Nothing of it is stored: a session transcript
    /// holds the same turns either way.
    ///
    /// Models before Claude 4.6 refuse the request outright rather than ignoring it.
    #[arg(long = "show-thinking")]
    pub(super) show_thinking: bool,

    /// Give the model a system prompt.
    ///
    /// Sent after whatever the run says about the tools it approved and the roots they
    /// can reach, neither of which it replaces.
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
    /// model run every command it chooses to, and nothing asks you in between
    /// unless `--approve call` does. The policy flags are still what bounds
    /// where an approved call can reach.
    // `Option<Vec<_>>` is what gives three states, as on `--allow-network`.
    #[arg(
        long = "allow-tool",
        value_name = "TOOL",
        num_args = 0..=1,
        value_parser = tool_name,
    )]
    pub(super) allow_tool: Option<Vec<BuiltinTool>>,

    /// Ask before each call instead of once from argv.
    ///
    /// `run`, the default, takes the whole answer from `--allow-tool`. `call` asks
    /// you on your terminal before each call that does more than read, within
    /// what `--allow-tool` already approved — it can only narrow that set, never
    /// widen it. Answer `y` for the one call, `n` to refuse it, or `a` to approve
    /// every later call to that tool.
    ///
    /// `call` needs a terminal to ask on, and refuses the run without one rather
    /// than falling back to the argv answer. A terminal that goes away mid-run
    /// ends the turn there: the call being asked about and every call behind it
    /// are refused, nothing after them runs, and the run exits 3.
    #[arg(long, value_name = "WHEN", default_value = "run")]
    pub(super) approve: Approve,

    /// Save the conversation, and resume one by id.
    ///
    /// Bare, it starts a session and prints the id to resume it with. With an id,
    /// it sends that conversation's history ahead of the new prompt and appends the
    /// answer. Absent, nothing is read and nothing is written.
    ///
    /// A transcript is plaintext under `$XDG_STATE_HOME/sandbx/sessions`, created
    /// `0600`, and holds whatever a tool read into the conversation. Resuming one that
    /// somebody else can write is refused; one they can only read resumes and says so.
    // `Option<Option<_>>` and not `--allow-tool`'s `Option<Vec<_>>`: this flag names one
    // session, and a `Vec` would take `--session a --session b` and quietly use one.
    #[arg(long, value_name = "ID", num_args = 0..=1, value_parser = session_id)]
    session: Option<Option<SessionId>>,

    /// The prompt to send.
    // `last` keeps the separator meaningful: a prompt beginning with `-` needs no
    // quoting trick. Not a `///`, which would reach `--help`.
    #[arg(last = true, required = true, value_name = "PROMPT")]
    prompt: Vec<String>,
}

impl AgentRun {
    /// The policy these flags describe.
    ///
    /// The credential refusal is first: decidable from argv alone, and a
    /// working-directory refusal landing ahead of it would mask it. It may refuse where
    /// `sandbox-run` grants, never derive a narrower policy.
    pub fn policy(&self) -> Result<SandboxPolicy, PolicyError> {
        if self.grants.names_env(sandbx_auth::ENV_VAR) {
            return Err(PolicyError::HarnessCredential {
                name: sandbx_auth::ENV_VAR,
            });
        }

        self.grants.policy()
    }

    /// The model to ask.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The cap on what the model may produce in one round.
    pub fn max_tokens(&self) -> u32 {
        self.max_tokens
    }

    /// How many times the model may be asked within one turn.
    pub fn max_rounds(&self) -> usize {
        self.max_rounds
    }

    /// The system prompt `--system` gave, before the approved tools and the roots are
    /// prepended to it.
    pub fn system(&self) -> Option<&str> {
        self.system.as_deref()
    }

    /// What `--session` asked for.
    pub fn session(&self) -> SessionChoice<'_> {
        match &self.session {
            None => SessionChoice::Off,
            Some(None) => SessionChoice::New,
            Some(Some(id)) => SessionChoice::Resume(id),
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
    /// `0` for an answer the model finished, `2` for one a bound cut short —
    /// `--max-tokens` or `--max-rounds`.
    ///
    /// # Errors
    ///
    /// [`AgentError::EmptyPrompt`], [`AgentError::Policy`] and [`AgentError::Provider`]
    /// all land before any request goes out. A tool the policy refuses is not an error
    /// here: it goes back to the model as a failed result, which is what lets it try
    /// something the policy allows.
    pub async fn execute(&self) -> Result<i32, AgentError> {
        let prompt = self.prompt();
        // The API rejects an empty text block with a 400, so letting it through buys a
        // round trip to be told what was knowable before it.
        if prompt.trim().is_empty() {
            return Err(AgentError::EmptyPrompt);
        }

        // Before the credential and the session: a run with no channel to ask on is
        // refused, so neither is opened for a turn that will not happen.
        let terminal = self.terminal()?;

        eprintln!(
            "sandbx: tools approved: {}",
            gate::approved_tools(self.allow_tool.as_deref()).join(", ")
        );

        // Ahead of the policy, and that placement is the whole point. The context needs a
        // session — it is what `rooted_access` names — and nothing may sit between
        // `self.policy()?`, which *vets* each granted root, and the context, which *pins*
        // it: that window is time an attacker has to swap a root and force the run onto
        // by-path resolution for good. This call's `eprintln!` can block outright on a
        // stderr nobody drains, so it is the one that could not stay in the middle.
        //
        // The cost, taken deliberately: a refused policy below now leaves a header-only
        // transcript nothing deletes, where before only a missing credential could. A stray
        // directory against a window in the sandbox's TOCTOU guarantee
        // (`guide-sandboxing.md`, *Known gaps*). The credential stays below the policy, so
        // a refused policy still reads no key.
        let session = session::open(self.session())?;

        let policy = self.policy()?;
        // Read off once: a second `self.policy()?` re-reads `getcwd`, and a cwd that moved
        // meanwhile would name the model a root the sandbox did not grant.
        let system = orientation::system_prompt(&policy, self.allow_tool.as_deref(), self.system());
        // A granted root is vetted above and pinned here, and the two are adjacent on
        // purpose. Not *nothing* in between — `system_prompt` resolves and stats each
        // granted path again — but a bounded number of path lookups on operator-named
        // paths, with nothing that blocks and no model-chosen input. What may not come
        // between them is anything an attacker can stall, which is why the session is
        // opened above rather than here.
        let ctx = match session.as_ref() {
            Some(open) => ExecutionContext::for_session(policy, open.id().to_string()),
            None => ExecutionContext::new(policy),
        };

        // After the policy, so a refused policy never reads the credential.
        let client = AnthropicClient::new(sandbx_auth::api_key()?)?;

        self.drive(
            |request| client.stream_chat(request),
            &ctx,
            prompt,
            system,
            Channels {
                out: io::stdout(),
                err: io::stderr(),
                renders: io::stderr().is_terminal(),
                terminal,
            },
            session,
        )
        .await
    }

    /// The terminal this run will ask on, or `None` where it asks nobody.
    ///
    /// # Errors
    ///
    /// [`AgentError::NoTerminal`] when `--approve call` was passed and there is no
    /// controlling terminal. Refused rather than served the argv answer, which would be
    /// fail-open against the request; `context/decision-approval-gate.md` has why.
    fn terminal(&self) -> Result<Option<Terminal>, AgentError> {
        match self.approve {
            Approve::Run => Ok(None),
            Approve::Call => {
                let terminal =
                    Terminal::open().map_err(|source| AgentError::NoTerminal { source })?;
                // After the open: claiming the run will ask would be false for one that couldn't.
                if gate::asks_about_anything(self.allow_tool.as_deref()) {
                    eprintln!(
                        "sandbx: each call that writes or runs a program will be asked for \
                         on this terminal"
                    );
                } else {
                    // Inert, not wrong: argv is the ceiling. Said plainly, or silence reads
                    // as consent.
                    eprintln!(
                        "sandbx: nothing in this run will be asked for: `{APPROVE_CALL}` \
                         asks only about the tools `{}` approved, and none was",
                        gate::ALLOW_TOOL
                    );
                }
                Ok(Some(terminal))
            }
        }
    }

    /// Run one turn against `open`, writing the answer to `out` and saving it to
    /// `session`.
    ///
    /// The opener and the channels are arguments so a test can drive a canned turn and
    /// read back the request — the only way to check either without a key.
    async fn drive<W: Write, E: Write>(
        &self,
        mut open: impl AsyncFnMut(Prompt) -> Result<EventStream, ProviderError>,
        ctx: &ExecutionContext,
        prompt: String,
        system: Option<String>,
        channels: Channels<W, E>,
        session: Option<Session>,
    ) -> Result<i32, AgentError> {
        let asked = RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text { text: prompt }],
        };

        // Stored turns first: the new prompt is the conversation's latest, not its own request.
        let mut history = session.as_ref().map_or_else(Vec::new, |session| {
            session::request_history(session.messages())
        });
        history.push(asked.clone());
        // Merged, not appended: a stored turn out of rounds ends on tool results, which
        // the prompt joins rather than follows (#188).
        let merged =
            session::merge_user_runs(history, session.as_ref().map_or(0, Session::withheld));

        let turn = Turn {
            model: self.model.clone(),
            max_output_tokens: self.max_tokens,
            system,
            tools: &BuiltinTool::ALL,
            tool_choice: None, // The model's to make.
            thinking: self.show_thinking.then_some(Thinking::Visible),
            history: &merged.history,
            limits: TurnLimits {
                max_rounds: self.max_rounds,
                ..TurnLimits::default()
            },
            // Last measured by the resumed conversation; `None`/`0` without one.
            observed: session
                .as_ref()
                .and_then(Session::observed)
                .map(session::request_usage),
            withheld: merged.withheld,
        };

        let mut render = Render::with(channels.out, channels.err)
            .showing_thinking(self.show_thinking)
            .rendering(channels.renders);
        let outcome = run_turn(
            &mut open,
            turn.clone(),
            ctx,
            |event| render.event(event),
            gate::ArgvGate::new(self.allow_tool.as_deref(), channels.terminal),
        )
        .await;

        // After the loop, where `render`'s borrow has ended: no event carries the turn's own stop.
        let stop = outcome.as_ref().ok().map(|outcome| outcome.stop);

        // Exhaustive on `TurnStop`, so a fourth way to end cannot reach `finish` as a clean one.
        let (outcome, ending) = match (stop, outcome) {
            (Some(TurnStop::RoundLimit { rounds }), Ok(first)) if !self.no_wrap_up => {
                let (outcome, summarised) =
                    wrapup::run(&mut open, ctx, turn, first, &mut render).await;
                // A round that failed after streaming prose has already put text on
                // stdout that no transcript will account for, which `CutShort` denies.
                let ending = match (summarised, render.wrote_after_gap()) {
                    (true, _) => Unfinished::Summarised(rounds),
                    (false, true) => Unfinished::Discarded(rounds),
                    (false, false) => Unfinished::CutShort(rounds),
                };
                (Ok(outcome), Some(ending))
            }
            (Some(TurnStop::RoundLimit { rounds }), outcome) => {
                (outcome, Some(Unfinished::CutShort(rounds)))
            }
            // Skipped rather than refused by a flag: the wrap-up round is exactly the
            // request there is no longer anyone to have asked for (#218).
            (Some(TurnStop::GateAborted), outcome) => (outcome, Some(Unfinished::Aborted)),
            (Some(TurnStop::Answered) | None, outcome) => (outcome, None),
        };

        // The outcome's figure, not the stream's: on `Discarded` that's the first turn's,
        // the wrap-up round's text not being an answer.
        let truncated = outcome
            .as_ref()
            .is_ok_and(|outcome| matches!(outcome.round_stop, Some(StopReason::MaxTokens)));

        // Closed before the turn's own error is propagated: a turn that died mid-stream
        // has already written part of an answer, and left the line it was on open.
        let code = render.finish(ending, truncated);
        // Before the append: a `TurnError` discards the turn's own messages, and a prompt
        // persisted without its answer makes the next resume send two user turns in a row.
        let outcome = outcome?;

        if let Some(session) = session {
            self.save(session, &asked, outcome, &merged)?;
        }

        // Last: an append still happens for a closed stdout — the transcript is the
        // conversation, not what reached the terminal.
        code
    }

    /// Add the prompt and the finished turn to the transcript.
    ///
    /// `asked` has to be passed back in: `TurnOutcome::messages` is what the turn
    /// produced, so a transcript built from the outcome alone would hold the model's
    /// replies with nothing it replied to.
    pub(super) fn save(
        &self,
        mut session: Session,
        asked: &RequestMessage,
        outcome: TurnOutcome,
        merged: &Merged,
    ) -> Result<(), AgentError> {
        let mut messages = session::stored_messages(slice::from_ref(asked));
        messages.extend(session::stored_messages(&outcome.messages));
        let turn = CompletedTurn {
            messages: &messages,
            observed: outcome.usage.map(session::stored_usage),
            // Back out of the request's index space, which the merge moved.
            withheld: merged.unmerged(outcome.withheld),
        };

        match session.append(turn) {
            Ok(()) => Ok(()),
            // Not an error: the turn's own exit code already says what happened, and a
            // turn that produced nothing at all has nothing to add.
            Err(SessionError::IncompleteTurn) => {
                eprintln!(
                    "sandbx: the turn produced nothing to store; session {} is unchanged",
                    session.id()
                );
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

/// Accept a cap that still allows one request, and refuse anything else.
///
/// A zero never opens a stream, so the turn would report reaching a bound it never tested.
fn round_cap(value: &str) -> Result<usize, String> {
    match value.parse::<usize>().map_err(|error| error.to_string())? {
        0 => Err("a turn needs at least one round".to_owned()),
        rounds => Ok(rounds),
    }
}

/// Accept an id the store could look up, and refuse anything else.
///
/// At parse time rather than on open, so `--session ../../etc/passwd` is refused before
/// any I/O happens at all.
fn session_id(value: &str) -> Result<SessionId, String> {
    value
        .parse()
        .map_err(|error: SessionError| error.to_string())
}

#[cfg(test)]
#[path = "agent_run_tests.rs"]
mod tests;
