//! `agent-run`: one prompt, one streamed answer, tool calls through the boundary.
//!
//! Single-shot: the approval gate is decided from argv before the first request goes out,
//! and `--approve call` narrows that answer per call on the controlling terminal rather
//! than widening it. `--session` carries a conversation between runs as a transcript on
//! disk, not a live session.

mod gate;
mod orientation;
mod prompt;
mod render;
mod wrapup;

use std::io::Write;

use gate::tool_name;
use prompt::{Approve, Terminal};

pub(crate) use prompt::APPROVE_CALL;
use render::{Capped, Render};
use sandbx_agent::{Turn, TurnLimits, TurnOutcome, TurnStop, run_turn};
use sandbx_core::SandboxPolicy;
use sandbx_providers::{
    AnthropicClient, ContentBlock, EventStream, Prompt, ProviderError, RequestMessage, Role,
    StopReason, Thinking,
};
use sandbx_session::{CompletedTurn, Session, SessionError, SessionId};
use sandbx_tools::{BuiltinTool, ExecutionContext};

use crate::session::{self, Merged, SessionChoice};
use crate::{AgentError, Grants, PolicyError};

/// The model asked when `--model` is not given.
///
/// Here because `Turn::model` is a freeform string with no context-window table behind
/// it, so no layer below has an opinion to inherit.
const DEFAULT_MODEL: &str = "claude-sonnet-5";

/// The output ceiling for one turn when `--max-tokens` is not given.
const DEFAULT_MAX_TOKENS: u32 = 4096;

/// The exit code for an answer a bound cut short.
///
/// Neither success nor failure: stdout holds the text that arrived before the bound, and
/// nothing at all when the model opened with a tool call. Stderr names the bound.
const INCOMPLETE: i32 = 2;

/// Where one run writes, and where it asks.
///
/// One argument rather than two because they are the same operator seen twice: stdout
/// carries the model's answer and is piped, so a question has to go somewhere else.
struct Channels<W> {
    /// The answer, streamed as it arrives.
    out: W,

    /// The controlling terminal, `Some` under `--approve call` alone. Every test passes
    /// `None`: opening a real one is what `prompt`'s own suite leaves uncovered.
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

    /// Cap the tokens the model may produce in one turn.
    ///
    /// Bounds the answer, not the prompt. A turn that hits the cap stops mid-sentence
    /// and says so on stderr.
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
    show_thinking: bool,

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
    allow_tool: Option<Vec<BuiltinTool>>,

    /// Ask before each call instead of once from argv.
    ///
    /// `run`, the default, takes the whole answer from `--allow-tool`. `call` asks
    /// you on your terminal before each call that does more than read, within
    /// what `--allow-tool` already approved — it can only narrow that set, never
    /// widen it. Answer `y` for the one call, `n` to refuse it, or `a` to approve
    /// every later call to that tool.
    ///
    /// `call` needs a terminal to ask on, and refuses the run without one rather
    /// than falling back to the argv answer.
    #[arg(long, value_name = "WHEN", default_value = "run")]
    approve: Approve,

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
        if self.grants.names_env(crate::auth::ENV_VAR) {
            return Err(PolicyError::HarnessCredential {
                name: crate::auth::ENV_VAR,
            });
        }

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

        // No `with_helper`: the default path re-execs this binary, and `main` dispatches
        // helper mode before parsing, so the shipped binary is its own helper. Derived
        // before the client, so a refused policy never reads the credential.
        let policy = self.policy()?;
        // Read off the one policy the context is about to take by value: a second
        // `self.policy()?` re-reads `getcwd`, and a cwd that moved in between would name
        // the model a root the sandbox did not grant.
        let system = orientation::system_prompt(&policy, self.allow_tool.as_deref(), self.system());
        let ctx = ExecutionContext::new(policy);

        eprintln!(
            "sandbx: tools approved: {}",
            gate::approved_tools(self.allow_tool.as_deref()).join(", ")
        );

        // Before the credential and the session: a run with no channel to ask on is
        // refused, so neither is opened for a turn that will not happen.
        let terminal = self.terminal()?;

        // Before the session: the credential chain can fail for want of a key, and a
        // session opened first would leave a header-only transcript nothing deletes.
        let client = AnthropicClient::new(crate::auth::api_key()?)?;

        let session = session::open(self.session())?;

        self.drive(
            |request| client.stream_chat(request),
            &ctx,
            prompt,
            system,
            Channels {
                out: std::io::stdout(),
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
                // After the open, not before: a line claiming the run will ask is false
                // for the run that could not.
                if gate::asks_about_anything(self.allow_tool.as_deref()) {
                    eprintln!(
                        "sandbx: each call that writes or runs a program will be asked for \
                         on this terminal"
                    );
                } else {
                    // Argv is the ceiling, so the flag is inert here rather than wrong.
                    // Said plainly, or an operator reads the silence as consent granted.
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
    /// The stream opener and the channels are arguments so a test can drive a canned turn
    /// and read back what the request carried — the only way to check either without a
    /// key.
    async fn drive<W: Write>(
        &self,
        mut open: impl AsyncFnMut(Prompt) -> Result<EventStream, ProviderError>,
        ctx: &ExecutionContext,
        prompt: String,
        system: Option<String>,
        channels: Channels<W>,
        session: Option<Session>,
    ) -> Result<i32, AgentError> {
        let Channels { out, terminal } = channels;
        let asked = RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text { text: prompt }],
        };

        // The stored turns first, so the new prompt is the conversation's latest and not
        // a request of its own.
        let mut history = match &session {
            Some(session) => session::request_history(session.messages()),
            None => Vec::new(),
        };
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
            // The model's to make: this is the turn that may use a tool.
            tool_choice: None,
            thinking: self.show_thinking.then_some(Thinking::Visible),
            history: &merged.history,
            limits: TurnLimits {
                max_rounds: self.max_rounds,
                ..TurnLimits::default()
            },
            // What the resumed conversation last measured, so a continued one and a
            // resumed one carry the same figures. Both are `None`/`0` without a session.
            observed: session
                .as_ref()
                .and_then(Session::observed)
                .map(session::request_usage),
            withheld: merged.withheld,
        };

        // Read off before `run_turn` takes the turn by value.
        let next = wrapup::Next::after(&turn);

        let mut render = Render::new(out).showing_thinking(self.show_thinking);
        let outcome = run_turn(
            &mut open,
            turn,
            ctx,
            |event| render.event(event),
            gate::ArgvGate::new(self.allow_tool.as_deref(), terminal),
        )
        .await;

        // Read after the loop, where `observe`'s borrow on `render` has ended: no event
        // carries the turn's own stop, only a round's.
        let out_of_rounds = match &outcome {
            Ok(TurnOutcome {
                stop: TurnStop::RoundLimit { rounds },
                ..
            }) => Some(*rounds),
            _ => None,
        };

        let (outcome, capped) = match (out_of_rounds, outcome) {
            (Some(rounds), Ok(first)) if !self.no_wrap_up => {
                let (outcome, summarised) = next
                    .run(&mut open, ctx, &merged.history, first, &mut render)
                    .await;
                // A round that failed after streaming prose has already put text on
                // stdout that no transcript will account for, which `CutShort` denies.
                let capped = match (summarised, render.wrote_after_gap()) {
                    (true, _) => Capped::Summarised(rounds),
                    (false, true) => Capped::Discarded(rounds),
                    (false, false) => Capped::CutShort(rounds),
                };
                (Ok(outcome), Some(capped))
            }
            (rounds, outcome) => (outcome, rounds.map(Capped::CutShort)),
        };

        // The outcome's figure, not the stream's: on the `Discarded` path that is the first
        // turn's, the wrap-up round's text not being an answer.
        let truncated = outcome
            .as_ref()
            .is_ok_and(|outcome| matches!(outcome.round_stop, Some(StopReason::MaxTokens)));

        // Closed before the turn's own error is propagated: a turn that died mid-stream
        // has already written part of an answer, and left the line it was on open.
        let code = render.finish(capped, truncated);
        // Before the append: a `TurnError` discards the turn's own messages, and a prompt
        // persisted without its answer makes the next resume send two user turns in a row.
        let outcome = outcome?;

        if let Some(session) = session {
            self.save(session, &asked, outcome, &merged)?;
        }

        // Last, so an append still happens for a turn whose stdout was a closed pipe:
        // the transcript is the conversation, not what reached the terminal.
        code
    }

    /// Add the prompt and the finished turn to the transcript.
    ///
    /// `asked` has to be passed back in: `TurnOutcome::messages` is what the turn
    /// produced, so a transcript built from the outcome alone would hold the model's
    /// replies with nothing it replied to.
    fn save(
        &self,
        mut session: Session,
        asked: &RequestMessage,
        outcome: TurnOutcome,
        merged: &Merged,
    ) -> Result<(), AgentError> {
        let mut messages = session::stored_messages(std::slice::from_ref(asked));
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
    match value.parse() {
        Ok(0) => Err("a turn needs at least one round".to_owned()),
        Ok(rounds) => Ok(rounds),
        Err(error) => Err(error.to_string()),
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
mod tests {
    use sandbx_providers::{AgentEvent, StopReason, ToolChoice};

    use super::render::tests::{stop, text};
    use super::*;

    use clap::Parser;

    /// `path`, pinned to the object it names — the shape every grant takes (#212).
    fn vetted(path: impl AsRef<std::path::Path>) -> sandbx_core::VettedPath {
        sandbx_core::VettedPath::vet(path).expect("an existing path to pin the grant to")
    }

    fn agent_run(argv: &[&str]) -> AgentRun {
        match crate::Cli::parse_from(argv).command {
            crate::Command::AgentRun(args) => args,
            other => panic!("{other:?} is not agent-run"),
        }
    }

    /// A misplaced `--` turns `--allow-tool write -- "…"` into the bare flag plus a
    /// prompt. What that does to the approved set is `gate`'s to pin; this is the prompt.
    #[test]
    fn a_misplaced_separator_leaves_the_flag_a_prompt() {
        let args = agent_run(&["sandbx", "agent-run", "--allow-tool", "--", "write", "it"]);

        assert_eq!(args.prompt(), "write it");
    }

    /// The default is what every existing run keeps, and the opt-in has to parse.
    #[test]
    fn approval_is_once_per_run_unless_asked_for_per_call() {
        assert_eq!(
            agent_run(&["sandbx", "agent-run", "--", "go"]).approve,
            Approve::Run
        );
        assert_eq!(
            agent_run(&["sandbx", "agent-run", "--approve", "call", "--", "go"]).approve,
            Approve::Call
        );
    }

    /// A run with no channel to ask on exits before the first request. Asserting only
    /// that it exits nonzero would pass for a provider failure too, so the assertion is
    /// that the refusal names the flag to drop.
    #[test]
    fn a_run_with_no_terminal_to_ask_on_names_the_flag() {
        // ENXIO on Linux, which is what opening `/dev/tty` returns with no controlling
        // terminal.
        let error = AgentError::NoTerminal {
            source: std::io::Error::from_raw_os_error(6),
        };

        let message = error.to_string();
        assert!(message.contains(APPROVE_CALL), "got {message}");
        assert!(message.contains("--allow-tool"), "got {message}");
    }

    #[test]
    fn a_round_cap_of_zero_is_refused() {
        let message = round_cap("0").expect_err("a turn that asks nothing was accepted");

        assert!(message.contains("at least one"), "got {message}");
        assert_eq!(round_cap("1"), Ok(1));
    }

    fn asked(text: &str) -> RequestMessage {
        RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: text.to_string(),
            }],
        }
    }

    fn answered(text: &str) -> RequestMessage {
        RequestMessage {
            role: Role::Assistant,
            content: vec![ContentBlock::Text {
                text: text.to_string(),
            }],
        }
    }

    /// An `EventStream` that replays `events` and then ends.
    ///
    /// `fuse()` because `EventStream` promises a `FusedStream`: a caller may poll it
    /// past its end without panicking.
    fn canned(events: Vec<AgentEvent>) -> EventStream {
        use futures_util::StreamExt;
        Box::pin(futures_util::stream::iter(events.into_iter().map(Ok)).fuse())
    }

    /// A current-thread runtime rather than `#[tokio::test]`: `rt` is already on for the
    /// binary, and `macros` is not. Timers are not optional — `run_turn` arms a
    /// per-round timeout and panics without one.
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a current-thread runtime")
    }

    /// What a scripted run reports: every request it sent, its stdout, and its exit code.
    type Driven = (Vec<Prompt>, String, Result<i32, AgentError>);

    /// Drive one scripted round through `drive`, and report what was sent and written.
    ///
    /// A default policy grants nothing, so the request carries the approved tools and
    /// whatever `--system` held, with no roots line.
    fn one_round(
        args: &AgentRun,
        prompt: &str,
        events: Vec<AgentEvent>,
        session: Option<Session>,
    ) -> Driven {
        under(
            SandboxPolicy::default(),
            args,
            prompt,
            vec![events],
            session,
        )
    }

    /// `one_round` over a script of several rounds, under a policy of its caller's
    /// choosing, composing the system prompt the way `execute` does.
    ///
    /// A script, not one round: a turn out of rounds is asked again with no tool call
    /// allowed, so the round-limited cases here open two streams.
    fn under(
        policy: SandboxPolicy,
        args: &AgentRun,
        prompt: &str,
        rounds: Vec<Vec<AgentEvent>>,
        session: Option<Session>,
    ) -> Driven {
        let system = orientation::system_prompt(&policy, args.allow_tool.as_deref(), args.system());
        let ctx = ExecutionContext::new(policy);
        let mut sent = Vec::new();
        let mut rounds = rounds.into_iter();
        let mut out = Vec::new();

        let code = runtime().block_on(args.drive(
            |request| {
                sent.push(request);
                let round = rounds.next().expect("one more round was asked for");
                std::future::ready(Ok(canned(round)))
            },
            &ctx,
            prompt.to_owned(),
            system,
            Channels {
                out: &mut out,
                terminal: None,
            },
            session,
        ));

        (sent, String::from_utf8(out).expect("utf-8"), code)
    }

    /// Drive a turn whose request never reaches a provider at all.
    fn failed_round(args: &AgentRun, session: Option<Session>) -> Result<i32, AgentError> {
        let ctx = ExecutionContext::new(SandboxPolicy::default());

        runtime().block_on(args.drive(
            |_| {
                std::future::ready(Err(ProviderError::ApiError {
                    transient: true,
                    status: Some(500),
                    kind: "api_error".to_owned(),
                    message: "overloaded".to_owned(),
                    retry_after: None,
                }))
            },
            &ctx,
            "hi".to_owned(),
            None,
            Channels {
                out: Vec::new(),
                terminal: None,
            },
            session,
        ))
    }

    /// A store under a temporary directory, and one new session in it.
    fn new_session() -> (tempfile::TempDir, sandbx_session::SessionStore, Session) {
        let root = tempfile::tempdir().expect("a temp dir");
        let store = sandbx_session::SessionStore::new(root.path().join("sessions"));
        let session = store.create().expect("a new session");
        (root, store, session)
    }

    #[test]
    fn the_prompt_is_the_whole_request_history() {
        let args = agent_run(&["sandbx", "agent-run", "--", "what", "is", "in", "/srv?"]);

        let (sent, written, code) = one_round(
            &args,
            &args.prompt(),
            vec![text("etc"), stop(StopReason::EndTurn)],
            None,
        );

        assert_eq!(written, "etc\n");
        assert_eq!(code.expect("clean turn"), 0);
        assert_eq!(sent[0].messages, vec![asked("what is in /srv?")]);
    }

    /// Both halves: the default has to be absent and not `Visible`, asking for a summary
    /// being a 400 on every model before Claude 4.6.
    #[test]
    fn show_thinking_asks_for_it_and_nothing_else_does() {
        let round = || vec![text("etc"), stop(StopReason::EndTurn)];

        let quiet = agent_run(&["sandbx", "agent-run", "--", "hi"]);
        let (sent, _, code) = one_round(&quiet, "hi", round(), None);
        code.expect("clean turn");
        assert_eq!(sent[0].thinking, None);

        let loud = agent_run(&["sandbx", "agent-run", "--show-thinking", "--", "hi"]);
        let (sent, _, code) = one_round(&loud, "hi", round(), None);
        code.expect("clean turn");
        assert_eq!(sent[0].thinking, Some(Thinking::Visible));
    }

    /// The last edge before the file, the replay itself being `run_turn`'s. Asserted on
    /// the bytes, not the parse: a variant added later would store it somewhere this does
    /// not know to look.
    #[test]
    fn a_stored_turn_carries_no_reasoning() {
        let args = agent_run(&["sandbx", "agent-run", "--show-thinking", "--", "hi"]);
        let (_root, store, session) = new_session();

        let (_, _, code) = one_round(
            &args,
            "hi",
            vec![
                AgentEvent::Thinking {
                    delta: "weighing it up".to_string(),
                },
                AgentEvent::ThinkingBlock {
                    text: "weighing it up".to_string(),
                    signature: "sig-1".to_string(),
                },
                AgentEvent::RedactedThinking {
                    data: "EvgBCkgIBR".to_string(),
                },
                text("etc"),
                stop(StopReason::EndTurn),
            ],
            Some(session),
        );
        code.expect("clean turn");

        let path = store.root().join(format!("{}.jsonl", only_session(&store)));
        let on_disk = std::fs::read_to_string(&path).expect("the transcript exists");

        for token in ["sig-1", "EvgBCkgIBR", "thinking", "weighing it up"] {
            assert!(
                !on_disk.contains(token),
                "{token} reached the transcript: {on_disk}"
            );
        }
        assert!(
            on_disk.contains("etc"),
            "the answer was lost too: {on_disk}"
        );
    }

    #[test]
    fn a_resumed_history_precedes_the_new_prompt() {
        let args = agent_run(&["sandbx", "agent-run", "--", "and the second?"]);
        let (_root, store, session) = new_session();
        let id = {
            let (_, _, code) = one_round(
                &args,
                "the first question",
                vec![text("the first answer"), stop(StopReason::EndTurn)],
                Some(session),
            );
            code.expect("clean turn");
            // Read back from the store rather than kept from before the turn: what a
            // resume gets is what reached disk.
            only_session(&store)
        };

        let (sent, _, code) = one_round(
            &args,
            &args.prompt(),
            vec![text("the second answer"), stop(StopReason::EndTurn)],
            Some(store.resume(&id).expect("the session resumes")),
        );
        code.expect("clean turn");

        assert_eq!(
            sent[0].messages,
            vec![
                asked("the first question"),
                answered("the first answer"),
                asked("and the second?"),
            ]
        );
    }

    /// The model is told the roots before the first request, not after a refusal (#178).
    #[test]
    fn the_request_carries_the_granted_root_as_system() {
        let args = agent_run(&["sandbx", "agent-run", "--system", "be terse", "--", "go"]);
        // A root that exists, and its canonical name: a grant the guard cannot resolve is
        // named by neither it nor the prompt.
        let work = tempfile::tempdir().expect("a temp dir");
        let named = work.path().canonicalize().expect("it exists");

        let (sent, _, code) = under(
            SandboxPolicy::default()
                .allow_read(vetted(work.path()))
                .allow_write(vetted(work.path())),
            &args,
            &args.prompt(),
            vec![vec![text("ok"), stop(StopReason::EndTurn)]],
            None,
        );
        code.expect("clean turn");

        let system = sent[0].system.as_deref().expect("a system prompt");
        assert!(
            system.contains(&format!("{} (read, write)", named.display())),
            "got {system:?}"
        );
        assert!(system.ends_with("be terse"), "got {system:?}");
    }

    /// The approved set reaches the model with the request, not one refused call at a
    /// time (#197).
    #[test]
    fn the_request_names_the_tools_the_run_approved() {
        let args = agent_run(&["sandbx", "agent-run", "--allow-tool", "edit", "--", "go"]);

        let (sent, _, code) = one_round(
            &args,
            &args.prompt(),
            vec![text("ok"), stop(StopReason::EndTurn)],
            None,
        );
        code.expect("clean turn");

        let system = sent[0].system.as_deref().expect("a system prompt");
        assert!(
            system.contains("read, edit, ls, grep, find"),
            "got {system:?}"
        );
        assert!(!system.contains("bash"), "got {system:?}");
    }

    #[test]
    fn a_failed_turn_leaves_the_transcript_alone() {
        let args = agent_run(&["sandbx", "agent-run", "--", "hi"]);
        let (_root, store, session) = new_session();
        let before = std::fs::read(session.path()).expect("the transcript exists");

        let error = failed_round(&args, Some(session)).expect_err("a turn that never opened");

        assert!(matches!(error, AgentError::Turn(_)), "got {error:?}");
        let after = std::fs::read(store.root().join(format!("{}.jsonl", only_session(&store))))
            .expect("the transcript exists");
        // A prompt saved without its answer would make the next resume send two user
        // turns in a row, which the API rejects.
        assert_eq!(after, before);
    }

    /// Fires if anyone ever persists the request headers. Proves nothing about a key the
    /// model itself typed into an answer — `guide-logging.md`'s register.
    #[test]
    fn a_transcript_holds_no_api_key_material() {
        let args = agent_run(&["sandbx", "agent-run", "--", "hi"]);
        let (_root, store, session) = new_session();
        let path = session.path().to_owned();

        let (_, _, code) = one_round(
            &args,
            "remember sentinel-9f3a",
            vec![text("noted, sentinel-9f3a"), stop(StopReason::EndTurn)],
            Some(session),
        );
        code.expect("clean turn");

        let body = std::fs::read_to_string(&path).expect("the transcript exists");
        // Both halves present first, so the assertions below are known to be reading the
        // file that holds the conversation.
        assert_eq!(body.matches("sentinel-9f3a").count(), 2, "got {body}");
        for secret in ["x-api-key", "authorization", "sk-ant-"] {
            assert!(!body.contains(secret), "{secret} reached {path:?}");
        }
        assert_eq!(
            store
                .resume(&only_session(&store))
                .unwrap()
                .messages()
                .len(),
            2
        );
    }

    #[test]
    fn a_turn_with_no_reply_keeps_the_turns_own_exit_code() {
        let args = agent_run(&["sandbx", "agent-run", "--", "hi"]);
        let (_root, store, session) = new_session();

        let (_, _, code) = one_round(
            &args,
            &args.prompt(),
            vec![stop(StopReason::MaxTokens)],
            Some(session),
        );

        // `IncompleteTurn` is a stderr line, not an error: the cut-short code is what a
        // script consuming stdout has to see.
        assert_eq!(code.expect("a reported turn"), INCOMPLETE);
        assert!(
            store
                .resume(&only_session(&store))
                .unwrap()
                .messages()
                .is_empty()
        );
    }

    /// The answered turn `a_turn_with_no_reply` cannot cover. Which mechanism supplies the
    /// figure is `render.rs`'s `the_exit_code_comes_from_the_outcome_not_a_stop`, not here:
    /// a latch over the event stream computes the same answer.
    #[test]
    fn a_truncated_answer_exits_incomplete() {
        let args = agent_run(&["sandbx", "agent-run", "--", "hi"]);

        let (_, out, code) = one_round(
            &args,
            &args.prompt(),
            vec![text("half a sen"), stop(StopReason::MaxTokens)],
            None,
        );

        assert_eq!(out, "half a sen\n");
        assert_eq!(code.expect("a reported turn"), INCOMPLETE);
    }

    /// The policy grants nothing, so the call comes back `is_error` — still a
    /// `tool_result`, which is what makes the turn re-enter and meet the cap.
    fn asking_for_ls() -> Vec<AgentEvent> {
        vec![
            text("looking"),
            AgentEvent::ToolCallRequested {
                id: "call_1".to_owned(),
                name: "ls".to_owned(),
                input: serde_json::json!({ "path": "/nowhere" }),
            },
            stop(StopReason::ToolUse),
        ]
    }

    /// A round-limited run, scripted as the two requests it now sends.
    fn capped(args: &AgentRun, wrap_up: Vec<AgentEvent>, session: Option<Session>) -> Driven {
        under(
            SandboxPolicy::default(),
            args,
            &args.prompt(),
            vec![asking_for_ls(), wrap_up],
            session,
        )
    }

    /// The wrap-up round answering, which is the whole point of spending it (#189).
    fn summarising() -> Vec<AgentEvent> {
        vec![text("I found nothing"), stop(StopReason::EndTurn)]
    }

    /// The wrap-up round streaming prose and then spending its one round asking for a
    /// tool anyway, which its gate denies whatever `--allow-tool` approved.
    fn stranding_text() -> Vec<AgentEvent> {
        vec![
            text("here is what I found"),
            AgentEvent::ToolCallRequested {
                id: "call_2".to_owned(),
                name: "ls".to_owned(),
                input: serde_json::json!({ "path": "/nowhere" }),
            },
            stop(StopReason::ToolUse),
        ]
    }

    /// Streamed text cannot be taken back, so the run has to own it on stderr rather
    /// than claim stdout holds only what arrived before the cap.
    #[test]
    fn a_discarded_wrap_up_round_owns_what_it_wrote() {
        let args = agent_run(&["sandbx", "agent-run", "--max-rounds", "1", "--", "go"]);
        let (_root, store, session) = new_session();
        let path = session.path().to_owned();

        let (sent, written, code) = capped(&args, stranding_text(), Some(session));

        assert_eq!(sent.len(), 2, "the cap should have bought a wrap-up round");
        assert_eq!(written, "looking\n\nhere is what I found\n");
        assert_eq!(code.expect("a reported turn"), INCOMPLETE);

        // The first turn is stored; the round that wrote and then asked for a tool is
        // the one discarded, so its prose reached stdout and nowhere else.
        let body = std::fs::read_to_string(&path).expect("the transcript exists");
        assert!(body.contains("looking"), "got {body}");
        assert!(!body.contains("here is what I found"), "got {body}");
        assert!(
            store
                .resume(&only_session(&store))
                .expect("a resumable turn")
                .pending_call()
        );
    }

    /// A provider failure exits 1 with an empty stdout; this must not read as one (#178).
    #[test]
    fn a_turn_out_of_rounds_exits_two_with_an_answer() {
        let args = agent_run(&["sandbx", "agent-run", "--max-rounds", "1", "--", "go"]);

        let (sent, written, code) = capped(&args, summarising(), None);

        assert_eq!(sent.len(), 2, "the cap should have bought a wrap-up round");
        // The cap cut the tool work off whatever prose followed, so the code is unchanged.
        assert_eq!(code.expect("a reported turn"), INCOMPLETE);
        assert_eq!(written, "looking\n\nI found nothing\n");
    }

    /// The round the cap buys must be one the model cannot spend on a tool, and the
    /// definitions stay in the body regardless — dropping either half is a 400 or a call.
    #[test]
    fn the_wrap_up_round_forbids_tools_and_adds_no_turn() {
        let args = agent_run(&["sandbx", "agent-run", "--max-rounds", "1", "--", "go"]);

        let (sent, _, _) = capped(&args, summarising(), None);

        assert!(sent[0].tool_choice.is_none(), "the first round was bound");
        assert!(!sent[1].tools.is_empty(), "got {:?}", sent[1].tools);
        assert_eq!(sent[1].tools, sent[0].tools, "the set changed");
        assert_eq!(sent[1].tool_choice, Some(ToolChoice::None));

        let last = sent[1].messages.last().expect("a last message");
        assert_eq!(last.role, Role::User);
        for block in &last.content {
            assert!(
                matches!(block, ContentBlock::ToolResult { .. }),
                "got {last:?}"
            );
        }
    }

    /// Nothing may append it to the history, so the only place left to say it is the
    /// system prompt — which is also the one place a resume will not replay.
    #[test]
    fn the_wrap_up_round_says_the_tools_are_gone() {
        let args = agent_run(&["sandbx", "agent-run", "--max-rounds", "1", "--", "go"]);

        let (sent, _, _) = capped(&args, summarising(), None);

        // Not `is_none`: #197 gives the first round a prompt naming its approved tools,
        // so the property is that the nudge is absent there, not that nothing is.
        let first = sent[0].system.as_deref().unwrap_or_default();
        assert!(
            !first.contains("no tool calls left"),
            "the first round already said it: {first:?}"
        );
        let system = sent[1].system.as_deref().expect("a system prompt");
        assert!(system.contains("no tool calls left"), "got {system:?}");
    }

    /// The flag refuses the second request, not the transcript (#188).
    #[test]
    fn no_wrap_up_still_stores_what_the_cap_reached() {
        let args = agent_run(&[
            "sandbx",
            "agent-run",
            "--max-rounds",
            "1",
            "--no-wrap-up",
            "--",
            "go",
        ]);
        let (_root, store, session) = new_session();

        let (sent, written, code) = under(
            SandboxPolicy::default(),
            &args,
            &args.prompt(),
            vec![asking_for_ls()],
            Some(session),
        );

        assert_eq!(sent.len(), 1, "no request should have followed the cap");
        assert_eq!(written, "looking\n");
        assert_eq!(code.expect("a reported turn"), INCOMPLETE);

        let stored = store
            .resume(&only_session(&store))
            .expect("a resumable turn");
        // The prompt, the round that asked for a tool, and its result.
        assert_eq!(stored.messages().len(), 3);
        assert!(stored.pending_call());
    }

    /// The round trip is the assertion: a batch `append` takes but `resume` refuses would
    /// brick the session from a run that exited 2 (#188).
    #[test]
    fn a_turn_out_of_rounds_is_stored_and_resumable() {
        let args = agent_run(&["sandbx", "agent-run", "--max-rounds", "1", "--", "go"]);
        let (_root, store, session) = new_session();

        let (_, _, code) = capped(&args, summarising(), Some(session));
        assert_eq!(code.expect("a reported turn"), INCOMPLETE);

        let stored = store
            .resume(&only_session(&store))
            .expect("a resumable turn");
        // The prompt, the round that asked for a tool, its result, and the summary.
        assert_eq!(stored.messages().len(), 4);
        let last = stored.messages().last().expect("a last message");
        assert_eq!(last.role, sandbx_session::Role::Assistant);
    }

    /// A `?` here would report a provider failure and cost the turn its text.
    #[test]
    fn a_failed_wrap_up_round_costs_the_turn_nothing() {
        let args = agent_run(&["sandbx", "agent-run", "--max-rounds", "1", "--", "go"]);
        let (_root, store, session) = new_session();

        // A round with no events at all ends without a `Stop`, which is the wrap-up
        // round failing without a provider that can be made to fail.
        let (sent, written, code) = capped(&args, Vec::new(), Some(session));

        assert_eq!(sent.len(), 2, "the wrap-up round should have been tried");
        assert_eq!(written, "looking\n");
        assert_eq!(code.expect("a reported turn"), INCOMPLETE);

        let stored = store
            .resume(&only_session(&store))
            .expect("a resumable turn");
        assert_eq!(stored.messages().len(), 3);
        assert!(stored.pending_call());
    }

    /// The prompt joins the stored results rather than following them (#188).
    #[test]
    fn a_prompt_resuming_an_unanswered_call_joins_it() {
        let args = agent_run(&["sandbx", "agent-run", "--", "what did you find?"]);
        let (_root, store, session) = new_session();
        let capping = agent_run(&[
            "sandbx",
            "agent-run",
            "--max-rounds",
            "1",
            "--no-wrap-up",
            "--",
            "go",
        ]);
        under(
            SandboxPolicy::default(),
            &capping,
            &capping.prompt(),
            vec![asking_for_ls()],
            Some(session),
        )
        .2
        .expect("a reported turn");

        let (sent, _, code) = one_round(
            &args,
            &args.prompt(),
            vec![text("nothing"), stop(StopReason::EndTurn)],
            Some(store.resume(&only_session(&store)).expect("it resumes")),
        );
        code.expect("clean turn");

        let messages = &sent[0].messages;
        // Three stored turns and a prompt, three sent: the result and the prompt travel
        // as one message.
        assert_eq!(messages.len(), 3, "got {messages:?}");
        assert!(
            messages.windows(2).all(|pair| pair[0].role != pair[1].role),
            "got {messages:?}"
        );
        // Results first, which is where the API wants them.
        assert!(
            matches!(
                &messages[2].content[..],
                [ContentBlock::ToolResult { .. }, ContentBlock::Text { .. }]
            ),
            "got {:?}",
            messages[2]
        );
    }

    /// The id of the one session in `store`.
    fn only_session(store: &sandbx_session::SessionStore) -> sandbx_session::SessionId {
        let mut ids: Vec<String> = std::fs::read_dir(store.root())
            .expect("the store exists")
            .map(|entry| {
                entry
                    .expect("a readable entry")
                    .file_name()
                    .to_string_lossy()
                    .trim_end_matches(".jsonl")
                    .to_owned()
            })
            .collect();
        ids.sort();
        assert_eq!(ids.len(), 1, "expected one transcript, got {ids:?}");
        ids[0].parse().expect("a stored name is a valid id")
    }

    #[test]
    fn a_traversing_session_id_is_refused_at_parse_time() {
        let message = session_id("../../etc/passwd").expect_err("a traversal was accepted");

        assert!(message.contains("passwd"), "got {message}");
    }
}
