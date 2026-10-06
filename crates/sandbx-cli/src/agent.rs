//! `agent-run`: one prompt, one streamed answer, tool calls through the boundary.
//!
//! Single-shot and non-interactive, so there is nobody to ask mid-turn: the approval gate
//! is decided from argv before the first request goes out. `--session` carries a
//! conversation between runs as a transcript on disk, not a live session.

mod render;

use std::io::Write;

use render::Render;
use sandbx_agent::{ApprovalDecision, ToolCall, Turn, TurnLimits, TurnOutcome, run_turn};
use sandbx_core::SandboxPolicy;
use sandbx_providers::{
    AnthropicClient, ContentBlock, EventStream, MessagesRequest, ProviderError, RequestMessage,
    Role,
};
use sandbx_session::{CompletedTurn, Session, SessionError, SessionId};
use sandbx_tools::{BuiltinTool, ExecutionContext, RiskLevel};

use crate::session::{self, SessionChoice};
use crate::{AgentError, Grants, PolicyError};

/// The model asked when `--model` is not given.
///
/// Here because `Turn::model` is a freeform string with no context-window table behind
/// it, so no layer below has an opinion to inherit.
const DEFAULT_MODEL: &str = "claude-sonnet-5";

/// The output ceiling for one turn when `--max-tokens` is not given.
const DEFAULT_MAX_TOKENS: u32 = 4096;

/// The exit code for an answer `--max-tokens` cut short.
///
/// Neither success nor failure: what reached stdout is a real answer and an incomplete
/// one, which a script consuming it has to tell apart.
const TRUNCATED: i32 = 2;

/// The flag that lifts the default refusal.
///
/// Named once because a refusal is read twice — on stderr and in the `tool_result` — and
/// the two accounts must not advise differently.
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

    /// What `--session` asked for.
    pub fn session(&self) -> SessionChoice<'_> {
        match &self.session {
            None => SessionChoice::Off,
            Some(None) => SessionChoice::New,
            Some(Some(id)) => SessionChoice::Resume(id),
        }
    }

    /// Whether the model may call `tool` in this run.
    ///
    /// Fail-closed, there being no operator to ask: a tool that does more than read runs
    /// only when a flag named it, or when the bare flag approved every tool.
    fn approves(&self, tool: BuiltinTool) -> bool {
        if tool.risk() == RiskLevel::ReadOnly {
            return true;
        }

        match self.allow_tool.as_deref() {
            None => false,
            // An empty `Vec` is the bare flag, so `--allow-tool --allow-tool write`
            // approves `write` alone: the broader spelling yields the narrower set.
            Some([]) => true,
            Some(named) => named.contains(&tool),
        }
    }

    /// The tools this run approved, in `BuiltinTool::ALL` order.
    ///
    /// Reported before the first request, the fail-open spelling being a typo away: clap
    /// reads `--allow-tool -- write the file` as the bare flag plus a prompt, which the
    /// per-call lines would not show until a `bash` ran.
    fn approved_tools(&self) -> Vec<&'static str> {
        BuiltinTool::ALL
            .iter()
            .filter(|tool| self.approves(**tool))
            .map(|tool| tool.name())
            .collect()
    }

    /// The decision for one call, and the operator's line about it.
    ///
    /// Printed here and not from `observe`, which fires while the round is still streaming
    /// and so would announce a call this then refuses.
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
        let ctx = ExecutionContext::new(self.policy()?);

        eprintln!(
            "sandbx: tools approved: {}",
            self.approved_tools().join(", ")
        );

        // Before the session: the credential chain can fail for want of a key, and a
        // session opened first would leave a header-only transcript nothing deletes.
        let client = AnthropicClient::new(crate::auth::api_key()?)?;

        let session = session::open(self.session())?;

        self.drive(
            |request| client.stream_chat(request),
            &ctx,
            prompt,
            std::io::stdout(),
            session,
        )
        .await
    }

    /// Run one turn against `open`, writing the answer to `out` and saving it to
    /// `session`.
    ///
    /// The stream opener and the sink are arguments so a test can drive a canned turn and
    /// read back what the request carried — the only way to check either without a key.
    async fn drive<W: Write>(
        &self,
        open: impl AsyncFnMut(MessagesRequest) -> Result<EventStream, ProviderError>,
        ctx: &ExecutionContext,
        prompt: String,
        out: W,
        session: Option<Session>,
    ) -> Result<i32, AgentError> {
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

        let turn = Turn {
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            system: self.system.clone(),
            tools: &BuiltinTool::ALL,
            history: &history,
            limits: TurnLimits::default(),
            // What the resumed conversation last measured, so a continued one and a
            // resumed one carry the same figures. Both are `None`/`0` without a session.
            observed: session
                .as_ref()
                .and_then(Session::observed)
                .map(session::request_usage),
            withheld: session.as_ref().map_or(0, Session::withheld),
        };

        let mut render = Render::new(out);
        let outcome = run_turn(
            open,
            turn,
            ctx,
            |event| render.event(event),
            |requested| self.gate(requested),
        )
        .await;

        // Closed before the turn's own error is propagated: a turn that died mid-stream
        // has already written part of an answer, and left the line it was on open.
        let code = render.finish();
        // Before the append: a `TurnError` discards the turn's own messages, and a prompt
        // persisted without its answer makes the next resume send two user turns in a row.
        let outcome = outcome?;

        if let Some(session) = session {
            self.save(session, &asked, outcome)?;
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
    ) -> Result<(), AgentError> {
        let mut messages = session::stored_messages(std::slice::from_ref(asked));
        messages.extend(session::stored_messages(&outcome.messages));
        let turn = CompletedTurn {
            messages: &messages,
            observed: outcome.usage.map(session::stored_usage),
            withheld: outcome.withheld,
        };

        match session.append(turn) {
            Ok(()) => Ok(()),
            // Not an error: the turn's own exit code already says what happened, and a
            // turn with no reply to store has nothing to add.
            Err(SessionError::IncompleteTurn) => {
                eprintln!(
                    "sandbx: the turn produced no reply; session {} is unchanged",
                    session.id()
                );
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

/// Accept a tool `--allow-tool` can actually approve, and refuse anything else.
///
/// `BuiltinTool::from_name` is exact-match, so taking a near miss would approve nothing
/// and exit 0, leaving whoever typed `--allow-tool shell` believing `bash` was approved.
fn tool_name(value: &str) -> Result<BuiltinTool, String> {
    BuiltinTool::from_name(value).ok_or_else(|| {
        // Only the tools the flag can change: listing all seven would invite
        // `--allow-tool read`, which parses and widens nothing.
        let names: Vec<&str> = BuiltinTool::ALL
            .iter()
            .filter(|tool| tool.risk() != RiskLevel::ReadOnly)
            .map(|tool| tool.name())
            .collect();
        format!(
            "no tool is called `{value}`; the tools needing approval are {}",
            names.join(", ")
        )
    })
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
    use sandbx_providers::{AgentEvent, StopReason};

    use super::render::tests::{stop, text};
    use super::*;

    use clap::Parser;

    fn agent_run(argv: &[&str]) -> AgentRun {
        match crate::Cli::parse_from(argv).command {
            crate::Command::AgentRun(args) => args,
            other => panic!("{other:?} is not agent-run"),
        }
    }

    /// Spelled out rather than compared against `risk()`, the table `approves` itself
    /// reads: derived, a `bash` reclassified as read-only would pass while running.
    #[test]
    fn the_read_only_tools_need_no_flag() {
        let args = agent_run(&["sandbx", "agent-run", "--", "hello"]);

        assert!(args.approves(BuiltinTool::Read));
        assert!(args.approves(BuiltinTool::Ls));
        assert!(args.approves(BuiltinTool::Grep));
        assert!(args.approves(BuiltinTool::Find));
        assert!(!args.approves(BuiltinTool::Write));
        assert!(!args.approves(BuiltinTool::Edit));
        assert!(!args.approves(BuiltinTool::Bash));
    }

    #[test]
    fn a_named_tool_is_the_only_one_lifted() {
        let args = agent_run(&["sandbx", "agent-run", "--allow-tool", "write", "--", "go"]);

        assert!(args.approves(BuiltinTool::Write));
        assert!(!args.approves(BuiltinTool::Edit));
        assert!(!args.approves(BuiltinTool::Bash));
        assert!(args.approves(BuiltinTool::Read), "a read was withdrawn");
    }

    #[test]
    fn a_bare_allow_tool_approves_every_tool() {
        let args = agent_run(&["sandbx", "agent-run", "--allow-tool", "--", "go"]);

        for tool in BuiltinTool::ALL {
            assert!(
                args.approves(tool),
                "{tool:?} is refused under the bare flag"
            );
        }
    }

    /// The broader spelling yields the narrower set, as `--allow-network` does.
    #[test]
    fn mixing_a_bare_flag_with_a_tool_narrows_to_the_tool() {
        let args = agent_run(&[
            "sandbx",
            "agent-run",
            "--allow-tool",
            "--allow-tool",
            "write",
            "--",
            "go",
        ]);

        assert!(args.approves(BuiltinTool::Write));
        assert!(!args.approves(BuiltinTool::Bash));
    }

    /// A misplaced `--` turns `--allow-tool write -- "…"` into the bare flag plus a
    /// prompt, approving all seven — which the announced set shows before a `bash` runs.
    #[test]
    fn a_bare_flag_from_a_misplaced_separator_announces_all_seven() {
        let args = agent_run(&["sandbx", "agent-run", "--allow-tool", "--", "write", "it"]);

        assert_eq!(args.prompt(), "write it");
        assert_eq!(
            args.approved_tools(),
            ["read", "write", "bash", "edit", "ls", "grep", "find"],
            "the bare flag approved something other than every tool"
        );
    }

    /// The line a default run prints: the four that need no flag, and nothing else.
    #[test]
    fn the_announced_set_is_the_read_only_four_by_default() {
        let args = agent_run(&["sandbx", "agent-run", "--", "go"]);

        assert_eq!(args.approved_tools(), ["read", "ls", "grep", "find"]);
    }

    /// The `tool_result` is the only account the model gets, so saying no is not enough.
    #[test]
    fn a_refusal_tells_the_model_which_flag_would_lift_it() {
        let args = agent_run(&["sandbx", "agent-run", "--", "go"]);
        let input = serde_json::Value::Null;

        let ApprovalDecision::Deny { reason } = args.gate(ToolCall {
            tool: BuiltinTool::Bash,
            id: "call_1",
            input: &input,
        }) else {
            panic!("bash was approved with no flag");
        };

        assert!(reason.contains("`--allow-tool bash`"), "got {reason}");
    }

    #[test]
    fn an_approved_tool_is_allowed_not_merely_announced() {
        let args = agent_run(&["sandbx", "agent-run", "--allow-tool", "bash", "--", "go"]);
        let input = serde_json::Value::Null;

        let decision = args.gate(ToolCall {
            tool: BuiltinTool::Bash,
            id: "call_1",
            input: &input,
        });

        assert_eq!(decision, ApprovalDecision::Allow);
    }

    /// `--allow-tool` can only widen, so offering a read-only name back would invite a
    /// spelling that parses and changes nothing.
    #[test]
    fn the_unknown_name_advice_lists_only_what_needs_approving() {
        let message = tool_name("shell").expect_err("a name no tool answers to was accepted");

        assert!(message.contains("write"), "got {message}");
        assert!(message.contains("bash"), "got {message}");
        assert!(
            !message.contains("grep"),
            "a read-only tool was offered as approvable: {message}"
        );
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

    /// Drive one scripted round through `drive`, and report what was sent and written.
    fn one_round(
        args: &AgentRun,
        prompt: &str,
        events: Vec<AgentEvent>,
        session: Option<Session>,
    ) -> (Vec<MessagesRequest>, String, Result<i32, AgentError>) {
        let ctx = ExecutionContext::new(SandboxPolicy::default());
        let mut sent = Vec::new();
        let mut events = Some(events);
        let mut out = Vec::new();

        let code = runtime().block_on(args.drive(
            |request| {
                sent.push(request);
                let round = events.take().expect("a second round was asked for");
                std::future::ready(Ok(canned(round)))
            },
            &ctx,
            prompt.to_owned(),
            &mut out,
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
                    status: Some(500),
                    kind: "api_error".to_owned(),
                    message: "overloaded".to_owned(),
                    retry_after: None,
                }))
            },
            &ctx,
            "hi".to_owned(),
            Vec::new(),
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
        let body = serde_json::to_value(&sent).unwrap();
        assert_eq!(
            body[0]["messages"],
            serde_json::json!([{
                "role": "user",
                "content": [{ "type": "text", "text": "what is in /srv?" }],
            }])
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

        let body = serde_json::to_value(&sent).expect("a serializable request");
        assert_eq!(
            body[0]["messages"],
            serde_json::json!([
                { "role": "user", "content": [{ "type": "text", "text": "the first question" }] },
                { "role": "assistant", "content": [{ "type": "text", "text": "the first answer" }] },
                { "role": "user", "content": [{ "type": "text", "text": "and the second?" }] },
            ])
        );
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
        assert_eq!(code.expect("a reported turn"), TRUNCATED);
        assert!(
            store
                .resume(&only_session(&store))
                .unwrap()
                .messages()
                .is_empty()
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
