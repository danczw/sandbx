//! `agent-run`: one prompt, one streamed answer, tool calls through the boundary.
//!
//! Single-shot and non-interactive, so there is nobody to ask mid-turn: the approval gate
//! is decided from argv before the first request goes out. `--session` carries a
//! conversation between runs as a transcript on disk, not a live session.

mod gate;
mod orientation;
mod render;

use std::io::Write;

use gate::tool_name;
use render::Render;
use sandbx_agent::{Turn, TurnLimits, TurnOutcome, TurnStop, run_turn};
use sandbx_core::SandboxPolicy;
use sandbx_providers::{
    AnthropicClient, ContentBlock, EventStream, MessagesRequest, ProviderError, RequestMessage,
    Role,
};
use sandbx_session::{CompletedTurn, Session, SessionError, SessionId};
use sandbx_tools::{BuiltinTool, ExecutionContext};

use crate::session::{self, SessionChoice};
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
/// Neither success nor failure: what reached stdout is a real answer and an incomplete
/// one, which a script consuming it has to tell apart. The stderr line names which bound
/// stopped it.
const INCOMPLETE: i32 = 2;

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

    /// Cap how many times the model may be asked within one turn.
    ///
    /// A turn re-enters once per batch of tool calls, so this bounds how far a looping
    /// model can drive tool execution. A turn that hits the cap stops with its tool calls
    /// unanswered and says so on stderr.
    #[arg(
        long = "max-rounds",
        value_name = "N",
        default_value_t = TurnLimits::default().max_rounds,
        value_parser = round_cap,
    )]
    max_rounds: usize,

    /// Give the model a system prompt.
    ///
    /// Sent after the line naming the roots this run's tools can reach, which it does not
    /// replace. Unset sends that line alone.
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

    /// The system prompt `--system` gave, before the roots are prepended to it.
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
        let system = orientation::system_prompt(&policy, self.system());
        let ctx = ExecutionContext::new(policy);

        eprintln!(
            "sandbx: tools approved: {}",
            gate::approved_tools(self.allow_tool.as_deref()).join(", ")
        );

        // Before the session: the credential chain can fail for want of a key, and a
        // session opened first would leave a header-only transcript nothing deletes.
        let client = AnthropicClient::new(crate::auth::api_key()?)?;

        let session = session::open(self.session())?;

        self.drive(
            |request| client.stream_chat(request),
            &ctx,
            prompt,
            system,
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
        system: Option<String>,
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
            system,
            tools: &BuiltinTool::ALL,
            history: &history,
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
            withheld: session.as_ref().map_or(0, Session::withheld),
        };

        let mut render = Render::new(out);
        let outcome = run_turn(
            open,
            turn,
            ctx,
            |event| render.event(event),
            |requested| gate::decide(self.allow_tool.as_deref(), requested),
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

        // Closed before the turn's own error is propagated: a turn that died mid-stream
        // has already written part of an answer, and left the line it was on open.
        let code = render.finish(out_of_rounds);
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
                    "sandbx: the turn did not end on an answer; session {} is unchanged",
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

    /// A misplaced `--` turns `--allow-tool write -- "…"` into the bare flag plus a
    /// prompt. What that does to the approved set is `gate`'s to pin; this is the prompt.
    #[test]
    fn a_misplaced_separator_leaves_the_flag_a_prompt() {
        let args = agent_run(&["sandbx", "agent-run", "--allow-tool", "--", "write", "it"]);

        assert_eq!(args.prompt(), "write it");
    }

    #[test]
    fn a_round_cap_of_zero_is_refused() {
        let message = round_cap("0").expect_err("a turn that asks nothing was accepted");

        assert!(message.contains("at least one"), "got {message}");
        assert_eq!(round_cap("1"), Ok(1));
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
    ///
    /// A default policy grants nothing, so the orientation line is empty and the request
    /// carries whatever `--system` held, as it did before #178.
    fn one_round(
        args: &AgentRun,
        prompt: &str,
        events: Vec<AgentEvent>,
        session: Option<Session>,
    ) -> (Vec<MessagesRequest>, String, Result<i32, AgentError>) {
        under(SandboxPolicy::default(), args, prompt, events, session)
    }

    /// `one_round` under a policy of its caller's choosing, composing the system prompt
    /// the way `execute` does.
    fn under(
        policy: SandboxPolicy,
        args: &AgentRun,
        prompt: &str,
        events: Vec<AgentEvent>,
        session: Option<Session>,
    ) -> (Vec<MessagesRequest>, String, Result<i32, AgentError>) {
        let system = orientation::system_prompt(&policy, args.system());
        let ctx = ExecutionContext::new(policy);
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
            system,
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
            None,
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

    /// What ends the probing the round cap used to be reached by: the model is told the
    /// roots before the first request, not after a refusal (#178).
    #[test]
    fn the_request_carries_the_granted_root_as_system() {
        let args = agent_run(&["sandbx", "agent-run", "--system", "be terse", "--", "go"]);
        // A root that exists, and its canonical name: a grant the guard cannot resolve is
        // named by neither it nor the prompt.
        let work = tempfile::tempdir().expect("a temp dir");
        let named = work.path().canonicalize().expect("it exists");

        let (sent, _, code) = under(
            SandboxPolicy::default()
                .allow_read(work.path())
                .allow_write(work.path()),
            &args,
            &args.prompt(),
            vec![text("ok"), stop(StopReason::EndTurn)],
            None,
        );
        code.expect("clean turn");

        let body = serde_json::to_value(&sent).expect("a serializable request");
        let system = body[0]["system"].as_str().expect("a system prompt");
        assert!(
            system.contains(&format!("{} (read, write)", named.display())),
            "got {system:?}"
        );
        assert!(system.ends_with("be terse"), "got {system:?}");
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

    /// A round that asks for a tool and so would be followed by another. The policy
    /// grants nothing, so the call comes back `is_error` — still a `tool_result`, which
    /// is what makes the turn re-enter and meet the cap.
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

    /// What the bound used to cost: exit 1 with an empty stdout, indistinguishable from a
    /// provider failure, with the work already on disk (#178).
    #[test]
    fn a_turn_out_of_rounds_exits_two_with_its_text() {
        let args = agent_run(&["sandbx", "agent-run", "--max-rounds", "1", "--", "go"]);

        let (sent, written, code) = one_round(&args, &args.prompt(), asking_for_ls(), None);

        assert_eq!(sent.len(), 1, "the cap should have allowed one request");
        assert_eq!(written, "looking\n");
        assert_eq!(code.expect("a reported turn"), INCOMPLETE);
    }

    #[test]
    fn a_turn_out_of_rounds_leaves_the_session_alone() {
        let args = agent_run(&["sandbx", "agent-run", "--max-rounds", "1", "--", "go"]);
        let (_root, store, session) = new_session();

        let (_, _, code) = one_round(&args, &args.prompt(), asking_for_ls(), Some(session));

        assert_eq!(code.expect("a reported turn"), INCOMPLETE);
        // The batch ends on a `tool_result` the model never answered, which the store
        // refuses: resuming it would hand the model its own unanswered call.
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
