use super::super::prompt::{APPROVE_CALL, Approve, Terminal};
use super::super::render::tests::{stop, text};
use super::super::{Device, orientation};
use super::{AgentRun, Channels, INCOMPLETE, round_cap, session_id};
use crate::AgentError;
use clap::Parser;
use sandbx_core::SandboxPolicy;
use sandbx_event::{AgentEvent, StopReason};
use sandbx_prompt::{ContentBlock, Prompt, RequestMessage, Role, Thinking, ToolChoice};
use sandbx_provider::{EventStream, ProviderError};
use sandbx_session_store::Session;
use sandbx_tools::ExecutionContext;
use std::path::Path;
use std::{fs, future, io};

/// `path`, pinned to the object it names — the shape every grant takes (#212).
fn vetted(path: impl AsRef<Path>) -> sandbx_core::VettedPath {
    sandbx_core::VettedPath::vet(path).expect("an existing path to pin the grant to")
}

fn agent_run(argv: &[&str]) -> AgentRun {
    match crate::Cli::parse_from(argv).command {
        crate::Command::AgentRun(args) => args,
        other => panic!("{other:?} is not agent-run"),
    }
}

/// What this leaves the approved set is `gate`'s to pin; this only asserts the prompt.
#[test]
fn a_misplaced_separator_leaves_the_flag_a_prompt() {
    let args = agent_run(&["sandbx", "agent-run", "--allow-tool", "--", "write", "it"]);

    assert_eq!(args.to_prompt(), "write it");
}

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

/// Asserting only a nonzero exit would also pass for a provider failure, so this
/// checks that the refusal names the flag to drop.
#[test]
fn a_run_with_no_terminal_to_ask_on_names_the_flag() {
    let error = AgentError::NoTerminal {
        source: io::Error::from_raw_os_error(6), // ENXIO: no controlling terminal
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

/// An `EventStream` that replays `events` and then ends. `fuse()` because
/// `EventStream` promises a `FusedStream`: a caller may poll past its end without panicking.
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

/// Drive one scripted round through `drive`. A default policy grants nothing, so the
/// request carries the approved tools and whatever `--system` held, with no roots line.
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

/// `one_round` over a script of several rounds, composing the system prompt the way
/// `execute` does. A script, not one round: a turn out of rounds is asked again with
/// no tool call allowed, so the round-limited cases here open two streams.
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
            future::ready(Ok(canned(round)))
        },
        &ctx,
        prompt.to_owned(),
        system,
        Channels {
            out: &mut out,
            err: Vec::new(),
            err_device: Device::Redirected,
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
            future::ready(Err(ProviderError::ApiError {
                status: Some(500),
                kind: "api_error".to_owned(),
                message: "overloaded".to_owned(),
            }))
        },
        &ctx,
        "hi".to_owned(),
        None,
        Channels {
            out: Vec::new(),
            err: Vec::new(),
            err_device: Device::Redirected,
            terminal: None,
        },
        session,
    ))
}

/// Drive a scripted run whose gate asks on `terminal`.
///
/// Its own builder rather than a sixth argument to `under`, which five callers pass
/// `None` through: this is the only shape where a verdict comes from a device.
fn asked_on(
    args: &AgentRun,
    policy: SandboxPolicy,
    terminal: Terminal,
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
            future::ready(Ok(canned(round)))
        },
        &ctx,
        "go".to_owned(),
        system,
        Channels {
            out: &mut out,
            err: Vec::new(),
            err_device: Device::Redirected,
            terminal: Some(terminal),
        },
        session,
    ));

    (sent, String::from_utf8(out).expect("utf-8"), code)
}

/// A terminal whose master is already gone — the configuration `strace` measured on a
/// `tmux kill-server`, driven through the real `/dev/tty` code path.
fn hung_up() -> Terminal {
    let (master, slave) = super::super::prompt::tests::pty();
    drop(master);
    Terminal::on(slave).expect("the terminal")
}

/// Two rounds — one asking to write `path`, one that must never be reached — so a
/// request count of one is evidence none opened rather than evidence the script ran dry.
fn asking_to_write(path: &Path) -> Vec<Vec<AgentEvent>> {
    vec![
        vec![
            text("looking"),
            AgentEvent::ToolCallRequested {
                id: "call_1".to_owned(),
                name: "write".to_owned(),
                input: serde_json::json!({
                    "path": path.to_str().unwrap(),
                    "content": "written",
                }),
            },
            stop(StopReason::ToolUse),
        ],
        vec![text("unreachable"), stop(StopReason::EndTurn)],
    ]
}

/// A store under a temporary directory, and one new session in it.
fn new_session() -> (
    tempfile::TempDir,
    sandbx_session_store::SessionStore,
    Session,
) {
    let root = tempfile::tempdir().expect("a temp dir");
    let store = sandbx_session_store::SessionStore::new(root.path().join("sessions"));
    let session = store.create().expect("a new session");
    (root, store, session)
}

#[test]
fn the_prompt_is_the_whole_request_history() {
    let args = agent_run(&["sandbx", "agent-run", "--", "what", "is", "in", "/srv?"]);

    let (sent, written, code) = one_round(
        &args,
        &args.to_prompt(),
        vec![text("etc"), stop(StopReason::EndTurn)],
        None,
    );

    assert_eq!(written, "etc\n");
    assert_eq!(code.expect("clean turn"), 0);
    assert_eq!(sent[0].messages, vec![asked("what is in /srv?")]);
}

/// A summary request is a 400 on every model before Claude 4.6, so both halves matter.
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

/// The last edge before the file; `run_turn` owns the replay. Asserted on raw bytes,
/// not the parse, so a later variant can't hide from this.
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
    let on_disk = fs::read_to_string(&path).expect("the transcript exists");

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
        &args.to_prompt(),
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
        &args.to_prompt(),
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
        &args.to_prompt(),
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
    let before = fs::read(session.path()).expect("the transcript exists");

    let error = failed_round(&args, Some(session)).expect_err("a turn that never opened");

    assert!(matches!(error, AgentError::Turn(_)), "got {error:?}");
    let after = fs::read(store.root().join(format!("{}.jsonl", only_session(&store))))
        .expect("the transcript exists");
    // An unanswered prompt would make the next resume send two user turns in a row.
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

    let body = fs::read_to_string(&path).expect("the transcript exists");
    // Both halves present first, so the assertions below are known to be reading the
    // file that holds the conversation.
    assert_eq!(body.matches("sentinel-9f3a").count(), 2, "got {body}");
    for needle in ["x-api-key", "authorization", "sk-ant-"] {
        assert!(!body.contains(needle), "{needle} reached {path:?}");
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
        &args.to_prompt(),
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
/// figure is `agent_render_tests.rs`'s `the_exit_code_comes_from_the_outcome_not_a_stop`,
/// not here: a latch over the event stream computes the same answer.
#[test]
fn a_truncated_answer_exits_incomplete() {
    let args = agent_run(&["sandbx", "agent-run", "--", "hi"]);

    let (_, out, code) = one_round(
        &args,
        &args.to_prompt(),
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
        &args.to_prompt(),
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
    let body = fs::read_to_string(&path).expect("the transcript exists");
    assert!(body.contains("looking"), "got {body}");
    assert!(!body.contains("here is what I found"), "got {body}");
    assert!(
        store
            .resume(&only_session(&store))
            .expect("a resumable turn")
            .pending_call()
    );
}

/// The two halves of #218 in one run: no further request is paid for, and the status
/// says the operator went away rather than reading as success.
#[test]
fn a_lost_terminal_exits_three_without_asking_again() {
    let args = agent_run(&[
        "sandbx",
        "agent-run",
        "--approve",
        "call",
        "--allow-tool",
        "write",
        "--",
        "go",
    ]);
    let root = tempfile::tempdir().expect("a temp dir");
    let file = root.path().join("out.txt");
    let policy = SandboxPolicy::default()
        .allow_read(vetted(root.path()))
        .allow_write(vetted(root.path()));

    let (sent, written, code) = asked_on(&args, policy, hung_up(), asking_to_write(&file), None);

    assert_eq!(code.expect("a reported turn"), 3);
    assert_eq!(
        sent.len(),
        1,
        "a turn with no operator opened a second request"
    );
    assert!(
        !file.exists(),
        "the call the operator was never asked about ran"
    );
    assert_eq!(written, "looking\n"); // What arrived before the hangup; no wrap-up prose.
}

/// A `TurnError` would discard exactly this, which is why the abort is a `TurnStop`:
/// the operator's own record of what the run got through is the transcript.
#[test]
fn a_lost_terminal_still_stores_the_turn() {
    let args = agent_run(&[
        "sandbx",
        "agent-run",
        "--approve",
        "call",
        "--allow-tool",
        "write",
        "--",
        "go",
    ]);
    let root = tempfile::tempdir().expect("a temp dir");
    let file = root.path().join("out.txt");
    let policy = SandboxPolicy::default()
        .allow_read(vetted(root.path()))
        .allow_write(vetted(root.path()));
    let (_store_root, store, session) = new_session();
    let path = session.path().to_owned();

    let (_, _, code) = asked_on(
        &args,
        policy,
        hung_up(),
        asking_to_write(&file),
        Some(session),
    );
    assert_eq!(code.expect("a reported turn"), 3);

    let body = fs::read_to_string(&path).expect("the transcript exists");
    assert!(body.contains("go"), "the prompt was not stored: {body}");
    assert!(body.contains("looking"), "the work was not stored: {body}");
    // The clause both channel reasons share, not either one: which of the drain and
    // the read fails first on a slave whose master is gone is platform detail.
    assert!(body.contains("no call can be approved"), "got {body}");
    assert!(
        store
            .resume(&only_session(&store))
            .expect("a resumable turn")
            .pending_call(),
        "an aborted turn stored an answer it never got"
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
        &args.to_prompt(),
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
    assert_eq!(last.role, sandbx_session_message::Role::Assistant);
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
        &capping.to_prompt(),
        vec![asking_for_ls()],
        Some(session),
    )
    .2
    .expect("a reported turn");

    let (sent, _, code) = one_round(
        &args,
        &args.to_prompt(),
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
fn only_session(store: &sandbx_session_store::SessionStore) -> sandbx_session_id::SessionId {
    let mut ids: Vec<String> = fs::read_dir(store.root())
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
