use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use nix::errno::Errno;
use sandbx_approval::{ApprovalDecision, CallGate, ToolCall};
use sandbx_tools::BuiltinTool;
use sandbx_tui_input::Reply;

use super::super::gate::ArgvGate;
use super::super::prompt::{Consent, Notes, Operator};
use super::{ANSWERS, Modal, Replies, Shows};

/// What happened, in order, across both fakes: the order is half of what is pinned.
type Log = Rc<RefCell<Vec<String>>>;

/// Whether a question reaches the screen is the second field.
struct Screen(Log, bool);

impl Shows for Screen {
    fn show(&mut self, lines: &[&str]) -> bool {
        self.0
            .borrow_mut()
            .push(format!("show {}", lines.join(" / ")));
        self.1
    }

    fn clear(&mut self) {
        self.0.borrow_mut().push("clear".to_string());
    }
}

impl Notes for Screen {
    fn note(&mut self, line: &str) {
        self.0.borrow_mut().push(format!("note {line}"));
    }
}

struct Keys {
    log: Log,
    replies: RefCell<VecDeque<Reply>>,
    clears: bool,
    /// Latched by an `Interrupted` reply, as the real stop is.
    stopped: std::cell::Cell<bool>,
}

impl Replies for Keys {
    fn arm(&self, accepts: &'static [char]) -> nix::Result<()> {
        self.log.borrow_mut().push(format!("arm {accepts:?}"));
        if self.clears {
            Ok(())
        } else {
            Err(Errno::ENOTTY)
        }
    }

    fn wait(&self) -> Reply {
        self.log.borrow_mut().push("wait".to_string());
        let reply = self
            .replies
            .borrow_mut()
            .pop_front()
            .expect("asked more often than the test scripted");
        if reply == Reply::Interrupted {
            self.stopped.set(true);
        }
        reply
    }

    fn interrupted(&self) -> bool {
        self.stopped.get()
    }
}

fn modal(replies: &[Reply]) -> (Modal<Screen, Keys>, Log) {
    let log = Log::default();
    let keys = Keys {
        log: Rc::clone(&log),
        replies: RefCell::new(replies.iter().copied().collect()),
        clears: true,
        stopped: std::cell::Cell::new(false),
    };

    (Modal::new(Screen(Rc::clone(&log), true), keys), log)
}

fn ask(
    modal: &mut impl Operator,
    tool: BuiltinTool,
    input: &serde_json::Value,
) -> ApprovalDecision {
    modal.ask(ToolCall {
        tool,
        id: "call_1",
        input,
    })
}

fn write() -> serde_json::Value {
    serde_json::json!({ "path": "/work/a.rs" })
}

fn refusal(decision: &ApprovalDecision) -> &str {
    match decision {
        ApprovalDecision::Deny { reason } => reason,
        other => panic!("not a refusal: {other:?}"),
    }
}

/// Drawn before it is armed, or a key pressed while nothing was on screen would answer a
/// question nobody had seen; and taken down once answered, or a stale one stays up over the
/// next round.
#[test]
fn the_question_is_drawn_then_armed_then_waited_on_then_taken_down() {
    let (mut modal, log) = modal(&[Reply::Key('y')]);

    let verdict = ask(&mut modal, BuiltinTool::Write, &write());

    assert_eq!(verdict, ApprovalDecision::Allow);
    assert_eq!(
        *log.borrow(),
        [
            "show sandbx: write /work/a.rs / sandbx: this call writes a file. allow it? \
             [y]es / [n]o / [a]ll `write` calls",
            "arm ['y', 'n', 'a']",
            "wait",
            "clear",
        ]
    );
}

#[test]
fn an_n_refuses_and_tells_the_model_no_flag_lifts_it() {
    let (mut modal, _) = modal(&[Reply::Key('n')]);

    let verdict = ask(&mut modal, BuiltinTool::Write, &write());

    assert!(
        refusal(&verdict).contains("the operator refused this call"),
        "{verdict:?}"
    );
}

/// Per tool, as under `agent-run`: judging one `write` is not judging `bash`.
#[test]
fn an_a_covers_later_calls_of_that_tool_and_no_other() {
    let (mut modal, log) = modal(&[Reply::Key('a'), Reply::Key('n')]);

    assert_eq!(
        ask(&mut modal, BuiltinTool::Write, &write()),
        ApprovalDecision::Allow
    );
    let asked = log.borrow().len();

    assert_eq!(
        ask(&mut modal, BuiltinTool::Write, &write()),
        ApprovalDecision::Allow
    );
    assert_eq!(
        log.borrow().len(),
        asked,
        "the covered call was asked about"
    );

    // Non-vacuous: another tool is still put to the operator, and refused when they say so.
    let bash = serde_json::json!({ "command": "ls" });
    let verdict = ask(&mut modal, BuiltinTool::Bash, &bash);
    assert!(
        refusal(&verdict).contains("refused"),
        "an `a` on `write` reached `bash`: {verdict:?}"
    );
}

/// Esc and ctrl-c refuse the call and leave the turn to the stop they latched: an interrupt
/// is the operator speaking, so it is not the lost channel `Abort` is for.
#[test]
fn an_interrupt_refuses_the_call_and_takes_the_question_down() {
    let (mut modal, log) = modal(&[Reply::Interrupted]);

    let verdict = ask(&mut modal, BuiltinTool::Write, &write());

    assert!(refusal(&verdict).contains("interrupted"), "{verdict:?}");
    assert_eq!(log.borrow().last().map(String::as_str), Some("clear"));
}

/// A channel that is gone is not an operator who said no: it ends the turn.
#[test]
fn a_lost_terminal_aborts_rather_than_refuses() {
    let (mut modal, log) = modal(&[Reply::Closed]);

    let verdict = ask(&mut modal, BuiltinTool::Write, &write());

    match verdict {
        ApprovalDecision::Abort { reason } => {
            assert!(reason.contains("terminal is closed"), "{reason}");
        }
        other => panic!("a lost terminal did not end the turn: {other:?}"),
    }
    assert_eq!(log.borrow().last().map(String::as_str), Some("clear"));
}

/// A queue that could not be cleared may already hold its own answer, so nothing is waited
/// for: the turn ends instead, as it does for a terminal `agent-run` could not flush.
#[test]
fn a_queue_that_could_not_be_cleared_aborts_without_waiting() {
    let (mut modal, log) = modal(&[]);
    modal.replies.clears = false;

    let verdict = ask(&mut modal, BuiltinTool::Write, &write());

    match verdict {
        ApprovalDecision::Abort { reason } => {
            assert!(reason.contains("could not be cleared"), "{reason}");
        }
        other => panic!("asked over an uncleared queue: {other:?}"),
    }
    assert!(
        !log.borrow().iter().any(|event| event == "wait"),
        "waited on a queue that could not be cleared"
    );
    assert_eq!(log.borrow().last().map(String::as_str), Some("clear"));
}

/// Unreachable through `arm`, which keeps only those three: and if it were reached, it is
/// not consent.
#[test]
fn a_key_nobody_asked_for_is_a_refusal() {
    let (mut modal, _) = modal(&[Reply::Key('x')]);

    let verdict = ask(&mut modal, BuiltinTool::Write, &write());

    assert!(refusal(&verdict).contains("refused"), "{verdict:?}");
}

/// The strip is the one the line prompt reads from, so an escape in a path never reaches
/// the screen as the model wrote it.
#[test]
fn the_question_carries_the_prompts_strip() {
    let (mut modal, log) = modal(&[Reply::Key('n')]);
    let hostile = serde_json::json!({ "path": "/work/\x1b[2J\x1b[8mallowed" });

    let _ = ask(&mut modal, BuiltinTool::Write, &hostile);

    let shown = log.borrow()[0].clone();
    assert!(shown.starts_with("show sandbx: write /work/"), "{shown}");
    assert!(
        !shown.contains('\x1b'),
        "an escape reached the screen: {shown:?}"
    );
}

/// Argv is asked first, so a tool no flag approved is refused without a question, and a
/// read-only call never gets one.
#[test]
fn argv_is_asked_first_and_a_read_is_never_asked() {
    let (modal, log) = modal(&[]);
    let mut gate = ArgvGate::new(None, Some(modal));

    let verdict = gate.approve(ToolCall {
        tool: BuiltinTool::Write,
        id: "call_1",
        input: &write(),
    });
    assert!(
        refusal(&verdict).contains("--allow-tool write"),
        "{verdict:?}"
    );

    let read = serde_json::json!({ "path": "/work/a.rs" });
    let verdict = gate.approve(ToolCall {
        tool: BuiltinTool::Read,
        id: "call_2",
        input: &read,
    });
    assert_eq!(verdict, ApprovalDecision::Allow);
    assert!(
        log.borrow().is_empty(),
        "a question was put: {:?}",
        log.borrow()
    );
}

/// Asked and told on one channel: the screen the question is on is where the account of
/// the call goes, never a stderr it covers.
#[test]
fn the_account_of_a_call_goes_where_the_question_was_asked() {
    let (mut modal, log) = modal(&[]);

    modal.report("sandbx: write /work/a.rs — ran");

    assert_eq!(*log.borrow(), ["note sandbx: write /work/a.rs — ran"]);
}

/// Consent without evidence: a question the screen could not draw is one the operator never
/// saw, and a key pressed meanwhile would answer it.
#[test]
fn a_question_that_could_not_be_drawn_is_never_asked() {
    let (mut modal, log) = modal(&[]);
    modal.screen.1 = false;

    let verdict = ask(&mut modal, BuiltinTool::Write, &write());

    match verdict {
        ApprovalDecision::Abort { reason } => {
            assert!(reason.contains("could not be drawn"), "{reason}");
        }
        other => panic!("asked a question nobody could see: {other:?}"),
    }
    let log = log.borrow();
    assert!(
        !log.iter()
            .any(|event| event.starts_with("arm") || event == "wait"),
        "armed or waited on a question that was not on screen: {log:?}"
    );
    assert_eq!(log.last().map(String::as_str), Some("clear"));
}

/// Unreachable through `arm`, which keeps only the keys asked for: the vocabulary is in two
/// places, and a key added to one alone would read as a refusal with no test failing.
#[test]
fn every_key_asked_for_is_an_answer() {
    for key in ANSWERS {
        let mut consent = Consent::new();
        assert!(
            consent
                .answer(BuiltinTool::Write, &key.to_string())
                .is_some(),
            "{key:?} is asked for and means nothing"
        );
    }
}

/// An `a` is the operator's word about a tool, not a way past a stop they gave afterwards:
/// a call it covers is refused once the turn has been interrupted, unasked.
#[test]
fn a_covered_call_is_refused_once_the_turn_is_interrupted() {
    let (mut modal, log) = modal(&[Reply::Key('a'), Reply::Interrupted]);
    assert_eq!(
        ask(&mut modal, BuiltinTool::Write, &write()),
        ApprovalDecision::Allow
    );

    let bash = serde_json::json!({ "command": "ls" });
    let _ = ask(&mut modal, BuiltinTool::Bash, &bash);
    let asked = log.borrow().len();

    let verdict = ask(&mut modal, BuiltinTool::Write, &write());

    assert!(refusal(&verdict).contains("interrupted"), "{verdict:?}");
    assert_eq!(log.borrow().len(), asked, "a stopped turn was asked again");
}
