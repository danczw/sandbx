use super::*;

use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};

/// The account every assertion below is written against.
const ACCOUNT: &str = "sandbx: write /work/out.rs — ran";

/// An in-memory stand-in for stderr.
///
/// Cloneable over a shared buffer because the terminal takes its fallback by value, and the
/// test still has to read back what reached it.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Sink {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).expect("utf-8")
    }
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Drive one exchange over `consent`, and report the verdict with what the operator saw.
///
/// A fresh `Cursor` per call, so a `consent` that asks again when it should not reaches
/// an immediate end of input and aborts — which is visible as the wrong verdict.
fn ask(
    consent: &mut Consent,
    tool: BuiltinTool,
    path: &str,
    typed: &str,
) -> (ApprovalDecision, String) {
    let input = serde_json::json!({ "path": path });
    let mut typed = Cursor::new(typed.as_bytes());
    let mut seen = Vec::new();

    let decision = consent.ask(
        ToolCall {
            tool,
            id: "call_1",
            input: &input,
        },
        &mut typed,
        &mut seen,
    );

    (decision, String::from_utf8(seen).expect("utf-8"))
}

/// One exchange on a consent with nothing already granted.
fn once(tool: BuiltinTool, path: &str, typed: &str) -> (ApprovalDecision, String) {
    ask(&mut Consent::new(), tool, path, typed)
}

#[test]
fn the_question_names_the_tool_what_it_does_and_the_arguments() {
    let (decision, seen) = once(BuiltinTool::Write, "/work/out.rs", "y\n");

    assert_eq!(decision, ApprovalDecision::Allow);
    assert!(seen.contains("write /work/out.rs"), "got {seen:?}");
    assert!(seen.contains("writes a file"), "got {seen:?}");
    assert!(seen.contains("[a]ll `write` calls"), "got {seen:?}");
}

/// A `bash` is the one call whose arguments are the whole decision, so the command has to
/// be in the question rather than the tool's name alone.
#[test]
fn a_command_is_quoted_back_before_it_runs() {
    let input = serde_json::json!({ "command": "rm -rf /work" });
    let mut typed = Cursor::new(b"n\n".as_slice());
    let mut seen = Vec::new();

    Consent::new().ask(
        ToolCall {
            tool: BuiltinTool::Bash,
            id: "call_1",
            input: &input,
        },
        &mut typed,
        &mut seen,
    );

    let seen = String::from_utf8(seen).expect("utf-8");
    assert!(seen.contains("bash rm -rf /work"), "got {seen:?}");
    assert!(seen.contains("runs a program"), "got {seen:?}");
}

/// No flag lifts an operator's refusal, so offering one would send the model round a
/// round advising a flag that changes nothing.
#[test]
fn a_refusal_offers_the_model_no_flag() {
    let (decision, _) = once(BuiltinTool::Write, "/work/out.rs", "n\n");

    let ApprovalDecision::Deny { reason } = decision else {
        panic!("a refused call was approved");
    };
    assert!(reason.contains("operator refused"), "got {reason}");
    assert!(!reason.contains("--allow-tool"), "got {reason}");
}

/// The answer that makes a twenty-write turn answerable, and the one that must not leak
/// into the next tool.
#[test]
fn all_is_remembered_for_that_tool_and_for_no_other() {
    let mut consent = Consent::new();

    let (first, _) = ask(&mut consent, BuiltinTool::Write, "/work/a", "a\n");
    assert_eq!(first, ApprovalDecision::Allow);

    // Nothing typed: a second question would hit the end of input and end the turn, so
    // `Allow` here is the evidence that none was asked.
    let (second, seen) = ask(&mut consent, BuiltinTool::Write, "/work/b", "");
    assert_eq!(second, ApprovalDecision::Allow);
    assert_eq!(seen, "", "a blanket-approved tool was asked about again");

    let (other, _) = ask(&mut consent, BuiltinTool::Bash, "/work/c", "");
    assert!(
        matches!(other, ApprovalDecision::Abort { .. }),
        "an `a` for write carried over to bash: {other:?}"
    );
}

/// Neither answer: taken as consent it runs an unapproved call, and taken as a refusal it
/// trains an operator to retype blind.
#[test]
fn an_unrecognised_answer_is_asked_again() {
    let (decision, seen) = once(BuiltinTool::Write, "/work/out.rs", "maybe\ny\n");

    assert_eq!(decision, ApprovalDecision::Allow);
    assert_eq!(
        seen.matches("allow it?").count(),
        2,
        "the question was not put again: {seen:?}"
    );
}

/// A terminal that went away cannot answer, and an unanswered question must not run the
/// call — nor any call behind it, there being nothing left to ask.
#[test]
fn an_end_of_input_ends_the_turn() {
    let (decision, _) = once(BuiltinTool::Bash, "/work/out.rs", "");

    let ApprovalDecision::Abort { reason } = decision else {
        panic!("a call was approved or merely refused by an operator who typed nothing");
    };
    assert_eq!(reason, CLOSED);
}

/// Two questions and not three, which is what pins the retry: `read_line` consumes the
/// rejected line through its newline before the UTF-8 check fails it, so a reader that
/// left the `\n` behind would give the second read an empty line, the typo arm, and a
/// third question.
#[test]
fn a_byte_that_is_not_text_is_asked_about_again() {
    let input = serde_json::json!({ "path": "/work/out.rs" });
    let mut typed = Cursor::new(b"\xff\ny\n".as_slice());
    let mut seen = Vec::new();

    let decision = Consent::new().ask(
        ToolCall {
            tool: BuiltinTool::Write,
            id: "call_1",
            input: &input,
        },
        &mut typed,
        &mut seen,
    );

    assert_eq!(decision, ApprovalDecision::Allow);
    let seen = String::from_utf8(seen).expect("utf-8");
    assert_eq!(
        seen.matches("allow it?").count(),
        2,
        "asked once, or asked a third time over a leftover newline: {seen:?}"
    );
}

/// A question an operator cannot read is one they cannot answer, so a sink that refuses
/// the write ends the turn rather than reading an answer to nothing.
#[test]
fn a_question_that_could_not_be_written_aborts() {
    /// A sink that fails every write, standing in for a terminal that went away between
    /// the open and the question.
    struct Closed;

    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let input = serde_json::json!({ "path": "/work/out.rs" });
    let mut typed = Cursor::new(b"y\n".as_slice());

    let decision = Consent::new().ask(
        ToolCall {
            tool: BuiltinTool::Write,
            id: "call_1",
            input: &input,
        },
        &mut typed,
        &mut Closed,
    );

    assert_eq!(
        decision,
        ApprovalDecision::Abort {
            reason: CLOSED.to_owned()
        }
    );
    assert_eq!(
        typed.position(),
        0,
        "the answer to an unasked question was read"
    );
}

/// The attack this prompt is the reason the strip exists: a model-chosen path carrying an
/// escape sequence rewrites the question the operator is about to answer `y` to.
#[test]
fn an_escape_sequence_in_a_path_cannot_rewrite_the_question() {
    let hostile = "/work/a\x1b[2K\rsandbx: this call reads a file, nothing to approve";
    assert!(
        hostile.chars().any(char::is_control),
        "the fixture carries no control character, so this asserts nothing"
    );

    let (_, seen) = once(BuiltinTool::Write, hostile, "n\n");

    assert!(
        !seen.chars().any(|c| c.is_control() && c != '\n'),
        "a control character reached the terminal: {seen:?}"
    );
    assert!(seen.contains("write /work/a"), "got {seen:?}");
    // One question, so the injected second one cannot be the one being answered.
    assert_eq!(seen.matches("allow it?").count(), 1, "got {seen:?}");
}

/// Wait for `fd` to carry something, or fail the test.
///
/// Not a sleep: a pty queues a written line from a workqueue, and a drain that ran before
/// it was queued would leave the test asserting nothing.
fn wait_readable(fd: &impl std::os::fd::AsFd) {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
    let ready = poll(&mut fds, PollTimeout::from(5_000u16)).expect("poll");

    assert_eq!(ready, 1, "the pty queued nothing within five seconds");
}

/// A pty pair with the echo off, so the master carries only what sandbx wrote.
///
/// `ONLCR` off with it: the line discipline translates a written `\n` into `\r\n` on the
/// way out, and a byte the writer never sent is one an exact assertion cannot allow for.
pub(crate) fn pty() -> (File, File) {
    use nix::sys::termios;

    let pair = nix::pty::openpty(None, None).expect("a pty pair");

    let mut attrs = termios::tcgetattr(&pair.slave).expect("the pty's termios");
    attrs.local_flags.remove(termios::LocalFlags::ECHO);
    attrs.output_flags.remove(termios::OutputFlags::ONLCR);
    termios::tcsetattr(&pair.slave, termios::SetArg::TCSANOW, &attrs).expect("echo off");

    (File::from(pair.master), File::from(pair.slave))
}

/// Over a real terminal because what the drain clears is the kernel's input queue: a `y`
/// typed at a counterfeit question is not read as the answer to the real one.
#[test]
fn an_answer_typed_before_the_question_is_not_read_as_its_answer() {
    let (mut master, slave) = pty();

    writeln!(master, "y").expect("the typed line");
    // Queued before the drain runs, or the drain is not what the verdict below shows.
    wait_readable(&slave);

    let mut terminal = Terminal::on(slave).expect("the terminal");
    let input = serde_json::json!({ "path": "/work/out.rs" });
    let asking = &mut terminal;

    let decision = std::thread::scope(|scope| {
        let asked = scope.spawn(move || {
            asking.ask(ToolCall {
                tool: BuiltinTool::Write,
                id: "call_1",
                input: &input,
            })
        });

        // Only after the question has been written, so the answer below is an answer to
        // it and the `y` above could only have been consumed by the drain.
        wait_readable(&master);
        writeln!(master, "n").expect("the answer");

        asked.join().expect("the asking thread")
    });

    assert!(
        matches!(decision, ApprovalDecision::Deny { .. }),
        "the `y` typed before the question was read as the answer to it: {decision:?}"
    );
}

/// A hangup is not an EOF the operator sent: the master is gone, so the read cannot block.
///
/// The discriminant alone, no reason: whether a slave whose master is gone fails at
/// `tcflush` or at the question's write is platform detail, and a `Deny` — the answer
/// before #218 — is what the discriminant rules out.
#[test]
fn a_terminal_that_hung_up_aborts_without_blocking() {
    let (master, slave) = pty();
    drop(master);

    let mut terminal = Terminal::on(slave).expect("the terminal");
    let input = serde_json::json!({ "path": "/work/out.rs" });

    let decision = terminal.ask(ToolCall {
        tool: BuiltinTool::Write,
        id: "call_1",
        input: &input,
    });

    assert!(
        matches!(decision, ApprovalDecision::Abort { .. }),
        "a dead terminal approved a call, or left the turn to go on: {decision:?}"
    );
}

/// The drain is what keeps a counterfeit question from being answered, so a terminal it
/// cannot run on is one no call may be approved over.
#[test]
fn a_terminal_that_cannot_be_cleared_aborts() {
    // Not a tty, so `tcflush` fails with `ENOTTY` before any question is written.
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .expect("/dev/null");
    let mut terminal = Terminal::on(null).expect("the terminal");
    let input = serde_json::json!({ "path": "/work/out.rs" });

    let decision = terminal.ask(ToolCall {
        tool: BuiltinTool::Write,
        id: "call_1",
        input: &input,
    });

    // `UNCLEARED` and not `CLOSED`: the drain is the arm that fired, not the read.
    assert_eq!(
        decision,
        ApprovalDecision::Abort {
            reason: UNCLEARED.to_owned()
        }
    );
}

/// The whole of the distinction: an operator who says no refuses one call, a channel that
/// cannot be asked refuses every call there will be.
#[test]
fn a_refusal_is_not_a_lost_channel() {
    let (refused, _) = once(BuiltinTool::Write, "/work/out.rs", "n\n");
    let (closed, _) = once(BuiltinTool::Write, "/work/out.rs", "");

    assert!(
        matches!(refused, ApprovalDecision::Deny { .. }),
        "an operator's refusal ended the run: {refused:?}"
    );
    assert!(
        matches!(closed, ApprovalDecision::Abort { .. }),
        "a lost channel was taken for a refusal: {closed:?}"
    );
}

/// The account is written from a reset too, not only the question: the model's text reaches
/// this same device, and a concealing SGR left in it would hide the one record of what ran.
#[test]
fn the_account_of_a_call_is_written_from_a_known_graphic_rendition() {
    let (mut master, slave) = pty();
    let mut terminal = Terminal::on(slave).expect("the terminal");

    terminal.report(ACCOUNT);

    // Sized off what is expected rather than a round number: a fixed buffer passes on a
    // prefix of a longer account, and the assertions below would not see the cut.
    let expected = format!("{RESET}{ACCOUNT}\n");
    wait_readable(&master);
    let mut buffer = vec![0u8; expected.len()];
    let read = master
        .read(&mut buffer)
        .expect("what the terminal was sent");
    let seen = String::from_utf8_lossy(&buffer[..read]);

    assert!(
        seen.starts_with(RESET),
        "the account was written from whatever state the model left behind: {seen:?}"
    );
    assert_eq!(seen, expected, "the account did not arrive whole");
}

/// A slave whose master is gone fails the write with `EIO`, and the account is the operator's
/// one record of what ran — so it reaches the fallback rather than nobody (#223).
#[test]
fn an_account_a_terminal_refused_still_lands() {
    let (master, slave) = pty();
    drop(master);

    let sink = Sink::default();
    let mut terminal = Terminal::on(slave)
        .expect("the terminal")
        .falls_back_to(sink.clone(), false);

    terminal.report(ACCOUNT);

    // The content, not merely that nothing panicked: a `report` that swallowed the error,
    // or wrote only to the dead pty, leaves this empty.
    assert_eq!(
        sink.text(),
        "sandbx: write /work/out.rs — ran\n",
        "the account went nowhere, or the hung-up pty took the write"
    );
}

/// The control the one above needs: a terminal that takes the account is not also written
/// to stderr, where an operator reading a redirect would see every line twice.
#[test]
fn an_account_a_terminal_took_reaches_no_fallback() {
    let (mut master, slave) = pty();

    let sink = Sink::default();
    let mut terminal = Terminal::on(slave)
        .expect("the terminal")
        .falls_back_to(sink.clone(), false);

    terminal.report(ACCOUNT);

    // The pty read first, so an empty sink is evidence the write landed rather than
    // evidence `report` did nothing at all.
    wait_readable(&master);
    let mut buffer = vec![0u8; RESET.len() + ACCOUNT.len() + 1];
    let read = master
        .read(&mut buffer)
        .expect("what the terminal was sent");
    assert_eq!(
        String::from_utf8_lossy(&buffer[..read]),
        format!("{RESET}{ACCOUNT}\n")
    );
    assert_eq!(
        sink.text(),
        "",
        "a terminal that took the account fell back as well"
    );
}

/// `2> run.log` would carry the escape into the log, so the reset belongs to the sink and
/// not to the line.
#[test]
fn an_account_resets_only_where_that_renders() {
    assert!(
        !ACCOUNT.chars().any(char::is_control),
        "the fixture carries a control character, so the second case asserts nothing"
    );

    // The escape spelled out rather than read off `RESET`: read off it, the assertion only
    // proves the account agrees with whatever the constant became.
    assert_eq!(
        account(true, ACCOUNT),
        "\x1b[0msandbx: write /work/out.rs — ran\n"
    );
    assert_eq!(
        account(false, ACCOUNT),
        "sandbx: write /work/out.rs — ran\n"
    );
}
