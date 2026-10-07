use super::*;

use std::io::Cursor;

/// Drive one exchange over `consent`, and report the verdict with what the operator saw.
///
/// A fresh `Cursor` per call, so a `consent` that asks again when it should not reaches
/// an immediate end of input and denies — which is visible as the wrong verdict.
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

    // Nothing typed: a second question would hit the end of input and deny, so `Allow`
    // here is the evidence that none was asked.
    let (second, seen) = ask(&mut consent, BuiltinTool::Write, "/work/b", "");
    assert_eq!(second, ApprovalDecision::Allow);
    assert_eq!(seen, "", "a blanket-approved tool was asked about again");

    let (other, _) = ask(&mut consent, BuiltinTool::Bash, "/work/c", "");
    assert!(
        matches!(other, ApprovalDecision::Deny { .. }),
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
/// call.
#[test]
fn an_end_of_input_refuses() {
    let (decision, _) = once(BuiltinTool::Bash, "/work/out.rs", "");

    let ApprovalDecision::Deny { reason } = decision else {
        panic!("a call was approved by an operator who typed nothing");
    };
    assert_eq!(reason, CLOSED);
}

/// A question an operator cannot read is one they cannot answer, so a sink that refuses
/// the write denies rather than reading an answer to nothing.
#[test]
fn a_question_that_could_not_be_written_refuses() {
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

    assert!(
        matches!(decision, ApprovalDecision::Deny { .. }),
        "an unwritten question was answered: {decision:?}"
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
/// Not a sleep: a pty's line discipline may move a written line into the reader's queue
/// from a workqueue, and a drain that ran before the line was queued would leave the
/// test asserting nothing.
fn wait_readable(fd: &impl std::os::fd::AsFd) {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
    let ready = poll(&mut fds, PollTimeout::from(5_000u16)).expect("poll");

    assert_eq!(ready, 1, "the pty queued nothing within five seconds");
}

/// A pty pair with the echo off, so the master carries only what sandbx wrote.
fn pty() -> (File, File) {
    use nix::sys::termios;

    let pair = nix::pty::openpty(None, None).expect("a pty pair");

    let mut attrs = termios::tcgetattr(&pair.slave).expect("the pty's termios");
    attrs.local_flags.remove(termios::LocalFlags::ECHO);
    termios::tcsetattr(&pair.slave, termios::SetArg::TCSANOW, &attrs).expect("echo off");

    (File::from(pair.master), File::from(pair.slave))
}

/// The branch's own invariant, over a real terminal because what the drain clears is the
/// kernel's input queue: a `y` typed at a question the model counterfeited in the round's
/// text is not read as the answer to the question that follows it.
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
