use super::exit_code;
use std::process::ExitStatus;

/// A `wait(2)` status as the kernel encodes one for a process that exited with `code`.
/// `ExitStatus::from_raw` takes exactly that encoding, so nothing here spawns.
fn exited(code: i32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;

    ExitStatus::from_raw(code << 8)
}

/// The same, for a process killed by `signal`. The signal number occupies the low
/// seven bits, which is why an exit code sits in the byte above them.
fn killed_by(signal: i32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;

    ExitStatus::from_raw(signal)
}

#[test]
fn an_exit_code_is_reported_as_itself() {
    for code in [0, 1, 42, 255] {
        assert_eq!(
            exit_code(&exited(code)),
            code,
            "an exit code must survive the translation unchanged"
        );
    }
}

#[test]
fn a_signalled_death_reports_128_plus_the_signal() {
    for signal in [libc::SIGKILL, libc::SIGSEGV, libc::SIGPIPE] {
        assert_eq!(
            exit_code(&killed_by(signal)),
            128 + signal,
            "a command killed by {signal} must report 128 + the signal"
        );
    }
}

/// A stop is the only status that is neither an exit nor a death, so the only way to
/// reach that arm. The premise is asserted first: a future libc or std decoding this
/// encoding differently says so, rather than quietly re-testing the signal arm above.
#[test]
fn a_status_that_is_neither_exit_nor_death_fails() {
    use std::os::unix::process::ExitStatusExt;

    // 0x7f in the low byte is `WSTOPPED`; the signal that stopped it sits above,
    // where an exit code would.
    let stopped = ExitStatus::from_raw((libc::SIGSTOP << 8) | 0x7f);

    assert!(
        stopped.code().is_none() && stopped.signal().is_none(),
        "this raw status was meant to be neither an exit nor a death: {stopped:?}"
    );
    assert_eq!(
        exit_code(&stopped),
        1,
        "a status with no verdict of its own must report failure: {stopped:?}"
    );
}
