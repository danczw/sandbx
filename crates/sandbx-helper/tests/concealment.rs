//! What another process running as the same user can read out of sandbx's procfs entry.
//!
//! Cross-process because that is the claim: what the flag stops is a same-uid reader, and
//! only a second process can be one. So the probe is spawned and read from here, before and
//! after it conceals itself, which is what pins the refusal on the call.
// `Command::new` spawns this crate's own probe; the workspace ban exists to stop code
// executing around the sandbox.
#![allow(clippy::disallowed_methods)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// A variable the probe carries, so a successful read is identifiable and not merely non-empty.
const MARKER: (&str, &str) = (
    "SANDBX_CONCEALMENT_PROBE",
    "a-stand-in-for-the-provider-key",
);

/// The probe, started with the marker in its environment and held at its first stage.
fn probe() -> Child {
    Command::new(env!("CARGO_BIN_EXE_sandbx-concealment-probe"))
        .env(MARKER.0, MARKER.1)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the probe should start")
}

/// Wait for the word the probe answers its current stage with. One reader for the whole
/// run: a `BufReader` built per line would take the next word into a buffer it then drops.
fn expect_word(stdout: &mut BufReader<impl Read>, expected: &str) {
    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .expect("the probe should report back");

    assert_eq!(line.trim(), expected, "the probe reported something else");
}

fn environ_of(child: &Child) -> PathBuf {
    PathBuf::from(format!("/proc/{}/environ", child.id()))
}

/// Kill the probe and reap it, so a case that ends early leaves no process behind.
fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// #192: a `--allow-read /proc` grant must not reach the key the harness was handed in its
/// environment.
#[test]
fn a_concealed_process_hides_its_environment_from_its_parent() {
    let mut child = probe();
    let mut stdout = BufReader::new(child.stdout.take().expect("the probe's stdout is piped"));
    let mut stdin = child.stdin.take().expect("the probe's stdin is piped");

    expect_word(&mut stdout, "STARTED");

    let before = std::fs::read(environ_of(&child));
    // A host that already hides procfs from a parent — `hidepid`, a locked-down container —
    // leaves nothing for the flag to take away, and a pass here would prove nothing.
    if let Err(error) = &before {
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        eprintln!("skipped: this host hides a child's procfs entry from its parent already");
        stop(&mut child);
        return;
    }

    let read = before.expect("read before concealment");
    assert!(
        String::from_utf8_lossy(&read).contains(&format!("{}={}", MARKER.0, MARKER.1)),
        "the probe's environment did not carry the marker, so the read proves nothing"
    );

    writeln!(stdin, "conceal").expect("the probe should still be listening");
    expect_word(&mut stdout, "CONCEALED");

    let after = std::fs::read(environ_of(&child));
    stop(&mut child);

    let error = after.expect_err("the concealed probe's environment was still readable");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "the read failed for a reason other than the kernel refusing it"
    );
}
