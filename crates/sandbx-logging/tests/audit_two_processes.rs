//! Two sandbx processes writing one stderr sink, which is the case #249 was filed about:
//! a CI job running several `sandbox-run` invocations into one file, or any aggregator.
//!
//! A per-process counter is the fix that looks right and is not one — both processes emit
//! 0, 1, 2, and the interleaved trail pairs the wrong spawn with the wrong exit while
//! looking perfectly well-formed. No test over a single process can see that, so this one
//! emits from two into one pipe and counts how many *distinct* ids come back.
//!
//! Its own binary, because it re-execs itself: `audit_log_held.rs` does the same for the
//! same reason, a real file descriptor being the only place two processes meet.
//!
//! Reading one pipe is safe *for the records below*: each is a single `write_all` of a
//! fixed fixture — a short `program` and a one-argument argv — which is a few hundred bytes
//! against `PIPE_BUF`'s 4096, so two writers cannot interleave within a line. That is a
//! property of this fixture and not of the format: `Spawned.args` carries up to `ARGS_CAP`
//! characters the model chose, which in non-ASCII is four bytes each, so a record in the
//! field can approach the limit. The record count below is what would catch a tear.
// `Command::new` here spawns this test binary, never a command that bypasses the sandbox.
#![allow(clippy::disallowed_methods)]

use std::collections::HashSet;
use std::io::Read;
use std::process::{Command, Stdio};

use sandbx_core::{AUDIT_TARGET, SandboxPolicy, SandboxedCommand};

/// Set on the re-exec, so the one test below runs its other half.
const CHILD: &str = "SANDBX_TEST_AUDIT_TWO_PROCESSES_CHILD";

/// How many runs each child opens, and how many children there are.
const RUNS: usize = 3;
const CHILDREN: usize = 2;

/// The `spawn=` of one record, less the quotes the layer renders a `&str` field with.
fn spawn_id(line: &str) -> &str {
    let after = line
        .split_once(r#"spawn=""#)
        .unwrap_or_else(|| panic!("no spawn id was recorded: {line}"))
        .1;

    after
        .split_once('"')
        .unwrap_or_else(|| panic!("the spawn id is unterminated: {line}"))
        .0
}

/// The nonce half of an id: everything ahead of the counter.
fn nonce(id: &str) -> &str {
    id.rsplit_once('.')
        .unwrap_or_else(|| panic!("an id carries no counter: {id}"))
        .0
}

#[test]
fn two_processes_never_mint_the_same_spawn_id() {
    if std::env::var_os(CHILD).is_some() {
        return child_run();
    }

    let (mut reader, writer) = std::io::pipe().expect("a pipe for the shared sink");
    let exe = std::env::current_exe().expect("the test binary should know its own path");

    let mut children: Vec<_> = (0..CHILDREN)
        .map(|_| {
            Command::new(&exe)
                .args([
                    "--exact",
                    "--nocapture",
                    "two_processes_never_mint_the_same_spawn_id",
                ])
                .env(CHILD, "1")
                // One descriptor, two writers: the configuration the issue names.
                .stderr(writer.try_clone().expect("a second handle on the sink"))
                // libtest's own chatter would otherwise land in what is parsed below.
                .stdout(Stdio::null())
                .spawn()
                .expect("the re-exec should start")
        })
        .collect();

    // Before the read: this handle is a write end too, so holding it would leave the pipe
    // open after both children exit and the read below would never see EOF.
    drop(writer);

    let mut sink = String::new();
    reader
        .read_to_string(&mut sink)
        .expect("the sink reads back");

    for (n, child) in children.iter_mut().enumerate() {
        let status = child.wait().expect("a child should be waitable");
        assert!(
            status.success(),
            "child {n} failed with {status}, so what it emitted proves nothing: {sink}"
        );
    }

    let records: Vec<&str> = sink
        .lines()
        .filter(|line| line.contains(AUDIT_TARGET))
        .collect();

    // The evidence the mechanism ran at all, and that no line was torn in two: a spawn and
    // an outcome per run, from each child.
    assert_eq!(
        records.len(),
        CHILDREN * RUNS * 2,
        "expected a spawn and an outcome per run from each child: {sink}"
    );

    let ids: Vec<&str> = records.iter().copied().map(spawn_id).collect();
    assert_eq!(
        ids.len(),
        records.len(),
        "a record carried no spawn id, so pairing is still positional: {sink}"
    );

    for id in &ids {
        assert_eq!(
            ids.iter().filter(|other| *other == id).count(),
            2,
            "{id} names {} records, where a run is exactly two: {sink}",
            ids.iter().filter(|other| *other == id).count()
        );
    }

    // The assertion this file exists for. A per-process counter reads 3 here: both children
    // emit 0, 1, 2, and three of the six runs are indistinguishable from the other three.
    let distinct: HashSet<&str> = ids.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        CHILDREN * RUNS,
        "{} distinct ids over {} runs in two processes, so a counter collided across them: \
         {sink}",
        distinct.len(),
        CHILDREN * RUNS
    );

    // What separated them has to be the nonce rather than the counter, and the nonce has to
    // be per process: re-derived per mint it would read 6 here and the counter would be dead
    // weight, shared across processes it would read 1 and the assertion above would be
    // passing on the counter alone. Both numbers are written here, not read off an id.
    let nonces: HashSet<&str> = ids.iter().copied().map(nonce).collect();
    assert_eq!(
        nonces.len(),
        CHILDREN,
        "{} nonces over two processes, where one process takes exactly one: {nonces:?}",
        nonces.len()
    );
}

/// The other half, in a process of its own: install the shipped subscriber and open `RUNS`
/// runs through the real emitter.
fn child_run() {
    sandbx_logging::init().expect("the subscriber installs once per process");

    for n in 0..RUNS {
        // A helper that cannot start closes the trail with a `failed`, so the pair is
        // complete with no kernel, no sandbox feature and no command ever executed.
        let _ = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
            .helper("/nonexistent/helper")
            .arg(format!("run-{n}"))
            .output();
    }
}
