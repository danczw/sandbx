//! Where a trail line comes from, end to end: a model-issued call, dispatched, through
//! the guard, to one `decision=` field.
//!
//! Its own test binary, and so its own process, because the subscriber has to be the
//! global one: tools run on `spawn_blocking`, and a thread-local subscriber is not
//! installed on the thread that emits. `sandbx_cli::logging` installs globally for the
//! same reason.

use sandbx_agent::run_turn;
use sandbx_core::SandboxPolicy;
use sandbx_providers::{ContentBlock, StopReason};
use sandbx_tools::BuiltinTool;

mod support;

use support::{AllowAll, Script, call, ctx, stop, text, turn, vetted};

/// An in-memory stand-in for stderr.
///
/// Cloneable over a shared buffer because the applicable `MakeWriter` impl is the one for
/// `Fn() -> impl io::Write`, and the test still has to read back what its writers wrote.
#[derive(Clone, Default)]
struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The guard and tool suites drive the guard directly, so this is the only place the
/// dispatch sits in the path — and the only one showing two `decision=` values in the
/// order one turn produced them.
#[tokio::test]
async fn a_model_issued_call_records_its_access() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("nope");
    let ctx = ctx(SandboxPolicy::default().allow_read(vetted(root.path())));

    let listing = |path: &std::path::Path| {
        vec![
            call("ls", serde_json::json!({ "path": path.to_str().unwrap() })),
            stop(StopReason::ToolUse),
        ]
    };
    let mut script = Script::new([
        listing(root.path()),
        listing(&missing),
        vec![text("listed"), stop(StopReason::EndTurn)],
    ]);

    let sink = Sink::default();
    let writer = sink.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish(),
    )
    .unwrap();

    let messages = run_turn(
        async |r| script.open(r).await,
        turn(&[], &[BuiltinTool::Ls]),
        &ctx,
        |_| {},
        AllowAll,
    )
    .await
    .unwrap()
    .messages;

    let output = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    let trail: Vec<&str> = output
        .lines()
        .filter(|line| line.contains(sandbx_core::AUDIT_TARGET))
        .collect();

    assert_eq!(trail.len(), 2, "{output}");
    assert!(trail[0].contains(r#"decision="allowed""#), "{output}");
    assert!(trail[0].contains(r#"tool="read""#), "{output}");
    assert!(trail[1].contains(r#"decision="absent""#), "{output}");
    assert!(!trail[1].contains("reason"), "{output}");

    // The absence the trail named is the one the model was told about, and the turn ran
    // every round that produced it.
    assert_eq!(
        script.sent.len(),
        3,
        "the turn should have re-entered twice"
    );
    assert!(
        matches!(
            messages[3].content[0],
            ContentBlock::ToolResult {
                is_error: Some(true),
                ..
            }
        ),
        "got {:?}",
        messages[3]
    );
}
