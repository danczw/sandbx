use super::*;
use std::sync::{Arc, Mutex};
use std::{fmt, io};

/// What `record_reports` makes of a channel, without a helper to write one. The write
/// end is dropped before the read, which is what makes the read terminate.
fn reported(channel: &str) -> Option<crate::HelperRefusal> {
    // A mint of its own: these assert on the refusal `record_reports` returns rather
    // than on the records it emits.
    read_channel(channel, &crate::SpawnId::next(), None).0
}

/// `record_reports` over a crafted channel, with whatever it emitted.
///
/// Here rather than against a real helper because **whether a run degrades is the
/// host's answer**: a kernel that drops the bounding set cleanly emits no `degraded` at
/// all, so `audit_channel.rs`'s real-helper tests cannot reach this path on most
/// machines and a regression in it would go unmeasured.
fn read_channel(
    channel: &str,
    spawn: &crate::SpawnId,
    session: Option<&str>,
) -> (Option<crate::HelperRefusal>, Vec<String>) {
    use std::io::Write;
    use tracing_subscriber::layer::SubscriberExt;

    let (read, mut write) = io::pipe().expect("a pipe for the channel");
    write.write_all(channel.as_bytes()).expect("the channel");
    drop(write);

    let sink = Captured::default();
    let subscriber = tracing_subscriber::registry().with(sink.clone());
    let refused =
        tracing::subscriber::with_default(subscriber, || record_reports(read, spawn, session));

    (refused, sink.0.lock().unwrap().clone())
}

/// Collects audit records as `field=value ` text, emitted on the calling thread so a
/// thread-local subscriber sees them.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Captured {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() != crate::AUDIT_TARGET {
            return;
        }
        let mut visitor = Collect(String::new());
        event.record(&mut visitor);
        self.0.lock().unwrap().push(visitor.0);
    }
}

struct Collect(String);

impl tracing::field::Visit for Collect {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.0.push_str(&format!("{}={value:?} ", field.name()));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.push_str(&format!("{}={value} ", field.name()));
    }
}

/// The id `record_reports` puts on a degradation is the run it weakened; that function's
/// own doc has why position cannot stand in for it.
#[test]
fn a_degradation_names_the_run_that_weakened() {
    let run = crate::SpawnId::next();
    let (refused, lines) = read_channel(
        "capability_bounding_set\tleft as inherited\n",
        &run,
        Some("abc123"),
    );

    assert_eq!(refused, None, "a degradation is not a refusal");
    assert_eq!(lines.len(), 1, "one degradation, one record: {lines:?}");
    let line = &lines[0];
    assert!(line.contains("decision=degraded"), "got: {line}");
    assert!(
        line.contains(&format!("spawn={} ", run.as_str())),
        "the degradation named another run than the one it weakened: {line}"
    );
    assert!(
        line.contains("session=abc123 "),
        "the degradation did not reach the transcript its run is stored in: {line}"
    );
}

/// The anti-vacuity half of the case above: a channel with nothing on it emits nothing,
/// so the assertions there are about a record the channel produced.
#[test]
fn an_empty_channel_emits_no_degradation() {
    let (refused, lines) = read_channel("", &crate::SpawnId::next(), None);

    assert_eq!(refused, None, "an empty channel refused the run");
    assert!(lines.is_empty(), "got: {lines:?}");
}

#[test]
fn a_refusal_on_the_channel_becomes_the_runs_reason() {
    assert_eq!(
        reported("process_hardening\t\n"),
        Some(crate::HelperRefusal::ProcessHardening),
        "a stage that refused did not name its reason"
    );
}

#[test]
fn a_degradation_alone_is_not_a_refusal() {
    assert_eq!(
        reported("capability_bounding_set\tleft as inherited\n"),
        None,
        "a degraded run was reported as one that never started"
    );
}

#[test]
fn an_unknown_reason_does_not_reach_the_trail() {
    assert_eq!(
        reported("not_a_refusal\t\n"),
        None,
        "the channel named a reason sandbx does not define"
    );
}
