//! The one `tracing` subscriber the `sandbx` binary installs.
//!
//! `sandbx-core` emits an audit trail on `AUDIT_TARGET`, but `tracing` drops every
//! event when no subscriber is installed, and a library cannot install one without
//! deciding for its embedder. Not configurable — no flag, no environment variable, no
//! format choice — since the audit trail is not opt-in diagnostics, and knobs are
//! worth designing once logging has more than one consumer.

use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// The subscriber the binary installs, writing to `writer`.
///
/// Takes its writer rather than hardcoding stderr so a test can drive the real
/// subscriber over an in-memory sink.
///
/// Admits `AUDIT_TARGET` at `INFO` and nothing else; both halves are load-bearing. The
/// target keeps `sandbx-core`'s own `debug!` diagnostics out. The level keeps anything
/// below `INFO` that merely borrowed the target out of a record meant to read as
/// decisions — hardening failures are `INFO` deliberately, and reach this subscriber
/// from the re-exec'd helper over the audit channel `core/src/degradation.rs`
/// describes.
///
/// Returns `impl SubscriberInitExt` rather than `impl tracing::Subscriber`: exactly
/// the two methods the callers need, and it keeps `tracing` off this crate's
/// dependency list.
pub fn subscriber<W>(writer: W) -> impl SubscriberInitExt
where
    W: for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> + Send + Sync + 'static,
{
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                // Forced off rather than left to the default, which keys off the
                // `ansi` feature and `NO_COLOR`: this stream is a record that gets
                // piped and grepped. The default is not even stable across profiles —
                // `cargo test --workspace` unifies `ansi` on via `sandbx-core`'s
                // dev-dependency.
                .with_ansi(false),
        )
        // A global filter rather than a per-layer `with_filter`: same effect with one
        // layer, but this form contributes a real `max_level_hint`, which lets
        // `tracing` skip every `debug!` callsite in the workspace statically.
        // `Targets` matches by prefix, so a `sandbx::audit::fs` sub-target is admitted
        // without a change here.
        .with(Targets::new().with_target(sandbx_core::AUDIT_TARGET, LevelFilter::INFO))
}

/// Install the audit subscriber on stderr for the rest of the process.
///
/// Stderr, not stdout — `tracing_subscriber::fmt` defaults to stdout, which
/// `SandboxRun::execute` forwards the sandboxed command's output over, so a record
/// interleaved there would corrupt whatever is piping it.
///
/// `try_init` rather than `SubscriberInitExt::init`: a process that cannot install a
/// subscriber has lost its audit trail, which is worth reporting, but it can still
/// sandbox a command.
pub fn init() -> Result<(), tracing_subscriber::util::TryInitError> {
    subscriber(std::io::stderr as fn() -> std::io::Stderr).try_init()
}
