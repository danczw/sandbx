//! The one `tracing` subscriber the `sandbx` binary installs.
//!
//! `sandbx-core` emits an audit trail on `AUDIT_TARGET`, but `tracing` drops every event
//! when no subscriber is installed, and a library cannot install one for its embedder.
//! Not configurable: the audit trail is not opt-in diagnostics.

use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// The subscriber the binary installs, writing to `writer`.
///
/// Generic over its writer so a test can drive the real subscriber over an in-memory
/// sink. Admits `AUDIT_TARGET` at `INFO` and nothing else, both halves load-bearing: the
/// target keeps `sandbx-core`'s own `debug!` out, the level keeps anything below `INFO`
/// that merely borrowed the target out. Returns `impl SubscriberInitExt` to keep
/// `tracing` off this crate's dependency list.
pub fn subscriber<W>(writer: W) -> impl SubscriberInitExt
where
    W: for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> + Send + Sync + 'static,
{
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                // Forced off, not left to the default, which keys off the `ansi`
                // feature — unstable across profiles, since `cargo test --workspace`
                // unifies it on through a dev-dependency. This stream gets grepped.
                .with_ansi(false),
        )
        // A global filter rather than a per-layer `with_filter`: same effect with one
        // layer, but this form contributes a real `max_level_hint`, which lets
        // `tracing` skip every `debug!` callsite in the workspace statically.
        .with(Targets::new().with_target(sandbx_core::AUDIT_TARGET, LevelFilter::INFO))
}

/// Install the audit subscriber on stderr for the rest of the process.
///
/// Stderr, not the stdout `tracing_subscriber::fmt` defaults to: `SandboxRun::execute`
/// forwards the sandboxed command's output over stdout, so a record interleaved there
/// would corrupt whatever is piping it. `try_init` rather than `init`: losing the audit
/// trail is worth reporting, but the process can still sandbox a command.
pub fn init() -> Result<(), tracing_subscriber::util::TryInitError> {
    subscriber(std::io::stderr as fn() -> std::io::Stderr).try_init()
}
