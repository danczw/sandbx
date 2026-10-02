//! The one `tracing` subscriber the `sandbx` binary installs.
//!
//! `sandbx-core` emits an audit trail on `AUDIT_TARGET` and documents it as a
//! product feature, but `tracing` drops every event when no subscriber is
//! installed — so until #89 the shipped binary recorded nothing, however verbose
//! `RUST_LOG` was set. A library cannot install a subscriber without deciding
//! for its embedder; the binary can, and this is it.
//!
//! Deliberately not configurable: no flag, no environment variable, no format
//! choice. The audit trail is not opt-in diagnostics, and a logging surface with
//! knobs is worth designing once logging has more than one consumer. Until then
//! this module is small enough to replace wholesale.

use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// The subscriber the binary installs, writing to `writer`.
///
/// Takes its writer rather than hardcoding stderr so a test can drive the real
/// subscriber over an in-memory sink: what this filters is the security-relevant
/// half, and pinning it should not require spawning the binary or capturing a
/// file descriptor.
///
/// The filter admits `AUDIT_TARGET` at `INFO` and nothing else. Both halves are
/// load-bearing. The target half keeps `sandbx-core`'s own `debug!` diagnostics
/// out, so making the audit trail visible does not also make the internals
/// user-visible noise. The level bound keeps anything below `INFO` that merely
/// borrowed this target out of a record meant to be read as decisions — the
/// best-effort hardening failures are `INFO` since #89 and admitted deliberately,
/// a weakened sandbox not being something an operator should have to opt into
/// seeing. They are detected in the re-exec'd helper, which installs no subscriber
/// at all, and reach this one over the audit channel `core/src/degradation.rs`
/// describes (#95).
///
/// Returns `impl SubscriberInitExt` rather than `impl tracing::Subscriber`: that
/// is exactly the two methods the two callers need — [`init`] uses `try_init`,
/// the tests use `set_default` — and it keeps `tracing` itself off this crate's
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
                // `ansi` feature and `NO_COLOR`: this stream is a record that
                // gets piped and grepped, and escape codes in a file are damage.
                // Under `cargo test --workspace` feature unification turns `ansi`
                // on via `sandbx-core`'s dev-dependency, so the default here is
                // not even stable across build profiles.
                .with_ansi(false),
        )
        // Stacked as a global filter rather than a per-layer `with_filter`. With
        // one layer the effect is the same, but this form contributes a real
        // `max_level_hint`, which lets `tracing` skip every `debug!` callsite in
        // the workspace statically. `Targets` matches by prefix, so a future
        // `sandbx::audit::fs` sub-target is admitted without a change here.
        .with(Targets::new().with_target(sandbx_core::AUDIT_TARGET, LevelFilter::INFO))
}

/// Install the audit subscriber on stderr for the rest of the process.
///
/// Stderr, not stdout: `SandboxRun::execute` forwards the sandboxed command's
/// stdout verbatim, and a record interleaved into it would corrupt whatever is
/// piping that output. `tracing_subscriber::fmt`'s own default is stdout, so the
/// choice is explicit rather than inherited.
///
/// Returns the error instead of panicking — which is why this is `try_init` and
/// not `SubscriberInitExt::init`. A process that cannot install a subscriber has
/// lost its audit trail, and that is worth reporting, but it has not lost the
/// ability to sandbox a command; taking the run down would be the larger
/// failure.
pub fn init() -> Result<(), tracing_subscriber::util::TryInitError> {
    subscriber(std::io::stderr as fn() -> std::io::Stderr).try_init()
}
