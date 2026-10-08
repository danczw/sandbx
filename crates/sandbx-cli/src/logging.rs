//! The one `tracing` subscriber the `sandbx` binary installs.
//!
//! `sandbx-core` emits an audit trail on `AUDIT_TARGET`, but `tracing` drops every event
//! when no subscriber is installed, and a library cannot install one for its embedder.
//! Not configurable: the audit trail is not opt-in diagnostics.

use std::io::{self, Write};
use std::sync::{Mutex, PoisonError};

use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// The subscriber the binary installs, writing to `writer`.
///
/// Generic over its writer so a test can drive the real subscriber over an in-memory
/// sink. Admits `AUDIT_TARGET` at `INFO` and nothing else, both halves load-bearing: the
/// target keeps `sandbx-core`'s own `debug!` out, the level keeps out anything below
/// `INFO` that borrowed the target. `impl SubscriberInitExt` keeps `tracing` a
/// dev-dependency.
pub fn subscriber<W>(writer: W) -> impl SubscriberInitExt
where
    W: for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> + Send + Sync + 'static,
{
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                // Forced off: the default keys off the `ansi` feature, which
                // `cargo test --workspace` unifies on through a dev-dependency. This
                // stream gets grepped.
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
/// would corrupt whatever is piping it. `try_init` because losing the audit trail is
/// worth reporting but still leaves a process that can sandbox a command.
pub fn init() -> Result<(), tracing_subscriber::util::TryInitError> {
    subscriber(Audit).try_init()
}

/// The records written while a screen owned the terminal, or `None` while stderr is clear.
///
/// Process-global because the subscriber is: `tracing` takes one for the whole process,
/// installed before the subcommand is known, so where its writer goes cannot be an
/// argument to it.
static HELD: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// Where a record goes: stderr, unless [`hold`] is in force.
#[derive(Clone, Copy)]
pub struct Audit;

impl Write for Audit {
    /// A held record is buffered whole; otherwise stderr takes it.
    ///
    /// A poisoned lock writes to stderr rather than dropping the record: the trail is the
    /// one output that is not opt-in, so a corrupted screen is the lesser loss.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut held = HELD.lock().unwrap_or_else(PoisonError::into_inner);

        match held.as_mut() {
            Some(held) => {
                held.extend_from_slice(buf);
                Ok(buf.len())
            }
            None => io::stderr().write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

impl tracing_subscriber::fmt::MakeWriter<'_> for Audit {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        *self
    }
}

/// Buffer the audit trail until the returned guard drops.
///
/// For a subcommand that draws on the alternate screen: that screen does not redirect
/// stderr, so a record written during the turn lands in the pane — corrupting it, since
/// ratatui flushes only the cells that differ from its own last buffer — and is then lost
/// with the screen. README's claim that every run records its trail on stderr is what this
/// keeps true.
///
/// Reentrant only in the sense that a second `hold` would discard the first's records, so
/// there is one caller.
pub fn hold() -> Held {
    *HELD.lock().unwrap_or_else(PoisonError::into_inner) = Some(Vec::new());
    Held
}

/// Releases the held audit trail onto stderr when it drops.
pub struct Held;

impl Drop for Held {
    /// `Drop` and not a method: a panic unwinding past the screen must still leave the
    /// trail behind it, that being the record of what the turn was allowed to touch.
    fn drop(&mut self) {
        let records = HELD
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .unwrap_or_default();

        // Ignored: there is nowhere left to report a stderr that stopped taking writes,
        // and this runs on an unwinding path as well as a returning one.
        let _ = io::stderr().write_all(&records);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the tests below: `HELD` is process-global, so two at once would each
    /// read the other's records.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    /// Whatever `HELD` holds now, without panicking on a lock a test poisoned on purpose.
    fn buffered() -> Option<Vec<u8>> {
        HELD.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Held, the records accumulate; released, they are gone from the buffer, which is what
    /// puts them on stderr exactly once.
    #[test]
    fn a_hold_buffers_the_trail_and_releases_it_once() {
        let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);

        // Non-vacuous: with no hold in force the writer buffers nothing, so the records
        // below are held because `hold` was called and not because every write is.
        Audit.write_all(b"before\n").expect("stderr");
        assert_eq!(buffered(), None);

        let held = hold();
        Audit.write_all(b"decision=\"allowed\"\n").expect("held");
        Audit.write_all(b"decision=\"exited\"\n").expect("held");
        assert_eq!(
            buffered().as_deref(),
            Some(&b"decision=\"allowed\"\ndecision=\"exited\"\n"[..])
        );

        drop(held);
        assert_eq!(buffered(), None);
    }

    /// The trail is the one output that is not opt-in, so a lock a panic poisoned must not
    /// turn a record into a dropped one.
    #[test]
    fn a_poisoned_lock_still_takes_a_record() {
        let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);

        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let panicked = std::panic::catch_unwind(|| {
            let _poison = HELD.lock().unwrap_or_else(PoisonError::into_inner);
            panic!("poison it");
        });
        std::panic::set_hook(hook);

        assert!(panicked.is_err(), "the panic did not reach the lock");
        assert!(HELD.is_poisoned(), "the lock was not poisoned");

        let held = hold();
        Audit.write_all(b"decision=\"denied\"\n").expect("held");
        assert_eq!(buffered().as_deref(), Some(&b"decision=\"denied\"\n"[..]));
        drop(held);

        // Put back for whichever test runs next: poison is permanent otherwise, and the
        // other test would then be asserting this one's state.
        HELD.clear_poison();
    }
}
