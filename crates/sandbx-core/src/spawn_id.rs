//! A per-spawn correlation id, unique across processes and not merely within one.
//!
//! Two sandbx processes writing into one stderr sink is the case a bare counter loses:
//! both emit 1, 2, 3, so an interleaved trail pairs the wrong spawn with the wrong exit
//! while looking well-formed. The child's pid is no better — the kernel reuses it, on a
//! busy host within one log file's lifetime. So an id is a per-process nonce and a
//! counter, and the nonce is what the other process cannot reproduce (#249).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// What separates this process's ids from every other process's. Derived once.
static NONCE: OnceLock<String> = OnceLock::new();

/// How many runs this process has opened.
static SPAWNS: AtomicU64 = AtomicU64::new(0);

/// A spawn and its outcome, named by one value rather than by their position in the trail.
///
/// Spelled `{pid:x}.{nanos:x}.{counter}`. Unique because a pid names one process at any
/// instant, so two processes sharing a pid started at different instants and take different
/// nonces. The precondition is a clock that does not step backwards: moved back far enough
/// to reissue a `(pid, nanos)` pair to a reused pid, two processes collide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnId(String);

impl SpawnId {
    /// Open a new run. Never returns one value twice in a process.
    pub fn next() -> Self {
        let nonce = NONCE.get_or_init(|| {
            // Zero on a clock before the epoch, weakening the nonce to the pid alone
            // rather than refusing: a run that goes under-recorded beats one that does
            // not happen, which is `sandbx_logging::init`'s rule for the same trade.
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos());

            format!("{:x}.{nanos:x}", std::process::id())
        });

        // Relaxed: the property is that no two reads return one value, which `fetch_add`
        // gives at any ordering. Nothing reads this against another variable.
        Self(format!(
            "{nonce}.{}",
            SPAWNS.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// The id as it reaches the trail.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[path = "spawn_id_tests.rs"]
mod tests;
