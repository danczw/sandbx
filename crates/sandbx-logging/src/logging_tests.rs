use std::io::Write;
use std::sync::Mutex;

use super::{Audit, HELD, UNPOISONED, hold};

/// Serialises these tests: `HELD` is process-global, so two at once would read each
/// other's records.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn buffered() -> Option<Vec<u8>> {
    HELD.lock().expect(UNPOISONED).clone()
}

#[test]
fn a_hold_buffers_the_trail_and_releases_it_once() {
    let _guard = ONE_AT_A_TIME
        .lock()
        .expect("a test that panicked here already failed");

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
