use super::{Audit, HELD, hold};
use std::io::Write;
use std::panic;
use std::sync::{Mutex, PoisonError};

/// Serialises these tests: `HELD` is process-global, so two at once would read each
/// other's records.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Whatever `HELD` holds now, without panicking on a lock a test poisoned on purpose.
fn buffered() -> Option<Vec<u8>> {
    HELD.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

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

/// The trail is not opt-in, so a poisoned lock must not drop a record.
#[test]
fn a_poisoned_lock_still_takes_a_record() {
    let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);

    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let panicked = panic::catch_unwind(|| {
        let _poison = HELD.lock().unwrap_or_else(PoisonError::into_inner);
        panic!("poison it");
    });
    panic::set_hook(hook);

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
