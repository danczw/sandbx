use std::collections::HashSet;
use std::thread;

use super::SpawnId;

/// How many threads and mints each the concurrency case uses.
const THREADS: usize = 8;
const PER_THREAD: usize = 64;

/// The nonce half of an id: everything ahead of the counter.
fn nonce(id: &SpawnId) -> &str {
    id.as_str()
        .rsplit_once('.')
        .unwrap_or_else(|| panic!("an id carries no counter: {}", id.as_str()))
        .0
}

/// The counter half, as the number a reader of the trail sees.
fn counter(id: &SpawnId) -> u64 {
    let tail = id
        .as_str()
        .rsplit_once('.')
        .unwrap_or_else(|| panic!("an id carries no counter: {}", id.as_str()))
        .1;

    tail.parse()
        .unwrap_or_else(|_| panic!("the counter is not a number: {tail}"))
}

#[test]
fn concurrent_mints_are_distinct_in_a_process() {
    let handles: Vec<_> = (0..THREADS)
        .map(|_| thread::spawn(|| (0..PER_THREAD).map(|_| SpawnId::next()).collect::<Vec<_>>()))
        .collect();

    let minted: Vec<SpawnId> = handles
        .into_iter()
        .flat_map(|handle| handle.join().expect("a minting thread should not panic"))
        .collect();

    // Ahead of the set below, which a lost thread's mints would make trivially distinct.
    assert_eq!(
        minted.len(),
        THREADS * PER_THREAD,
        "a thread's mints were lost, so the set below proves nothing"
    );

    let distinct: HashSet<&str> = minted.iter().map(SpawnId::as_str).collect();
    assert_eq!(
        distinct.len(),
        THREADS * PER_THREAD,
        "two threads were handed one id, so a trail cannot tell their runs apart"
    );
}

/// The `OnceLock`'s only test. Re-derived per mint, the nonce would carry the identity and
/// the counter would be dead weight — every id still distinct, and nothing else noticing.
#[test]
fn one_process_mints_under_one_nonce() {
    let minted: Vec<SpawnId> = (0..THREADS * PER_THREAD).map(|_| SpawnId::next()).collect();

    let nonces: HashSet<&str> = minted.iter().map(nonce).collect();
    assert_eq!(
        nonces.len(),
        1,
        "one process minted under {} nonces: {nonces:?}",
        nonces.len()
    );
}

/// No absolute value: `cargo test` runs every test in this crate in one process, so
/// `SPAWNS` is shared and the first mint here is not the process's first.
#[test]
fn the_counter_advances_across_mints() {
    let first = counter(&SpawnId::next());
    let second = counter(&SpawnId::next());
    let third = counter(&SpawnId::next());

    assert!(
        first < second && second < third,
        "the counter did not advance: {first}, {second}, {third}"
    );
}
