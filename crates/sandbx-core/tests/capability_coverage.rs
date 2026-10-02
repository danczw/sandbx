//! Does the `caps` crate still know about every capability this kernel has?
//!
//! `caps::clear(Bounding)` issues one `PR_CAPBSET_DROP` per capability, enumerated
//! from a hardcoded list in the crate rather than from the running kernel — so a
//! capability the crate has never heard of stays in `CapBnd` while `SECURITY.md`
//! promises an empty set. Not behind `sandbox-integration`: it spawns nothing, so
//! it runs on hosts where the `CapBnd` assertion in `enforcement.rs` cannot.
#![cfg(target_os = "linux")]

/// The kernel's own answer for the highest capability it implements.
fn kernel_last_cap() -> u8 {
    // Present on every Linux since 2.6.25; absence is a broken test environment,
    // so fail loudly rather than skip and report a silent pass.
    let raw = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .expect("no /proc/sys/kernel/cap_last_cap — is /proc mounted?");

    raw.trim()
        .parse()
        .unwrap_or_else(|e| panic!("cap_last_cap was not a number: {raw:?} ({e})"))
}

#[test]
fn the_caps_crate_covers_every_capability_this_kernel_has() {
    let kernel_last = kernel_last_cap();
    let known_last = caps::all()
        .iter()
        .map(|cap| cap.index())
        .max()
        .expect("caps::all() should never be empty");

    assert!(
        known_last >= kernel_last,
        "this kernel implements capabilities up to index {kernel_last}, but the \
         `caps` crate only knows up to {known_last}. `caps::clear(Bounding)` \
         iterates its own hardcoded list, so indices {} to {kernel_last} are \
         never dropped from CapBnd and SECURITY.md now overstates what the \
         helper clears. Fix by bumping `caps` (or dropping the bounding set \
         against cap_last_cap directly), then update SECURITY.md if the gap was \
         real in a released version.",
        known_last + 1
    );
}
