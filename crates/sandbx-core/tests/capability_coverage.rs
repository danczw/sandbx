//! Does the `caps` crate still know about every capability this kernel has?
//!
//! `SECURITY.md` claims the helper leaves the sandboxed command with an empty
//! capability set. Four of the five sets are cleared with a single bitmask
//! write, so they cover whatever the kernel supports. The *bounding* set is
//! different: `caps::clear(Bounding)` has to issue one `PR_CAPBSET_DROP` per
//! capability, and it enumerates them from a **hardcoded list** in the crate
//! rather than from the running kernel.
//!
//! That makes the claim only as complete as a third-party constant. A kernel
//! that gains a capability the crate has never heard of would keep that bit in
//! `CapBnd` while the policy still promised an empty set — a documentation
//! defect in a file people rely on, which is the one kind this repo treats as a
//! security defect in its own right.
//!
//! So assert the invariant directly rather than waiting to notice. Deliberately
//! *not* behind `sandbox-integration`: it spawns nothing and needs no Landlock,
//! so it belongs in the suite that runs everywhere, including the hosts where
//! the `CapBnd` assertion in `enforcement.rs` cannot run at all.
#![cfg(target_os = "linux")]

/// The kernel's own answer for the highest capability it implements.
fn kernel_last_cap() -> u8 {
    // Present on every Linux since 2.6.25; its absence means something is wrong
    // with the test environment, not with the invariant, so fail loudly rather
    // than skip and report a silent pass.
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
