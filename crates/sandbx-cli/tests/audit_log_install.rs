//! Installing the subscriber, which can only happen once per process.
//!
//! This file holds exactly one test and must keep holding exactly one: cargo gives each
//! `tests/*.rs` its own binary, and the property below is about the process-global
//! dispatcher, so a second test here would race it.

#[test]
fn a_second_install_is_reported_rather_than_panicking() {
    assert!(
        sandbx_cli::logging::init().is_ok(),
        "the first install in a process must succeed"
    );
    assert!(
        sandbx_cli::logging::init().is_err(),
        "a second install must report, not panic or silently replace the first"
    );
}
