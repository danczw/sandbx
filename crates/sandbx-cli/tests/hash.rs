//! `sandbx hash`, whose only job is to print something `--pin-sha256` will accept.
//!
//! So the two are asserted together, over the real binary's stdout: a digest this prints
//! and the flag refuses would be a subcommand that reads correctly and composes with
//! nothing.
// The `Command::new` below runs sandbx itself to read what it wrote to stdout; the
// workspace ban exists to stop code executing *around* the sandbox.
#![allow(clippy::disallowed_methods)]

use clap::Parser;
use sandbx_cli::{Cli, Command};

fn hash(argv: &[&str]) -> sandbx_cli::Hash {
    match Cli::parse_from(argv).command {
        Command::Hash(args) => args,
        other => panic!("{other:?} is not hash"),
    }
}

/// What the subcommand wrote to stdout, and the digest the library takes for the same
/// bytes.
fn printed(contents: &[u8]) -> (String, sandbx_core::Sha256Digest) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("program");
    std::fs::write(&path, contents).expect("write");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sandbx"))
        .args(["hash", path.to_str().unwrap()])
        .output()
        .expect("sandbx should run");

    assert!(
        output.status.success(),
        "hashing a readable file failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut file = std::fs::File::open(&path).expect("reopen");
    let digest = sandbx_core::Sha256Digest::of_file(&mut file).expect("hash");

    (String::from_utf8(output.stdout).expect("utf-8"), digest)
}

/// The exact bytes: a prefix, a different case or a second field all break
/// `--pin-sha256 "$(sandbx hash …)"` while leaving a laxer assertion green.
#[test]
fn the_printed_digest_is_the_one_the_flag_accepts() {
    let (stdout, digest) = printed(b"pinned bytes");

    assert_eq!(stdout, format!("{digest}\n"));
    assert_eq!(
        sandbx_core::Sha256Digest::parse(stdout.trim_end()).expect("the printed form"),
        digest
    );
}

#[test]
fn a_file_that_cannot_be_read_is_reported_not_hashed() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let missing = dir.path().join("not-here");

    let error = hash(&["sandbx", "hash", missing.to_str().unwrap()])
        .execute()
        .expect_err("a missing file produced a digest");

    assert!(
        error.to_string().contains("not-here"),
        "the refusal did not name the file: {error}"
    );
}
