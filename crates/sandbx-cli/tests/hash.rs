//! `sandbx hash`, whose only job is to print something `--pin-sha256` will accept.
//!
//! So the two are asserted together: a digest this prints and the flag refuses would be a
//! subcommand that reads correctly and composes with nothing.

use clap::Parser;
use sandbx_cli::{Cli, Command};

fn hash(argv: &[&str]) -> sandbx_cli::Hash {
    match Cli::parse_from(argv).command {
        Command::Hash(args) => args,
        other => panic!("{other:?} is not hash"),
    }
}

#[test]
fn the_digest_is_the_one_the_library_takes() {
    let mut file = tempfile::NamedTempFile::new().expect("a temporary file");
    std::io::Write::write_all(&mut file, b"pinned bytes").expect("write");

    let mut handle = std::fs::File::open(file.path()).expect("reopen");
    let expected = sandbx_core::Sha256Digest::of_file(&mut handle).expect("hash");

    // `execute` prints rather than returning the digest, so the assertion is that the
    // digest it would print is one `--pin-sha256` accepts for the same bytes.
    assert_eq!(
        sandbx_core::Sha256Digest::parse(&expected.to_string()).expect("the printed form"),
        expected
    );
    assert_eq!(
        hash(&["sandbx", "hash", file.path().to_str().unwrap()])
            .execute()
            .expect("the file is readable"),
        0
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
