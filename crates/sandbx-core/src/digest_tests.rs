use super::{CHUNK, DigestParseError, HEX_LEN, Sha256Digest, fd_path, open_verified};
use std::fs;
use std::fs::{File, Permissions};
use std::path::PathBuf;

/// The empty-input vector from FIPS 180-4, which also fixes the byte order `Display`
/// emits — a digest reversed would still round-trip through `parse`.
const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[test]
fn parses_and_renders_the_empty_vector() {
    let digest = Sha256Digest::parse(EMPTY).expect("64 lowercase hex characters");

    assert_eq!(digest.to_string(), EMPTY);
}

#[test]
fn hashes_a_file_to_the_known_vector() {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new().expect("a temporary file");
    file.write_all(b"abc").expect("write");

    let mut handle = File::open(file.path()).expect("reopen");
    let digest = Sha256Digest::of_file(&mut handle).expect("hash");

    // The "abc" vector from FIPS 180-4.
    assert_eq!(
        digest.to_string(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn a_digest_one_character_short_or_long_is_refused() {
    for hex in [&EMPTY[..HEX_LEN - 1], &format!("{EMPTY}0")[..]] {
        let error = Sha256Digest::parse(hex).expect_err("not 64 characters");

        assert!(
            matches!(error, DigestParseError::Length { .. }),
            "{hex:?} should be refused for its length, not as {error:?}"
        );
    }
}

#[test]
fn a_digest_that_is_not_lowercase_hex_is_refused() {
    // Uppercase among them: `Display` emits lowercase, so folding case would put two
    // spellings of one digest on the trail.
    for hex in ["z", "E", " ", "-"] {
        let candidate = format!("{hex}{}", &EMPTY[1..]);
        let error = Sha256Digest::parse(&candidate).expect_err("not lowercase hex");

        assert!(
            matches!(error, DigestParseError::Character { .. }),
            "{candidate:?} should be refused for its characters, not as {error:?}"
        );
    }
}

#[test]
fn two_files_with_the_same_bytes_hash_alike_and_differ_otherwise() {
    use std::io::Write;
    let hash = |bytes: &[u8]| {
        let mut file = tempfile::NamedTempFile::new().expect("a temporary file");
        file.write_all(bytes).expect("write");
        let mut handle = File::open(file.path()).expect("reopen");
        Sha256Digest::of_file(&mut handle).expect("hash")
    };

    assert_eq!(hash(b"same"), hash(b"same"));
    assert_ne!(hash(b"same"), hash(b"other"));
}

/// More than one `CHUNK`, so a file read in several passes hashes as one stream.
#[test]
fn a_file_larger_than_one_chunk_hashes_as_one_stream() {
    use std::io::Write;
    let bytes = vec![b'x'; CHUNK * 2 + 1];

    let mut file = tempfile::NamedTempFile::new().expect("a temporary file");
    file.write_all(&bytes).expect("write");
    let mut handle = File::open(file.path()).expect("reopen");

    let streamed = Sha256Digest::of_file(&mut handle).expect("hash");

    use sha2::Digest as _;
    let at_once: [u8; 32] = sha2::Sha256::digest(&bytes).into();

    assert_eq!(streamed, Sha256Digest(at_once));
}

/// A file, and the digest a pin on it would be checked against.
fn written(contents: &[u8]) -> (tempfile::TempDir, PathBuf, Sha256Digest) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("program");
    fs::write(&path, contents).expect("write");

    let mut file = File::open(&path).expect("reopen");
    let digest = Sha256Digest::of_file(&mut file).expect("hash");

    (dir, path, digest)
}

#[test]
fn a_matching_image_hands_back_a_descriptor() {
    let (_dir, path, digest) = written(b"\x7fELF not really, but not a script");

    let file = open_verified(path.to_str().unwrap(), digest).expect("the pinned bytes");

    assert!(
        fd_path(&file).starts_with("/proc/self/fd/"),
        "the descriptor was not named for exec: {:?}",
        fd_path(&file)
    );
}

#[test]
fn a_shebang_image_is_refused_rather_than_exec_d() {
    let (_dir, path, digest) = written(b"#!/bin/sh\nexit 0\n");

    let error = open_verified(path.to_str().unwrap(), digest).expect_err("a script ran");

    assert!(
        matches!(error, crate::SandboxError::PinnedScript { .. }),
        "a script was refused as something else: {error}"
    );
}

/// The pin is checked first, so bytes that were never the pinned ones report that and
/// not the narrower complaint about what they happen to be.
#[test]
fn a_swapped_script_reports_the_mismatch() {
    let (_dir, path, digest) = written(b"the pinned bytes");
    fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("swap");

    let error = open_verified(path.to_str().unwrap(), digest).expect_err("a swap ran");

    assert!(
        matches!(error, crate::SandboxError::PinMismatch { .. }),
        "a swapped image was refused as something else: {error}"
    );
}

/// Mode 111 runs unpinned and cannot be pinned, so the refusal has to name the missing
/// read rather than read as a program that could not be executed.
#[test]
fn an_unreadable_program_says_the_pin_needs_read() {
    use std::os::unix::fs::PermissionsExt as _;

    let (_dir, path, digest) = written(b"\x7fELF");
    fs::set_permissions(&path, Permissions::from_mode(0o111)).expect("chmod");

    // Both branches assert: root reads a mode-111 file, and skipping there would report
    // `ok` for a mapping this never exercised.
    let readable = File::open(&path).is_ok();
    let result = open_verified(path.to_str().unwrap(), digest);

    match readable {
        true => {
            result.expect("the bytes are the pinned ones, whoever may read them");
        }
        false => {
            let error = result.expect_err("an unreadable program was hashed");

            assert!(
                matches!(error, crate::SandboxError::PinUnreadable { .. }),
                "an unreadable program was refused as something else: {error}"
            );
            assert!(
                error.to_string().contains("needs read access"),
                "the refusal did not say what was missing: {error}"
            );
        }
    }
}
