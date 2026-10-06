//! The SHA-256 of a binary, as an operator writes it and as the helper checks it.
//!
//! Bytes rather than a hex `String`, so a comparison cannot be decided by letter case or
//! by a stray space. Parsing is the only way in, which leaves the 32-byte length to the
//! type rather than to each caller. What uses one: a pinned entry point, in `helper`.

use std::fmt;

/// How many hex characters spell one.
const HEX_LEN: usize = 64;

/// How much of a file is hashed at a time, as a stack buffer — nothing holds the file.
const CHUNK: usize = 64 * 1024;

/// A SHA-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Parse the 64 hex characters an operator writes, or say why they are not a digest.
    ///
    /// Rejects uppercase rather than folding it: [`fmt::Display`] emits lowercase, so
    /// accepting both would mean two spellings of one digest in the audit trail.
    pub fn parse(hex: &str) -> Result<Self, DigestParseError> {
        // Characters and not bytes, because that is what the refusal says it counted: a
        // digest pasted with a non-breaking space is 65 characters and 66 bytes.
        let found = hex.chars().count();
        if found != HEX_LEN {
            return Err(DigestParseError::Length { found });
        }

        let mut bytes = [0u8; 32];
        let (pairs, _) = hex.as_bytes().as_chunks::<2>();
        for (byte, pair) in bytes.iter_mut().zip(pairs) {
            let (high, low) = (nibble(pair[0])?, nibble(pair[1])?);
            *byte = high << 4 | low;
        }

        Ok(Self(bytes))
    }

    /// Hash an already-open file.
    ///
    /// Takes the handle and never a path: the caller hashes and then runs *this*
    /// descriptor, and re-opening by path between the two is the swap the pin exists to
    /// catch. Reads from wherever the handle is positioned, so it is `&mut`.
    pub fn of_file(file: &mut std::fs::File) -> std::io::Result<Self> {
        use sha2::Digest as _;
        use std::io::Read as _;

        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0u8; CHUNK];

        loop {
            let read = match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                // A signal between chunks is not a different file; std does not retry.
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            hasher.update(&buffer[..read]);
        }

        Ok(Self(hasher.finalize().into()))
    }
}

/// Open `program`, and hand back the descriptor only if its bytes are `expected`.
///
/// The returned handle is the whole point: it, and not the path, is what gets exec'd, so
/// there is no second resolution between the check and the run for the file to be swapped
/// in. Keep it alive until after the `exec` — closing it un-names [`fd_path`].
///
/// Follows symlinks, unlike `fs_guard`'s `open`: `execve` follows them too, and the swap
/// is closed by holding the inode. See `context/decision-pinned-entry-point.md`.
pub(crate) fn open_verified(
    program: &str,
    expected: Sha256Digest,
) -> Result<std::fs::File, crate::SandboxError> {
    let unreadable = |source| crate::SandboxError::PinUnreadable {
        program: program.to_string(),
        source,
    };

    let mut file = std::fs::File::open(program).map_err(unreadable)?;

    let actual = Sha256Digest::of_file(&mut file).map_err(unreadable)?;

    if actual != expected {
        return Err(crate::SandboxError::PinMismatch {
            program: program.to_string(),
            expected,
            actual,
        });
    }

    // After the digest, so bytes that were never the pinned ones report the mismatch; a
    // script is the narrower refusal and only reachable once the image is the right one.
    if starts_with_shebang(&mut file).map_err(unreadable)? {
        return Err(crate::SandboxError::PinnedScript {
            program: program.to_string(),
        });
    }

    Ok(file)
}

/// Would the kernel hand this image to an interpreter rather than run it?
///
/// `binfmt_script` substitutes the path sandbx exec'd for the script's own, and that path
/// names a descriptor closed by then — so the interpreter cannot open it.
fn starts_with_shebang(file: &mut std::fs::File) -> std::io::Result<bool> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    file.seek(SeekFrom::Start(0))?;

    let mut magic = [0u8; 2];
    let mut read = 0;
    while read < magic.len() {
        match file.read(&mut magic[read..]) {
            Ok(0) => return Ok(false),
            Ok(n) => read += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    Ok(&magic == b"#!")
}

/// The path that execs `file` itself rather than whatever its name now points at.
///
/// Landlock dereferences this magic link, so the exec is still checked against the real
/// path and a pinned run needs no grant on `/proc`.
pub(crate) fn fd_path(file: &std::fs::File) -> std::path::PathBuf {
    use std::os::fd::{AsFd, AsRawFd};

    std::path::PathBuf::from(format!("/proc/self/fd/{}", file.as_fd().as_raw_fd()))
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Why a string is not a digest.
///
/// Two cases and not one, because the advice differs: a wrong length usually means a
/// truncated copy-paste, a bad character means the wrong tool's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestParseError {
    /// Not 64 characters long.
    Length {
        /// How many characters were given.
        found: usize,
    },
    /// Contains something other than `0-9a-f`.
    Character {
        /// The offending byte.
        found: u8,
    },
}

impl fmt::Display for DigestParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { found } => write!(
                f,
                "a SHA-256 digest is {HEX_LEN} hex characters, and this one is {found}"
            ),
            Self::Character { found } => write!(
                f,
                "a SHA-256 digest is lowercase hex, and this one contains `{}`",
                char::from(*found).escape_debug()
            ),
        }
    }
}

impl std::error::Error for DigestParseError {}

/// One hex character's value.
fn nibble(byte: u8) -> Result<u8, DigestParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        found => Err(DigestParseError::Character { found }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut file = tempfile::NamedTempFile::new().expect("a temporary file");
        std::io::Write::write_all(&mut file, b"abc").expect("write");

        let mut handle = std::fs::File::open(file.path()).expect("reopen");
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
        let hash = |bytes: &[u8]| {
            let mut file = tempfile::NamedTempFile::new().expect("a temporary file");
            std::io::Write::write_all(&mut file, bytes).expect("write");
            let mut handle = std::fs::File::open(file.path()).expect("reopen");
            Sha256Digest::of_file(&mut handle).expect("hash")
        };

        assert_eq!(hash(b"same"), hash(b"same"));
        assert_ne!(hash(b"same"), hash(b"other"));
    }

    /// More than one `CHUNK`, so a file read in several passes hashes as one stream.
    #[test]
    fn a_file_larger_than_one_chunk_hashes_as_one_stream() {
        let bytes = vec![b'x'; CHUNK * 2 + 1];

        let mut file = tempfile::NamedTempFile::new().expect("a temporary file");
        std::io::Write::write_all(&mut file, &bytes).expect("write");
        let mut handle = std::fs::File::open(file.path()).expect("reopen");

        let streamed = Sha256Digest::of_file(&mut handle).expect("hash");

        use sha2::Digest as _;
        let at_once: [u8; 32] = sha2::Sha256::digest(&bytes).into();

        assert_eq!(streamed, Sha256Digest(at_once));
    }

    /// A file, and the digest a pin on it would be checked against.
    fn written(contents: &[u8]) -> (tempfile::TempDir, std::path::PathBuf, Sha256Digest) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("program");
        std::fs::write(&path, contents).expect("write");

        let mut file = std::fs::File::open(&path).expect("reopen");
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
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("swap");

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
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o111)).expect("chmod");

        // Both branches assert: root reads a mode-111 file, and skipping there would report
        // `ok` for a mapping this never exercised.
        let readable = std::fs::File::open(&path).is_ok();
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
}
