//! The SHA-256 of a binary, as an operator writes it and as the helper checks it.
//!
//! Bytes rather than a hex `String`, so a comparison cannot be decided by letter case or
//! by a stray space. Parsing is the only way in, which leaves the 32-byte length to the
//! type rather than to each caller. What uses one: a pinned entry point, in `helper`.

use std::fmt;

/// How many hex characters spell one.
const HEX_LEN: usize = 64;

/// How much of a file is hashed at a time.
///
/// A binary is read whole and discarded, so this trades only syscall count against a
/// stack frame; nothing here holds the file in memory.
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
        if hex.len() != HEX_LEN {
            return Err(DigestParseError::Length { found: hex.len() });
        }

        let mut bytes = [0u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
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
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }

        Ok(Self(hasher.finalize().into()))
    }
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
}
