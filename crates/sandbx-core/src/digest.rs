//! The SHA-256 of a binary, as an operator writes it and as the helper checks it.
//!
//! Bytes rather than a hex `String`, so a comparison cannot be decided by letter case or by
//! a stray space. Parsing is the only way in, which leaves the 32-byte length to the type.
//! What uses one: a pinned entry point, in `helper`.

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

    /// Hash an already-open file. Takes the handle and never a path: the caller hashes and
    /// then runs this descriptor, and re-opening by path between the two is the swap the pin
    /// exists to catch. Reads from wherever the handle is positioned, so it is `&mut`.
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

/// Open `program`, and hand back the descriptor only if its bytes are `expected`. The
/// handle and not the path is what gets exec'd, so nothing resolves a second time for a
/// swap to land in. Keep it alive until after the `exec` — closing it un-names [`fd_path`].
/// Follows symlinks, unlike `fs_guard`'s `open`, since `execve` follows them too
/// (`context/decision-helper-audit-channel.md`).
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

/// Would the kernel hand this image to an interpreter rather than run it? `binfmt_script`
/// substitutes the path sandbx exec'd for the script's own, and that path names a
/// descriptor closed by then — so the interpreter cannot open it.
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
/// Landlock dereferences this magic link, so the exec is still checked against the real
/// path and a pinned run needs no grant on `/proc`.
pub(crate) fn fd_path(file: &std::fs::File) -> std::path::PathBuf {
    use std::os::fd::{AsFd, AsRawFd};

    std::path::PathBuf::from(format!("/proc/self/fd/{}", file.as_fd().as_raw_fd()))
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// Why a string is not a digest. Two cases and not one, because the advice differs: a
/// wrong length usually means a truncated copy-paste, a bad character means the wrong
/// tool's output.
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
#[path = "digest_tests.rs"]
mod tests;
