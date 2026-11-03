//! What stops `sandbx hash`.

use std::path::PathBuf;
use std::{fmt, io};

/// Why `sandbx hash` printed no digest.
///
/// One field and no variants: a path that cannot be opened and one that cannot be read
/// through are the same answer to the operator, and the errno distinguishes them.
#[derive(Debug)]
pub struct HashError {
    pub(crate) path: PathBuf,
    pub(crate) source: io::Error,
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "could not hash {}: {}", self.path.display(), self.source)
    }
}

impl std::error::Error for HashError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
