//! Printing the digest `--pin-sha256` takes.
//!
//! The one subcommand that confines nothing: it reads a file in the harness, the way
//! `sha256sum` does, because a pin has to be taken *before* there is a policy to take it
//! under. Nothing it reads crosses into a sandbox.

use std::path::PathBuf;

use sandbx_core::Sha256Digest;

/// A parsed `sandbx hash` invocation.
#[derive(Debug, clap::Args)]
pub struct Hash {
    /// The file to hash.
    #[arg(value_name = "PATH")]
    path: PathBuf,
}

impl Hash {
    /// Print the digest and report the code to exit with.
    ///
    /// The hex and a newline, and nothing else, so `--pin-sha256 "$(sandbx hash …)"`
    /// composes without a `cut`.
    pub fn execute(&self) -> Result<i32, HashError> {
        let mut file = std::fs::File::open(&self.path).map_err(|source| HashError {
            path: self.path.clone(),
            source,
        })?;

        let digest = Sha256Digest::of_file(&mut file).map_err(|source| HashError {
            path: self.path.clone(),
            source,
        })?;

        println!("{digest}");
        Ok(0)
    }
}

/// Why no digest was printed.
///
/// One variant: a path that cannot be opened and one that cannot be read through are the
/// same answer to the operator, and the errno distinguishes them.
#[derive(Debug)]
pub struct HashError {
    /// The file as it was named.
    path: PathBuf,
    /// The underlying OS failure.
    source: std::io::Error,
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "could not hash {}: {}", self.path.display(), self.source)
    }
}

impl std::error::Error for HashError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
