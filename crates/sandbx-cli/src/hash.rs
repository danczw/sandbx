//! Printing the digest `--pin-sha256` takes.
//!
//! The one subcommand that confines nothing: it reads a file in the harness, the way
//! `sha256sum` does, because a pin has to be taken before there is a policy to take it
//! under.

use std::path::PathBuf;

use sandbx_core::Sha256Digest;

use crate::HashError;

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

        // Not `println!`, which panics on a closed stdout with `SIGPIPE` ignored: dropped
        // the way `SandboxRun::execute` drops its own write failures.
        let line = format!("{digest}\n");
        let _ = std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes());

        Ok(0)
    }
}
