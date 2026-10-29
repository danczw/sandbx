//! Printing the digest `--pin-sha256` takes.
//!
//! The one subcommand that confines nothing: it reads a file in the harness, the way
//! `sha256sum` does, because a pin has to be taken before there is a policy to take it
//! under.

use std::fs::File;
use std::io;
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
        use std::io::Write;

        let digest = File::open(&self.path)
            .and_then(|mut file| Sha256Digest::of_file(&mut file))
            .map_err(|source| HashError {
                path: self.path.clone(),
                source,
            })?;

        // Not `println!`, which panics on a closed stdout with `SIGPIPE` ignored: dropped
        // the way `SandboxRun::execute` drops its own write failures.
        let _ = io::stdout().write_all(format!("{digest}\n").as_bytes());

        Ok(0)
    }
}
