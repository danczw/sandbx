//! `auth`: where the provider key comes from when it is not in the environment.
//!
//! Environment first, then a file at `0600` in a directory at `0700`, refused rather than
//! read when either is wider. `login` takes the key on stdin and refuses a tty. See
//! `context/decision-credentials.md`.
//!
//! [`key`] is the resolution and the subcommand; [`store`] is the file itself.

mod key;
mod store;

pub use key::Auth;

pub(crate) use key::{ENV_VAR, api_key, config_file};
