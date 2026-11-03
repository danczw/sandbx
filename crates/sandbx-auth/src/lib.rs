//! `auth`: where the provider key comes from when it is not in the environment.
//!
//! Environment first, then a file at `0600` in a directory at `0700`, refused rather than
//! read when either is wider. `login` takes the key on stdin and refuses a tty. See
//! `context/decision-credentials.md`. No workspace dependency, so nothing it reaches could
//! widen what it writes.
//!
//! `key` is the resolution and the subcommand; `store` is the file itself; `auth_error` is
//! what stops either. Not links: all three are private, and `private_intra_doc_links` fails
//! the `-D warnings` doc gate.

mod auth_error;
mod key;
mod store;

pub use auth_error::AuthError;
pub use key::Auth;

pub use key::{ENV_VAR, api_key, config_file};
