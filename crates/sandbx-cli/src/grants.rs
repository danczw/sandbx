//! The grant flags, and the policy they describe.
//!
//! Shared by every subcommand that runs something, so the axis loop, the one widening it
//! applies, and the working-directory default exist once rather than once per subcommand.
//! Deriving that default, and vetting what a flag names, is [`root`]; the flags themselves
//! and the loop over them are [`flags`].

mod flags;
mod root;

pub use flags::Grants;
