//! The keys that interrupt a turn, and what a hangup means.
//!
//! Reads them off the terminal `sandbx-screen` took, on threads of its own because neither
//! `poll` nor crossterm's `event::read` can be cancelled. Nothing here draws, and nothing
//! here holds a policy, a provider, a session or a gate.

mod input;

pub use input::{Keys, Stopped};
