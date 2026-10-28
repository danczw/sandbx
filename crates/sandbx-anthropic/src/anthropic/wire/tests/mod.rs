//! Unit tests for the wire layer, grouped by what a turn is doing: [`usage`],
//! [`tool_use`], [`content`], [`lifecycle`]. Their shared frames live in [`fixture`].
//!
//! All drive [`event_stream`](super::event_stream) over a canned frame sequence rather
//! than a `Raw*` type, so they pin what the caller sees; unit tests because it is
//! `pub(crate)`.

mod content;
mod fixture;
mod lifecycle;
mod tool_use;
mod usage;
