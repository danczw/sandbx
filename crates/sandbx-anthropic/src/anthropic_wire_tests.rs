//! Unit tests for the wire layer, grouped by what a turn is doing: [`usage`],
//! [`tool_use`], [`content`], [`lifecycle`]. Their shared frames live in [`fixture`].
//!
//! All drive [`event_stream`](super::event_stream) over a canned frame sequence rather
//! than a `Raw*` type, so they pin what the caller sees; unit tests because it is
//! `pub(crate)`.

#[path = "anthropic_wire_tests_content.rs"]
mod content;
#[path = "anthropic_wire_tests_fixture.rs"]
mod fixture;
#[path = "anthropic_wire_tests_lifecycle.rs"]
mod lifecycle;
#[path = "anthropic_wire_tests_tool_use.rs"]
mod tool_use;
#[path = "anthropic_wire_tests_usage.rs"]
mod usage;
