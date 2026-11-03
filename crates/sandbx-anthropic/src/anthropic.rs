//! The Anthropic Messages API, and the only place in the crate that knows its
//! field names: [`anthropic_client`] makes the request, [`body`] is what is serialised into
//! it, [`wire`] is what comes back.

#[path = "anthropic_client.rs"]
mod anthropic_client;
#[path = "body.rs"]
mod body;
#[path = "anthropic_wire.rs"]
mod wire;

pub use anthropic_client::AnthropicClient;
