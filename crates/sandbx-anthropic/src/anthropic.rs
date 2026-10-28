//! The Anthropic Messages API, and the only place in the crate that knows its
//! field names: [`client`] makes the request, [`body`] is what is serialised into
//! it, [`wire`] is what comes back.

mod body;
mod client;
mod wire;

pub use client::AnthropicClient;
