//! Exercises the real Anthropic API over the network.
//!
//! Excluded from the default `cargo test` run and deliberately from CI: it
//! costs real money and needs a live `ANTHROPIC_API_KEY` as a secret. Gated
//! behind a Cargo feature — matching `sandbox-integration`'s pattern in
//! sandbx-core/sandbx-tools — rather than a runtime env-var check, so without
//! the feature `cargo test` reports zero tests here instead of a
//! silently-passing no-op hidden behind a green check.
//!
//! Run manually: `cargo test -p sandbx-providers --features live-anthropic-tests`
#![cfg(feature = "live-anthropic-tests")]

use futures_util::StreamExt;
use sandbx_providers::{AnthropicClient, ContentBlock, MessagesRequest, RequestMessage, Role};

#[tokio::test]
async fn streams_a_real_response_from_the_anthropic_api() {
    let client = AnthropicClient::from_env()
        .expect("ANTHROPIC_API_KEY must be set to run live-anthropic-tests");

    let request = MessagesRequest {
        model: "claude-opus-5".to_string(),
        // Generous on purpose: `max_tokens` also has to cover whatever thinking
        // the model does first. At 64 a turn can spend the whole budget before
        // emitting any text and fail `saw_text` as a flake, not a regression.
        max_tokens: 1024,
        system: None,
        messages: vec![RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "Reply with exactly the word: pong".to_string(),
            }],
        }],
        tools: vec![],
    };

    let events: Vec<_> = client
        .stream_chat(request)
        .await
        .expect("the request must reach the real API")
        .collect()
        .await;

    let mut saw_text = false;
    let mut saw_stop = false;
    for event in events {
        match event.expect("every event from a real turn must parse") {
            sandbx_providers::AgentEvent::Text { .. } => saw_text = true,
            sandbx_providers::AgentEvent::Stop { .. } => saw_stop = true,
            _ => {}
        }
    }

    assert!(
        saw_text,
        "expected at least one Text event from a real turn"
    );
    assert!(saw_stop, "expected the turn to reach a Stop event");
}
