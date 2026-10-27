//! Exercises the real Anthropic API over the network.
//!
//! Costs real money and needs a live `ANTHROPIC_API_KEY`, so it is behind a Cargo
//! feature rather than a runtime env-var check: without the feature `cargo test`
//! reports zero tests here instead of a silently-passing no-op.
//!
//! Run manually: `cargo test -p sandbx-providers --features live-anthropic-tests`
#![cfg(feature = "live-anthropic-tests")]

use futures_util::StreamExt;
use sandbx_prompt::{ContentBlock, Prompt, RequestMessage, Role};
use sandbx_providers::AnthropicClient;

#[tokio::test]
async fn streams_a_real_response_from_the_anthropic_api() {
    // Blank counts as unset, as it does in the CLI: an empty key would only come back as
    // an opaque 401.
    let key = std::env::var("ANTHROPIC_API_KEY")
        .ok()
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
        .expect("a non-blank, UTF-8 ANTHROPIC_API_KEY must be set to run live-anthropic-tests");
    let client = AnthropicClient::new(secrecy::SecretString::from(key))
        .expect("a client is built without a network call");

    let request = Prompt {
        model: "claude-opus-5".to_string(),
        // Generous: the cap also covers whatever thinking the model does first, and a
        // small budget can be spent before any text is emitted.
        max_output_tokens: 1024,
        system: None,
        messages: vec![RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "Reply with exactly the word: pong".to_string(),
            }],
        }],
        tools: vec![],
        tool_choice: None,
        thinking: None,
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
            sandbx_event::AgentEvent::Text { .. } => saw_text = true,
            sandbx_event::AgentEvent::Stop { .. } => saw_stop = true,
            _ => {}
        }
    }

    assert!(
        saw_text,
        "expected at least one Text event from a real turn"
    );
    assert!(saw_stop, "expected the turn to reach a Stop event");
}
