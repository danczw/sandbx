//! Exercises the real Anthropic API over the network.
//!
//! Excluded from the default `cargo test` run: it costs real money, needs a
//! live `ANTHROPIC_API_KEY`, and is not reproducible in CI without a secret.
//! Gated behind a Cargo feature — matching `sandbox-integration`'s pattern in
//! sandbx-core/sandbx-tools — rather than a runtime env-var check inside the
//! test body, so an accidental run without opting in fails to *compile* the
//! test binary at all instead of silently no-op'ing.
//!
//! Deliberately no CI job for this feature: it would need a paid API key as a
//! CI secret and spend money on every push. `ci.yml`'s `test` job comment
//! already anticipates this exclusion ("and any test gated on live LLM
//! credentials").
//!
//! Run manually: `cargo test -p sandbx-providers --features live-anthropic-tests`
#![cfg(feature = "live-anthropic-tests")]

use futures_util::StreamExt;
use sandbx_providers::{ContentBlock, MessagesRequest, Provider, RequestMessage, Role};

#[tokio::test]
async fn streams_a_real_response_from_the_anthropic_api() {
    let provider = Provider::anthropic_from_env()
        .expect("ANTHROPIC_API_KEY must be set to run live-anthropic-tests");

    let request = MessagesRequest {
        model: "claude-opus-5".to_string(),
        max_tokens: 64,
        system: None,
        messages: vec![RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "Reply with exactly the word: pong".to_string(),
            }],
        }],
        tools: vec![],
        stream: true,
    };

    let events: Vec<_> = provider
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
