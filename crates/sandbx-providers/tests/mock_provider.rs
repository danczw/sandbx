//! Public contract of [`MockProvider`].
//!
//! Deliberately kept out of any shared abstraction over the backends — see its
//! doc comment — so the agent loop is generic over the stream shape
//! (`EventStream`), never over which type produced it. These tests exercise it
//! that way.

use futures_util::StreamExt;
use sandbx_providers::{AgentEvent, MessagesRequest, MockProvider, ProviderError, StopReason};

fn a_request() -> MessagesRequest {
    MessagesRequest {
        model: "claude-opus-5".to_string(),
        max_tokens: 100,
        system: None,
        messages: vec![],
        tools: vec![],
    }
}

#[tokio::test]
async fn replays_events_in_order() {
    let provider = MockProvider::new(vec![
        AgentEvent::Text {
            delta: "Hello".to_string(),
        },
        AgentEvent::Stop {
            reason: StopReason::EndTurn,
        },
    ]);

    let events: Vec<AgentEvent> = provider
        .stream_chat(a_request())
        .await
        .unwrap()
        .map(|event| event.expect("MockProvider::new never injects an error"))
        .collect()
        .await;

    assert_eq!(
        events,
        vec![
            AgentEvent::Text {
                delta: "Hello".to_string()
            },
            AgentEvent::Stop {
                reason: StopReason::EndTurn
            },
        ]
    );
}

#[tokio::test]
async fn an_empty_sequence_yields_no_events() {
    let provider = MockProvider::new(vec![]);

    let events: Vec<_> = provider
        .stream_chat(a_request())
        .await
        .unwrap()
        .collect()
        .await;

    assert!(events.is_empty());
}

/// The negative-path constructor: a caller testing a provider that fails
/// partway through a turn needs the error at a specific point, not merely an
/// all-success sequence.
#[tokio::test]
async fn with_results_can_inject_a_terminal_error() {
    let provider = MockProvider::with_results(vec![
        Ok(AgentEvent::Text {
            delta: "partial".to_string(),
        }),
        Err(ProviderError::StreamEndedUnexpectedly),
    ]);

    let results: Vec<_> = provider
        .stream_chat(a_request())
        .await
        .unwrap()
        .collect()
        .await;

    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok());
    assert!(matches!(
        results[1],
        Err(ProviderError::StreamEndedUnexpectedly)
    ));
}
