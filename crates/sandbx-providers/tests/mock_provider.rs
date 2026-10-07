//! Public contract of [`MockProvider`]: the agent loop is generic over the stream
//! shape, `EventStream`, never over which type produced it.

use futures_util::StreamExt;
use sandbx_providers::{AgentEvent, MockProvider, Prompt, ProviderError, StopReason};

fn a_request() -> Prompt {
    Prompt {
        model: "claude-opus-5".to_string(),
        max_output_tokens: 100,
        system: None,
        messages: vec![],
        tools: vec![],
        tool_choice: None,
        thinking: None,
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

/// The negative-path constructor: an error at a chosen point in the sequence.
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
