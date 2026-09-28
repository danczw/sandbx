//! Public contract of [`AnthropicClient`] and [`Provider`], exercised over
//! real HTTP against a local mock server — no live network access, no API key.

use futures_util::StreamExt;
use sandbx_providers::{
    AgentEvent, AnthropicClient, ContentBlock, MessagesRequest, Provider, ProviderError,
    RequestMessage, Role, StopReason,
};
use secrecy::SecretString;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client_for(server: &MockServer) -> AnthropicClient {
    AnthropicClient::new(SecretString::from("sk-ant-test".to_string()))
        .unwrap()
        .with_base_url(server.uri())
}

fn a_request() -> MessagesRequest {
    MessagesRequest {
        model: "claude-opus-5".to_string(),
        max_tokens: 1_000,
        system: None,
        messages: vec![RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "hi".to_string(),
            }],
        }],
        tools: vec![],
    }
}

/// The full happy-path SSE body a real turn produces, including a tool call
/// split across fragments — this is the same shape `wire.rs`'s unit tests
/// exercise in-process, now proven over a real HTTP round trip.
const FULL_TURN_SSE: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10}}}\n\n",
    "event: content_block_start\n",
    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Checking.\"}}\n\n",
    "event: content_block_stop\n",
    "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
    "event: content_block_start\n",
    "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01A\",\"name\":\"get_weather\"}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"loc\"}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"ation\\\":\\\"Paris\\\"}\"}}\n\n",
    "event: content_block_stop\n",
    "data: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
    "event: message_delta\n",
    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":8}}\n\n",
    "event: message_stop\n",
    "data: {\"type\":\"message_stop\"}\n\n",
);

#[tokio::test]
async fn sends_the_right_headers_and_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "sk-ant-test"))
        .and(header("anthropic-version", "2023-06-01"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(FULL_TURN_SSE, "text/event-stream"))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let stream = client.stream_chat(a_request()).await.unwrap();
    let _: Vec<_> = stream.collect().await;

    // wiremock's `.expect(1)` (verified on drop) is the real assertion that
    // the headers matched; reaching here without a panic confirms it.
}

#[tokio::test]
async fn a_full_turn_produces_the_expected_event_sequence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(FULL_TURN_SSE, "text/event-stream"))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let stream = client.stream_chat(a_request()).await.unwrap();
    let events: Vec<AgentEvent> = stream
        .map(|event| event.expect("every event in this fixture is well-formed"))
        .collect()
        .await;

    assert_eq!(
        events,
        vec![
            AgentEvent::Text {
                delta: "Checking.".to_string()
            },
            AgentEvent::ToolCallRequested {
                id: "toolu_01A".to_string(),
                name: "get_weather".to_string(),
                input: serde_json::json!({"location": "Paris"}),
            },
            AgentEvent::Usage {
                input_tokens: Some(10),
                output_tokens: Some(8),
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            AgentEvent::Stop {
                reason: StopReason::ToolUse
            },
        ]
    );
}

#[tokio::test]
async fn a_429_response_is_reported_as_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "2")
                .set_body_json(serde_json::json!({
                    "type": "error",
                    "error": {"type": "rate_limit_error", "message": "too many requests"}
                })),
        )
        .mount(&server)
        .await;

    let client = client_for(&server);
    let error = match client.stream_chat(a_request()).await {
        Ok(_) => panic!("a 429 must be reported before any stream item"),
        Err(error) => error,
    };

    match error {
        ProviderError::RateLimited {
            retry_after,
            message,
        } => {
            assert_eq!(retry_after, Some(std::time::Duration::from_secs(2)));
            assert_eq!(message, "too many requests");
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

#[tokio::test]
async fn a_400_response_is_reported_with_the_vendor_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "type": "error",
            "error": {"type": "invalid_request_error", "message": "model field is required"}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let error = match client.stream_chat(a_request()).await {
        Ok(_) => panic!("a 400 must be reported before any stream item"),
        Err(error) => error,
    };

    match error {
        ProviderError::ApiError {
            status,
            kind,
            message,
        } => {
            assert_eq!(status, Some(400));
            assert_eq!(kind, "invalid_request_error");
            assert_eq!(message, "model field is required");
        }
        other => panic!("expected ApiError, got {other:?}"),
    }
}

/// A mid-stream `error` event (no `message_stop`) must surface as an item in
/// the stream, not as the outer `Result` — by the time it arrives the
/// response was already a 200 and events were already flowing.
#[tokio::test]
async fn a_mid_stream_error_event_ends_the_stream_as_an_item() {
    let server = MockServer::start().await;
    let body = concat!(
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n",
        "event: error\n",
        "data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"overloaded\"}}\n\n",
    );
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/event-stream"))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let stream = client.stream_chat(a_request()).await.unwrap();
    let items: Vec<_> = stream.collect().await;

    assert_eq!(items.len(), 2);
    assert!(items[0].is_ok());
    match &items[1] {
        Err(ProviderError::ApiError { status, kind, .. }) => {
            assert_eq!(status, &None, "an in-band error carries no HTTP status");
            assert_eq!(kind, "overloaded_error");
        }
        other => panic!("expected ApiError, got {other:?}"),
    }
}

/// A connection that closes before `message_stop` — everything seen was
/// well-formed, but the turn never reached a defined end state.
#[tokio::test]
async fn a_connection_closed_before_message_stop_is_reported() {
    let server = MockServer::start().await;
    let body = "event: ping\ndata: {\"type\":\"ping\"}\n\n";
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/event-stream"))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let stream = client.stream_chat(a_request()).await.unwrap();
    let items: Vec<_> = stream.collect().await;

    assert_eq!(items.len(), 1);
    assert!(matches!(
        items[0],
        Err(ProviderError::StreamEndedUnexpectedly)
    ));
}

#[tokio::test]
async fn provider_enum_dispatches_to_the_anthropic_client() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(FULL_TURN_SSE, "text/event-stream"))
        .mount(&server)
        .await;

    let provider = Provider::Anthropic(client_for(&server));
    let stream = provider.stream_chat(a_request()).await.unwrap();
    let events: Vec<_> = stream.collect().await;

    assert_eq!(
        events.len(),
        4,
        "the same sequence as calling AnthropicClient directly"
    );
}

#[test]
fn the_client_does_not_leak_the_api_key_in_debug_output() {
    let client =
        AnthropicClient::new(SecretString::from("sk-ant-super-secret".to_string())).unwrap();

    let rendered = format!("{client:?}");

    assert!(
        !rendered.contains("sk-ant-super-secret"),
        "the API key leaked into Debug output: {rendered}"
    );
    assert!(rendered.contains("redacted"));
}
