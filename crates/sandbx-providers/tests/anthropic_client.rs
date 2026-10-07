//! Public contract of [`AnthropicClient`], over real HTTP against a local mock server
//! — no live network access, no API key.

use futures_util::StreamExt;
use sandbx_providers::{
    AgentEvent, AnthropicClient, ContentBlock, Prompt, ProviderError, RequestMessage, Role,
    StopReason, Thinking, ToolChoice, ToolDefinition,
};
use secrecy::SecretString;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client_for(server: &MockServer) -> AnthropicClient {
    AnthropicClient::new(SecretString::from("sk-ant-test".to_string()))
        .unwrap()
        // wiremock binds loopback, which `with_base_url` allows over plain http so
        // this needs no TLS mock.
        .with_base_url(server.uri())
        .unwrap()
}

fn a_request() -> Prompt {
    Prompt {
        model: "claude-opus-5".to_string(),
        max_output_tokens: 1_000,
        system: None,
        messages: vec![RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "hi".to_string(),
            }],
        }],
        tools: vec![],
        tool_choice: None,
        thinking: None,
    }
}

/// The SSE body a real turn produces, tool call split across fragments included.
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

/// The body too: without a body matcher the suite passes with `stream: true` dropped,
/// or with `.json(&request)` swapped for a `.body(..)` that loses `content-type`.
#[tokio::test]
async fn sends_the_right_headers_and_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "sk-ant-test"))
        .and(header("anthropic-version", "2023-06-01"))
        .and(header("content-type", "application/json"))
        .and(body_json(serde_json::json!({
            "model": "claude-opus-5",
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
            "stream": true,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_raw(FULL_TURN_SSE, "text/event-stream"))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let stream = client.stream_chat(a_request()).await.unwrap();
    let _: Vec<_> = stream.collect().await;

    // wiremock's `.expect(1)`, verified on drop, is the assertion that every matcher
    // above held.
}

/// Every field at once, because the per-field rules are `body.rs`'s own tests and what
/// this adds is that the client posts *that* body: a `.json(&request)` on the neutral type
/// would compile and send `max_output_tokens`, `schema` and no `stream`.
#[tokio::test]
async fn the_body_on_the_wire_is_the_adapter_shape() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(body_json(serde_json::json!({
            "model": "claude-opus-5",
            "max_tokens": 1000,
            "system": "be brief",
            "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
            "tools": [{
                "name": "ls",
                "description": "list a directory",
                "input_schema": {"type": "object"},
            }],
            "tool_choice": {"type": "none"},
            "thinking": {"type": "adaptive", "display": "summarized"},
            "stream": true,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_raw(FULL_TURN_SSE, "text/event-stream"))
        .expect(1)
        .mount(&server)
        .await;

    let request = Prompt {
        system: Some("be brief".to_string()),
        tools: vec![ToolDefinition {
            name: "ls".to_string(),
            description: "list a directory".to_string(),
            schema: serde_json::json!({"type": "object"}),
        }],
        tool_choice: Some(ToolChoice::None),
        thinking: Some(Thinking::Visible),
        ..a_request()
    };

    let client = client_for(&server);
    let stream = client.stream_chat(request).await.unwrap();
    let _: Vec<_> = stream.collect().await;
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
                cache_write_tokens: None,
                cache_read_tokens: None,
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
async fn a_400_is_reported_with_the_vendor_envelope() {
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
            ..
        } => {
            assert_eq!(status, Some(400));
            assert_eq!(kind, "invalid_request_error");
            assert_eq!(message, "model field is required");
        }
        other => panic!("expected ApiError, got {other:?}"),
    }
}

/// 529 is Anthropic's non-standard "overloaded", so it has no `StatusCode` constant
/// and is classified by the numeric range alone.
#[tokio::test]
async fn a_529_is_retryable_and_carries_its_retry_after() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(529)
                .insert_header("retry-after", "3")
                .set_body_json(serde_json::json!({
                    "type": "error",
                    "error": {"type": "overloaded_error", "message": "overloaded"}
                })),
        )
        .mount(&server)
        .await;

    let client = client_for(&server);
    let error = client
        .stream_chat(a_request())
        .await
        .err()
        .expect("a 529 must be reported before any stream item");

    assert!(
        error.is_retryable(),
        "a 529 must be classified as retryable: {error:?}"
    );
    assert_eq!(error.retry_after(), Some(std::time::Duration::from_secs(3)));
    match error {
        ProviderError::ApiError { status, kind, .. } => {
            assert_eq!(status, Some(529));
            assert_eq!(kind, "overloaded_error");
        }
        other => panic!("expected ApiError, got {other:?}"),
    }
}

/// An item in the stream, not the outer `Result`: by the time it arrives the response
/// was already a 200.
#[tokio::test]
async fn a_mid_stream_error_ends_the_stream_as_an_item() {
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

/// Everything seen was well-formed, so this is not a `MalformedEvent`.
#[tokio::test]
async fn a_close_before_message_stop_is_reported() {
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

/// The signature states the returned stream is `Send`; that the *future* is, it does
/// not — that is inferred, so it can regress silently, and a non-`Send` future cannot
/// be `tokio::spawn`ed. Compiled but never run, so it needs no `MockServer`.
#[allow(dead_code)]
fn client_future_stays_spawnable(client: &'static AnthropicClient) {
    fn assert_send<T: Send>(_: T) {}

    assert_send(client.stream_chat(a_request()));
}

/// reqwest does not scrub `x-api-key` across hosts, so following a redirect would hand
/// a live key to whatever `Location` names; the Messages API never redirects.
#[tokio::test]
async fn a_redirect_is_not_followed() {
    let attacker = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(FULL_TURN_SSE, "text/event-stream"))
        .expect(0)
        .mount(&attacker)
        .await;

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(307).insert_header("Location", attacker.uri().as_str()))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let error = match client.stream_chat(a_request()).await {
        Ok(_) => panic!("a redirect must not be followed into a stream"),
        Err(error) => error,
    };

    assert!(
        matches!(
            error,
            ProviderError::ApiError {
                status: Some(307),
                ..
            }
        ),
        "expected the 307 to surface as an error, got {error:?}"
    );
    // `attacker`'s `.expect(0)`, verified on drop, is the assertion: the key was never
    // replayed to it.
}

#[test]
fn a_cleartext_base_url_is_rejected() {
    let client = AnthropicClient::new(SecretString::from("sk-ant-test".to_string())).unwrap();

    let error = match client.with_base_url("http://gateway.internal.example") {
        Ok(_) => panic!("http:// to a non-loopback host must be rejected"),
        Err(error) => error,
    };

    match error {
        ProviderError::InvalidBaseUrl { base_url, .. } => {
            assert_eq!(base_url, "http://gateway.internal.example");
        }
        other => panic!("expected InvalidBaseUrl, got {other:?}"),
    }
}

#[test]
fn an_https_base_url_loses_its_trailing_slash() {
    let client = AnthropicClient::new(SecretString::from("sk-ant-test".to_string()))
        .unwrap()
        .with_base_url("https://gateway.internal.example/")
        .expect("https:// must be accepted");

    assert!(
        format!("{client:?}").contains("https://gateway.internal.example\""),
        "trailing slash should be trimmed: {client:?}"
    );
}

#[test]
fn a_non_http_base_url_scheme_is_rejected() {
    let client = AnthropicClient::new(SecretString::from("sk-ant-test".to_string())).unwrap();

    assert!(
        client.with_base_url("file:///etc/passwd").is_err(),
        "only https:// (or loopback http://) may carry the API key"
    );
}

/// `/v1/messages` is appended before any `?` or `#`, so either would post to a
/// different URL than the operator read back; userinfo would put a second credential
/// on the wire.
#[test]
fn a_query_fragment_or_credentials_is_rejected() {
    let client = AnthropicClient::new(SecretString::from("sk-ant-test".to_string())).unwrap();

    for base_url in [
        "https://gateway.example?tenant=acme",
        "https://gateway.example#frag",
        "https://user:pw@gateway.example",
    ] {
        assert!(
            client.clone().with_base_url(base_url).is_err(),
            "{base_url} must be rejected: appending /v1/messages would not preserve it"
        );
    }
}

/// An IPv6 literal arrives from `Url::host_str` still wrapped in brackets, which do
/// not parse as part of an address.
#[test]
fn every_loopback_spelling_is_accepted_cleartext() {
    let client = AnthropicClient::new(SecretString::from("sk-ant-test".to_string())).unwrap();

    for base_url in [
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "http://127.0.0.2:8080",
        "http://[::1]:8080",
    ] {
        assert!(
            client.clone().with_base_url(base_url).is_ok(),
            "{base_url} is loopback and must be allowed for a local mock server"
        );
    }
}

#[test]
fn debug_output_does_not_leak_the_api_key() {
    let client =
        AnthropicClient::new(SecretString::from("sk-ant-super-secret".to_string())).unwrap();

    let rendered = format!("{client:?}");

    assert!(
        !rendered.contains("sk-ant-super-secret"),
        "the API key leaked into Debug output: {rendered}"
    );
    assert!(
        rendered.to_lowercase().contains("redacted"),
        "expected the key field to render as a redaction: {rendered}"
    );
}
