//! Compacted requests, sent to the real Anthropic API.
//!
//! `turn_compaction.rs` checks every cut against the repo's own model of what the API
//! rejects, through a script that accepts anything. Only the API can say a cut that model
//! allows is one it accepts, and the reasoning-replay rules are where they could differ
//! (`context/decision-thinking-replay.md`, rule 3).
//!
//! Costs real money and needs a live key, `ANTHROPIC_API_KEY` or the one `sandbx auth`
//! stored, so it is behind the same feature as `sandbx-anthropic`'s live test, for the same
//! reason.
//!
//! Run manually: `cargo test -p sandbx-turn --features live-anthropic-tests`
#![cfg(feature = "live-anthropic-tests")]

use std::fs;

use sandbx_anthropic::AnthropicClient;
use sandbx_core::SandboxPolicy;
use sandbx_event::AgentEvent;
use sandbx_prompt::{ContentBlock, Prompt, RequestMessage, Role, Thinking};
use sandbx_tools::BuiltinTool;
use sandbx_turn::{Compaction, PromptUsage, TurnLimits, TurnStop, run_turn};

use sandbx_turn_fixture::{AllowAll, ctx, turn, vetted};

/// A client on the key `agent-run` would send with.
fn client() -> AnthropicClient {
    let key = sandbx_auth::api_key()
        .expect("ANTHROPIC_API_KEY or a `sandbx auth` key must be set to run live-anthropic-tests");
    AnthropicClient::new(key).expect("a client is built without a network call")
}

fn said(text: &str) -> RequestMessage {
    RequestMessage {
        role: Role::User,
        content: vec![ContentBlock::Text {
            text: text.to_string(),
        }],
    }
}

/// Withhold as much as the law allows once anything at all was measured.
const EAGER: Compaction = Compaction {
    budget_tokens: 1,
    keep_recent: 0,
};

/// A cut that deepens inside a turn strips the reasoning already sent, and the API still
/// takes the request: the one edit rule 3 claims it permits.
///
/// Round one goes out whole, being unmeasured; its figure is over budget, so round two cuts
/// onto the prompt and drops the round-one reasoning ahead of the call it made.
#[tokio::test]
async fn a_deepened_cut_over_reasoning_is_accepted() {
    let client = client();
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("heron.txt"), "").unwrap();
    let path = root.path().to_str().unwrap();

    let history = [
        said("Remember the word: kestrel."),
        RequestMessage {
            role: Role::Assistant,
            content: vec![ContentBlock::Text {
                text: "Noted.".to_string(),
            }],
        },
        said(&format!(
            "Think this through before any tool call: a train leaves at 14:50 and the trip \
             takes 2 hours 25 minutes; when does it arrive? Then call the ls tool exactly once, \
             on {path}, and reply with the arrival time and the name of the one file it lists."
        )),
    ];
    let mut asked = turn(&history, &[BuiltinTool::Ls]);
    asked.max_output_tokens = 4096;
    asked.thinking = Some(Thinking::Visible);
    asked.limits = TurnLimits {
        compaction: Some(EAGER),
        ..TurnLimits::default()
    };

    let mut sent: Vec<Prompt> = Vec::new();
    let mut round = 0usize;
    let mut reasoned_first = false;
    let outcome = run_turn(
        async |request: Prompt| {
            sent.push(request.clone());
            client.stream_chat(request).await
        },
        asked,
        &ctx(SandboxPolicy::default().allow_read(vetted(root.path()))),
        |event: &AgentEvent| match event {
            AgentEvent::ThinkingBlock { .. } | AgentEvent::RedactedThinking { .. } => {
                reasoned_first |= round == 0;
            }
            AgentEvent::Stop { .. } => round += 1,
            _ => {}
        },
        AllowAll,
    )
    .await
    .expect("every compacted request must be accepted");

    // Each a precondition: without it the cut stripped nothing, and a pass proves nothing.
    assert!(sent.len() >= 2, "the model made no tool call: {outcome:?}");
    assert!(
        reasoned_first,
        "round one carried no reasoning; run it again"
    );

    assert_eq!(sent[0].messages.len(), 3, "round one went out cut");
    assert_eq!(
        sent[1].messages[0], history[2],
        "round two did not cut onto the prompt"
    );
    assert!(
        sent[1]
            .messages
            .iter()
            .flat_map(|message| &message.content)
            .all(|block| !block.is_thinking()),
        "round two replayed reasoning across the cut: {:?}",
        sent[1].messages
    );
    assert_eq!(outcome.withheld, 2);
    assert_eq!(outcome.stop, TurnStop::Answered, "{outcome:?}");
}

/// A cut onto a resumed prompt sheds the results it was merged with, and the API takes
/// the request that opens on its prose alone (#208).
#[tokio::test]
async fn a_cut_onto_a_resumed_prompt_is_accepted() {
    let client = client();
    let history = [
        said("List the root directory."),
        RequestMessage {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: "toolu_01".to_string(),
                name: "ls".to_string(),
                input: serde_json::json!({ "path": "/" }),
            }],
        },
        RequestMessage {
            role: Role::User,
            content: vec![
                ContentBlock::ToolResult {
                    tool_use_id: "toolu_01".to_string(),
                    content: "bin\netc\nusr".to_string(),
                    is_error: None,
                },
                ContentBlock::Text {
                    text: "What is two plus two? Reply with the digit only.".to_string(),
                },
            ],
        },
    ];
    let mut asked = turn(&history, &[BuiltinTool::Ls]);
    asked.limits = TurnLimits {
        compaction: Some(EAGER),
        ..TurnLimits::default()
    };
    // A resumed session's last figure, over budget, so the cut lands on round one.
    asked.observed = Some(PromptUsage {
        input_tokens: Some(10_000),
        cache_read_tokens: None,
        cache_write_tokens: None,
    });

    let mut sent: Vec<Prompt> = Vec::new();
    let outcome = run_turn(
        async |request: Prompt| {
            sent.push(request.clone());
            client.stream_chat(request).await
        },
        asked,
        &ctx(SandboxPolicy::default()),
        |_: &AgentEvent| {},
        AllowAll,
    )
    .await
    .expect("the compacted request must be accepted");

    assert!(
        matches!(&sent[0].messages[..], [RequestMessage { role: Role::User, content }]
            if matches!(&content[..], [ContentBlock::Text { .. }])),
        "round one did not open on the prompt's prose alone: {:?}",
        sent[0].messages
    );
    assert_eq!(outcome.withheld, 2);
    assert_eq!(outcome.stop, TurnStop::Answered, "{outcome:?}");
}
