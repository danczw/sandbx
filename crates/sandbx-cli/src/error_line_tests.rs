use super::error_line;
use crate::AgentError;
use sandbx_anthropic::AnthropicClient;
use sandbx_prompt::{ContentBlock, Prompt, RequestMessage, Role};
use sandbx_turn::TurnError;
use secrecy::SecretString;
use std::error::Error;
use std::fmt;

/// The case #457 was filed for, against reqwest's real chain: its message names only the
/// URL, so what tells a refused connection from a rejected certificate is below it.
#[tokio::test]
async fn a_refused_connection_is_reported_with_its_cause() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    let base_url = format!("http://{}", listener.local_addr().expect("a bound address"));
    drop(listener);
    let client = AnthropicClient::new(SecretString::from("sk-ant-test".to_string()))
        .expect("the default base URL is https")
        .with_base_url(base_url)
        .expect("loopback http is allowed");
    let prompt = Prompt {
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
    };
    let error = match client.stream_chat(prompt).await {
        Ok(_) => panic!("nothing listens on the port, so there is no stream"),
        Err(error) => AgentError::Turn(TurnError::Provider(error)),
    };

    let mut leaf: &dyn Error = &error;
    while let Some(cause) = leaf.source() {
        leaf = cause;
    }
    let leaf = leaf.to_string();
    let line = error_line(&error);
    assert!(
        !error.to_string().contains(&leaf),
        "the message already names {leaf:?}, so this test proves nothing"
    );
    assert!(line.ends_with(&leaf), "{line:?} does not end on {leaf:?}");
    assert_eq!(
        line.matches("error sending request").count(),
        1,
        "{line:?} repeats a link its parent already printed"
    );
}

/// A link whose parent printed it is skipped, and one whose parent did not is printed —
/// checked against the parent, wherever in the chain it is.
#[test]
fn a_cause_its_parent_already_prints_is_not_repeated() {
    let embedded_first = chain(&["outer: middle", "middle", "leaf"]);
    assert_eq!(
        error_line(&embedded_first),
        "outer: middle: leaf",
        "a link the top printed was repeated, or the one below it dropped"
    );

    let embedded_last = chain(&["outer", "middle: leaf", "leaf"]);
    assert_eq!(
        error_line(&embedded_last),
        "outer: middle: leaf",
        "a link its own parent printed was repeated"
    );

    // The grandparent names the leaf and the parent does not: checked against the line
    // so far, the leaf would be dropped.
    let named_above = chain(&["outer leaf", "middle", "leaf"]);
    assert_eq!(
        error_line(&named_above),
        "outer leaf: middle: leaf",
        "a cause was hidden by text above its parent"
    );
}

/// Nothing in any link may rewrite the terminal or break the report onto a second line:
/// the top message can carry a model-chosen path, a cause text sandbx did not write.
#[test]
fn a_cause_cannot_carry_an_escape_to_the_terminal() {
    let hostile = chain(&[
        "\u{1b}[1mouter",
        "mid\u{202e}dle",
        "\u{1b}[2Jname\nforged\tline",
    ]);

    assert_eq!(
        error_line(&hostile),
        "\u{fffd}[1mouter: mid\u{fffd}dle: \u{fffd}[2Jname\\nforged\\tline",
        "an escape, a bidi override or a line break reached the report as written"
    );
}

/// A chain of [`Link`]s, outermost first.
fn chain(texts: &[&'static str]) -> Link {
    texts
        .iter()
        .rev()
        .fold(None, |source, &text| {
            Some(Link {
                text,
                source: source.map(Box::new),
            })
        })
        .expect("a chain has at least one link")
}

/// One link of a hand-built chain.
#[derive(Debug)]
struct Link {
    text: &'static str,
    source: Option<Box<Link>>,
}

impl fmt::Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text)
    }
}

impl Error for Link {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|link| link as &dyn Error)
    }
}
