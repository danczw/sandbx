use super::{rendered, usage_code};
use clap::Parser;
use sandbx_anthropic::AnthropicClient;
use sandbx_cli::{AgentError, Cli};
use sandbx_prompt::{ContentBlock, Prompt, RequestMessage, Role};
use sandbx_turn::TurnError;
use secrecy::SecretString;
use std::error::Error;
use std::fmt;

/// Every way clap can refuse an argv takes one code, and the two it reports as errors
/// without refusing anything take 0.
///
/// Codes as literals, so renumbering [`USAGE`] under the claim `README.md` and
/// `SECURITY.md` both make fails here.
#[test]
fn a_refused_command_line_exits_sixty_four_and_help_exits_zero() {
    let kind = |argv: &[&str]| {
        Cli::try_parse_from(argv)
            .expect_err("clap took an argv it should have refused")
            .kind()
    };

    // #265's own repro first, then a value clap will not take, an unknown flag and a
    // missing required argument — the four shapes already in tree. Then the two argvs
    // that name no subcommand at all: clap answers both by printing the help, which is
    // why they are easy to read as a help anyone asked for, and prints it to stderr
    // because neither is.
    for argv in [
        ["sandbx", "tui", "--max-rounds", "1", "no-dashdash"].as_slice(),
        &[
            "sandbx",
            "sandbox-run",
            "--allow-network",
            "65536",
            "--",
            "true",
        ],
        &["sandbx", "auth", "status", "--nonsense"],
        &["sandbx", "sandbox-run"],
        &["sandbx"],
        &["sandbx", "auth"],
    ] {
        assert_eq!(usage_code(kind(argv)), 64, "{argv:?}");
    }

    // Only what the caller asked for takes 0.
    for argv in [["sandbx", "--help"].as_slice(), &["sandbx", "--version"]] {
        assert_eq!(usage_code(kind(argv)), 0, "{argv:?}");
    }
}

/// Non-vacuity for the test above: an argv sandbx accepts produces no code at all, so
/// what is asserted there is the refusal and not every call.
#[test]
fn an_argv_sandbx_accepts_is_not_a_usage_error() {
    Cli::try_parse_from(["sandbx", "sandbox-run", "--", "true"])
        .expect("a well-formed sandbox-run");
}

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
    let line = rendered(&error);
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
    let chain = |texts: &[&'static str]| {
        texts.iter().rev().fold(None, |source, &text| {
            Some(Link {
                text,
                source: source.map(Box::new),
            })
        })
    };

    let embedded_first = chain(&["outer: middle", "middle", "leaf"]).expect("a chain");
    assert_eq!(rendered(&embedded_first), "outer: middle: leaf");

    let embedded_last = chain(&["outer", "middle: leaf", "leaf"]).expect("a chain");
    assert_eq!(rendered(&embedded_last), "outer: middle: leaf");
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
