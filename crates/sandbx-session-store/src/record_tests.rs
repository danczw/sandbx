use std::path::Path;

use sandbx_session_error::SessionError;
use sandbx_session_message::{Content, Message, Role, TurnStop, Usage};

use super::{Accounting, Header, Record, fold};

#[test]
fn a_turn_line_carries_its_own_type() {
    let record = Record::Turn(Accounting {
        observed: Some(Usage {
            input_tokens: Some(1204),
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        }),
        withheld: 2,
        stop: Some(TurnStop::RoundLimit),
    });

    assert_eq!(
        serde_json::to_value(&record).unwrap(),
        serde_json::json!({
            "type": "turn",
            "observed": {
                "input_tokens": 1204,
                "cache_read_input_tokens": null,
                "cache_creation_input_tokens": null,
            },
            "withheld": 2,
            "stop": "round_limit",
        })
    );
}

fn turn_of(line: &str) -> Accounting {
    match serde_json::from_str::<Record>(line).expect("a turn line") {
        Record::Turn(turn) => turn,
        other => panic!("not a turn line: {other:?}"),
    }
}

/// Every transcript written before the field existed has lines like the first.
#[test]
fn a_turn_line_with_no_stop_reads_as_none_recorded() {
    assert_eq!(
        turn_of(r#"{"type":"turn","observed":null,"withheld":0}"#).stop,
        None
    );
    assert_eq!(
        turn_of(r#"{"type":"turn","observed":null,"withheld":0,"stop":"gate_aborted"}"#).stop,
        Some(TurnStop::GateAborted)
    );
    assert_eq!(
        turn_of(r#"{"type":"turn","observed":null,"withheld":0,"stop":"summarised"}"#).stop,
        Some(TurnStop::Summarised)
    );
}

/// Literals, so a renamed variant fails here rather than leaving old lines unreadable.
#[test]
fn a_stopped_turn_says_who_stopped_it() {
    for (stop, wire) in [
        (TurnStop::Interrupted, "interrupted"),
        (TurnStop::HungUp, "hung_up"),
    ] {
        let line = format!(r#"{{"type":"turn","observed":null,"withheld":0,"stop":"{wire}"}}"#);
        assert_eq!(turn_of(&line).stop, Some(stop), "{line}");
        assert_eq!(serde_json::to_value(stop).unwrap(), wire);
    }
}

/// A later build's stop is a diagnosis this one cannot give, not a line it cannot read.
#[test]
fn a_stop_this_build_cannot_name_reads_as_none_recorded() {
    for stop in [
        r#""rewound""#,
        "null",
        "7",
        r#"{"round_limit":{"rounds":5}}"#,
    ] {
        let line = format!(r#"{{"type":"turn","observed":null,"withheld":3,"stop":{stop}}}"#);
        let turn = turn_of(&line);
        assert_eq!(turn.stop, None, "{line}");
        // The rest of the line is still read, so nothing was skipped wholesale.
        assert_eq!(turn.withheld, 3, "{line}");
    }
}

/// A message after the last `turn` line is an append torn before its own: the stop on
/// disk is the previous turn's, and names nothing about where the conversation ends.
#[test]
fn a_message_after_the_last_turn_line_clears_its_stop() {
    let header = r#"{"type":"header","version":1,"id":"01k6n0","created_at_millis":0}"#;
    let turn = r#"{"type":"turn","observed":null,"withheld":0,"stop":"round_limit"}"#;
    let result = r#"{"type":"message","role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_02","content":"x"}]}"#;
    let path = Path::new("/sessions/01k6n0.jsonl");

    let torn = fold(path, &format!("{header}\n{turn}\n{result}\n")).unwrap();
    let whole = fold(path, &format!("{header}\n{result}\n{turn}\n")).unwrap();

    assert_eq!(torn.accounting.stop, None);
    // Not vacuous: the same lines with the turn line last keep the stop it carries.
    assert_eq!(whole.accounting.stop, Some(TurnStop::RoundLimit));
}

#[test]
fn a_message_line_is_the_message_plus_a_type() {
    let record = Record::Message(Message {
        role: Role::User,
        content: vec![Content::Text {
            text: "what is in /srv?".to_owned(),
        }],
    });

    assert_eq!(
        serde_json::to_value(&record).unwrap(),
        serde_json::json!({
            "type": "message",
            "role": "user",
            "content": [{ "type": "text", "text": "what is in /srv?" }],
        })
    );
}

#[test]
fn an_unknown_record_type_is_not_a_record() {
    let line = r#"{"type":"compaction","dropped":4}"#;

    assert!(serde_json::from_str::<Record>(line).is_err());
}

/// Versions as literals, so a `VERSION` bump fails this rather than passing unread.
#[test]
fn a_later_header_is_read_for_its_version_too() {
    let header = |version| {
        serde_json::to_string(&Record::Header(Header {
            version,
            id: "01k6n0".to_owned(),
            created_at_millis: 0,
        }))
        .unwrap()
    };
    let body = |second| format!("{}\n{}\n", header(1), header(second));
    let path = Path::new("/sessions/01k6n0.jsonl");

    let err = fold(path, &body(2)).unwrap_err();

    assert!(
        matches!(err, SessionError::UnsupportedVersion { version: 2, .. }),
        "got {err:?}"
    );
    // Not vacuous: the same two lines fold when the second header declares the version
    // the first one does, so what is refused is the version and not the extra header.
    assert!(fold(path, &body(1)).is_ok());
}
