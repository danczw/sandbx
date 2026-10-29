use sandbx_session_message::{Content, Role};

use super::*;

#[test]
fn a_turn_line_carries_its_own_type() {
    let record = Record::Turn(Accounting {
        observed: Some(Usage {
            input_tokens: Some(1204),
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        }),
        withheld: 2,
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
        })
    );
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
