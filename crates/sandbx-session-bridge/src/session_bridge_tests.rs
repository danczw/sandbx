use sandbx_compact::PromptUsage;
use sandbx_prompt::{ContentBlock, RequestMessage, Role};
use sandbx_session_message::{Content, TurnStop};

use super::{
    merge_user_runs, request_history, request_usage, resume_note, stored_messages, stored_usage,
};

fn blocks() -> Vec<ContentBlock> {
    vec![
        ContentBlock::Text {
            text: "what is in /srv?".to_owned(),
        },
        ContentBlock::ToolUse {
            id: "toolu_01".to_owned(),
            name: "ls".to_owned(),
            input: serde_json::json!({ "path": "/srv" }),
        },
        ContentBlock::ToolResult {
            tool_use_id: "toolu_01".to_owned(),
            content: "notes.txt".to_owned(),
            is_error: None,
        },
        ContentBlock::ToolResult {
            tool_use_id: "toolu_02".to_owned(),
            content: "denied".to_owned(),
            is_error: Some(true),
        },
    ]
}

#[test]
fn every_block_kind_survives_the_round_trip() {
    let sent = [RequestMessage {
        role: Role::Assistant,
        content: blocks(),
    }];

    let back = request_history(&stored_messages(&sent));

    assert_eq!(stored_messages(&back), stored_messages(&sent));
    assert_eq!(stored_messages(&back)[0].content.len(), 4);
}

#[test]
fn a_failed_tool_result_stays_failed() {
    let stored = stored_messages(&[RequestMessage {
        role: Role::User,
        content: blocks(),
    }]);

    let Content::ToolResult { is_error, .. } = &stored[0].content[3] else {
        panic!("the fourth block is a tool result");
    };
    assert_eq!(*is_error, Some(true));
}

/// A history ending on an unanswered call, with the prompt that resumed it and the
/// reply to that: `[user, assistant, user(tool_result), user, assistant]`.
fn resumed() -> Vec<RequestMessage> {
    vec![
        RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "what is in /srv?".to_owned(),
            }],
        },
        RequestMessage {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: "toolu_01".to_owned(),
                name: "ls".to_owned(),
                input: serde_json::json!({ "path": "/srv" }),
            }],
        },
        RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "toolu_01".to_owned(),
                content: "notes.txt".to_owned(),
                is_error: None,
            }],
        },
        RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "what did you find?".to_owned(),
            }],
        },
        RequestMessage {
            role: Role::Assistant,
            content: vec![ContentBlock::Text {
                text: "notes.txt".to_owned(),
            }],
        },
    ]
}

#[test]
fn a_run_of_user_turns_travels_as_one_message() {
    let merged = merge_user_runs(resumed(), 0);

    let stored = stored_messages(&merged.history);
    assert_eq!(stored.len(), 4);
    // The results stay ahead of the prompt, which is the order the API takes.
    assert!(matches!(
        stored[2].content.as_slice(),
        [Content::ToolResult { .. }, Content::Text { .. }]
    ));
}

/// Merging moves the indices after a run, so the floor is translated, not carried.
#[test]
fn the_floor_names_the_message_it_named_before() {
    for (before, after) in [(0, 0), (1, 1), (2, 2), (3, 2), (4, 3)] {
        let merged = merge_user_runs(resumed(), before);

        assert_eq!(merged.withheld, after, "a floor of {before}");
    }
}

/// Inverting it: a merged index names where a cut onto it lands in the transcript, which
/// for the run is its prose, the results going with the withheld call (#208).
#[test]
fn a_reported_floor_returns_to_the_stored_index() {
    let merged = merge_user_runs(resumed(), 0);

    for (reported, stored) in [(0, 0), (1, 1), (2, 3), (3, 4)] {
        assert_eq!(merged.unmerged(reported), stored, "a cut at {reported}");
    }

    // Past the history: the turn's own messages, which no merge saw. Five stored
    // messages, four sent, so the first produced one is 4 out and 5 back.
    assert_eq!(merged.unmerged(4), 5);
    assert_eq!(merged.unmerged(6), 7);
}

/// Stored, resumed and stored again, a cut onto the run's prose holds still.
#[test]
fn a_stored_cut_onto_a_run_survives_a_resume() {
    let merged = merge_user_runs(resumed(), 3);

    assert_eq!(merged.withheld, 2);
    assert_eq!(merged.unmerged(merged.withheld), 3);
}

/// What `window` keeps, whatever the run: no result is shed at cut 0, and a run opening on
/// prose sheds no part of itself. Hand-edited shapes, which resume refuses but merge takes.
#[test]
fn a_stored_cut_counts_only_what_was_shed() {
    let [ask, call, result, prompt, reply] = resumed().try_into().unwrap();
    // `[user(tool_result), user, assistant, user, user, assistant]`.
    let history = vec![result, prompt, call, ask.clone(), ask, reply];

    let merged = merge_user_runs(history, 0);

    assert_eq!(merged.unmerged(0), 0, "a run opening the history");
    assert_eq!(merged.unmerged(2), 3, "a run of two prompts");
}

#[test]
fn a_figure_nobody_reported_stays_unreported() {
    let observed = PromptUsage {
        input_tokens: Some(1204),
        cache_read_tokens: None,
        cache_write_tokens: None,
    };

    let back = request_usage(stored_usage(observed));

    assert_eq!(back.input_tokens, Some(1204));
    assert_eq!(back.cache_read_tokens, None);
    assert_eq!(back.cache_write_tokens, None);
}

/// Every stop, and none recorded.
const STOPS: [Option<TurnStop>; 7] = [
    None,
    Some(TurnStop::Answered),
    Some(TurnStop::RoundLimit),
    Some(TurnStop::Summarised),
    Some(TurnStop::GateAborted),
    Some(TurnStop::Interrupted),
    Some(TurnStop::HungUp),
];

#[test]
fn a_settled_conversation_resumes_without_a_note() {
    for stop in STOPS {
        assert_eq!(resume_note(false, stop), None, "{stop:?}");
    }
}

/// A gate abort ends on the same unanswered call a round limit does, and is not reported
/// as one (#226).
#[test]
fn an_unanswered_call_is_explained_by_the_stop_recorded() {
    let note = |stop| resume_note(true, stop).expect("a note");

    assert!(note(Some(TurnStop::RoundLimit)).contains("ran out of rounds"));
    assert!(note(Some(TurnStop::GateAborted)).contains("approve"));
    for unknown in [None, Some(TurnStop::Answered), Some(TurnStop::Summarised)] {
        assert!(note(unknown).contains("does not say why"), "{unknown:?}");
    }
    // Each names one cause, so no reason is reported for another's.
    assert!(!note(Some(TurnStop::GateAborted)).contains("rounds"));
    assert!(!note(None).contains("rounds"));
}

/// A hangup is not reported as a keypress, and both say the round was kept and what the
/// call the stop landed on left out (#271, #26).
#[test]
fn a_stopped_turn_names_its_stop_and_what_it_kept() {
    let pressed = resume_note(true, Some(TurnStop::Interrupted)).expect("a note");
    let gone = resume_note(true, Some(TurnStop::HungUp)).expect("a note");

    assert!(pressed.contains("interrupted"), "{pressed}");
    assert!(gone.contains("terminal went away"), "{gone}");
    assert!(!gone.contains("interrupted"), "{gone}");
    for note in [pressed, gone] {
        assert!(note.contains("output withheld"), "{note}");
        assert!(!note.contains("not stored"), "{note}");
        assert!(!note.contains("rounds"), "{note}");
    }
}
