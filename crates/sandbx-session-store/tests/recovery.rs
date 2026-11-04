//! What a transcript recovers from, and what it still refuses.
//!
//! Apart from `transcript.rs`, which pins the format's own rules: here the file is
//! already damaged or the turn already odd.

mod common;

use std::fs;
use std::path::PathBuf;

use sandbx_session_error::SessionError;
use sandbx_session_message::{CompletedTurn, TurnStop, Usage};
use sandbx_session_store::SessionStore;

use common::{exchange, out_of_rounds, store};

/// One session with one turn in it, and the path it was written to.
fn spoken_to(store: &SessionStore) -> Spoken {
    let mut session = store.create().expect("a session is created");
    session
        .append(CompletedTurn {
            messages: &exchange("a", "1"),
            observed: None,
            withheld: 0,
            stop: TurnStop::Answered,
        })
        .expect("the turn is appended");

    Spoken {
        id: session.id().clone(),
        path: session.path().to_owned(),
    }
}

/// The session [`spoken_to`] made.
struct Spoken {
    id: sandbx_session_id::SessionId,
    path: PathBuf,
}

/// ENOSPC part-way through an append, which refusing would let cost the conversation.
#[test]
fn a_torn_final_line_is_dropped() {
    let fixture = store();
    let store = fixture.store;
    let Spoken { id, path } = spoken_to(&store);

    let whole = fs::read_to_string(&path).unwrap();
    fs::write(&path, format!("{whole}{{\"type\":\"mes")).unwrap();

    let resumed = store.resume(&id).unwrap();

    assert_eq!(resumed.messages(), exchange("a", "1"));
}

/// Nothing is left to replay, so the header is as absent as it is for an empty file.
#[test]
fn a_transcript_of_nothing_but_a_torn_line_is_refused() {
    let fixture = store();
    let store = fixture.store;
    let Spoken { id, path } = spoken_to(&store);

    fs::write(&path, "{\"type\":\"hea").unwrap();

    let err = store.resume(&id).unwrap_err();

    assert!(
        matches!(err, SessionError::MissingHeader { .. }),
        "got {err:?}"
    );
}

/// `settled` sees only the last role, so an interior pair would reach the provider as a
/// 400.
#[test]
fn an_interior_pair_of_user_turns_is_refused() {
    let fixture = store();
    let store = fixture.store;
    let Spoken { id, path } = spoken_to(&store);

    // Appended so the history still ends on the model: only a check over the whole
    // history sees the break.
    let mut body = fs::read_to_string(&path).unwrap();
    for role in ["user", "user", "assistant"] {
        body.push_str(&format!(
            "{{\"type\":\"message\",\"role\":\"{role}\",\"content\":[]}}\n"
        ));
    }
    fs::write(&path, body).unwrap();

    let err = store.resume(&id).unwrap_err();

    assert!(
        matches!(err, SessionError::Disordered { .. }),
        "got {err:?}"
    );
}

/// The accounting line is the only place a figure from a round that produced no blocks
/// can live.
#[test]
fn a_turn_with_no_messages_still_records_what_it_cost() {
    let fixture = store();
    let store = fixture.store;
    let mut session = store.create().unwrap();
    let observed = Usage {
        input_tokens: Some(1204),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    };

    session
        .append(CompletedTurn {
            messages: &[],
            observed: Some(observed),
            withheld: 0,
            stop: TurnStop::Answered,
        })
        .unwrap();
    let id = session.id().clone();

    let resumed = store.resume(&id).unwrap();

    assert_eq!(resumed.observed(), Some(observed));
    assert!(resumed.messages().is_empty());
}

/// An append torn after its results, before its `turn` line: the shape of a turn out of
/// rounds with nothing to say it was one, which resume has to hedge (#226).
#[test]
fn results_torn_from_their_turn_line_record_no_stop() {
    let fixture = store();
    let store = fixture.store;
    let Spoken { id, path } = spoken_to(&store);
    let mut session = store.resume(&id).unwrap();
    session
        .append(CompletedTurn {
            messages: &out_of_rounds("what is in /srv?", "toolu_01"),
            observed: None,
            withheld: 0,
            stop: TurnStop::RoundLimit,
        })
        .unwrap();
    // Not vacuous: whole, the transcript says why it stops where it does.
    assert_eq!(
        store.resume(&id).unwrap().last_stop(),
        Some(TurnStop::RoundLimit)
    );

    let whole = fs::read_to_string(&path).unwrap();
    let (kept, dropped) = whole.trim_end().rsplit_once('\n').unwrap();
    assert!(dropped.contains("\"type\":\"turn\""), "got {dropped}");
    fs::write(&path, format!("{kept}\n")).unwrap();

    let resumed = store.resume(&id).unwrap();
    assert!(resumed.pending_call());
    // Not the first turn's `Answered`, which is the last `turn` line left on disk.
    assert_eq!(resumed.last_stop(), None);
}

/// An empty turn describes no messages, so the stop of the turn the conversation still
/// ends on survives it — in the live session and in the file alike.
#[test]
fn an_empty_turn_keeps_the_stop_before_it() {
    let fixture = store();
    let store = fixture.store;
    let mut session = store.create().unwrap();
    session
        .append(CompletedTurn {
            messages: &out_of_rounds("what is in /srv?", "toolu_01"),
            observed: None,
            withheld: 0,
            stop: TurnStop::RoundLimit,
        })
        .unwrap();

    session
        .append(CompletedTurn {
            messages: &[],
            observed: None,
            withheld: 0,
            stop: TurnStop::Answered,
        })
        .unwrap();

    assert_eq!(session.last_stop(), Some(TurnStop::RoundLimit));
    assert_eq!(
        store.resume(session.id()).unwrap().last_stop(),
        Some(TurnStop::RoundLimit)
    );
}
