use super::Cancel;

#[test]
fn a_new_token_is_not_raised() {
    assert!(!Cancel::new().is_raised());
}

/// The point of the type: the turn keeps one end and every spawned command holds another.
#[test]
fn raising_one_clone_raises_them_all() {
    let held = Cancel::new();
    let handed_out = held.clone();

    held.raise();

    assert!(handed_out.is_raised());
}

#[test]
fn a_separate_token_is_unaffected() {
    let first = Cancel::new();
    let second = Cancel::new();

    first.raise();

    assert!(!second.is_raised());
}
