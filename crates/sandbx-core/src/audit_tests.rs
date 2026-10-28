use super::*;

/// `n` arguments of one character, which render as `n` quoted singletons.
fn singletons(n: usize) -> Vec<String> {
    (0..n).map(|_| "x".to_owned()).collect()
}

#[test]
fn args_field_renders_each_argument_quoted() {
    let rendered = args_field(&["-c".to_owned(), "echo hi".to_owned()]);

    assert_eq!(
        rendered, r#"["-c", "echo hi"]"#,
        "an argument holding a space has to stay one argument on the trail"
    );
}

#[test]
fn no_arguments_render_as_an_empty_list() {
    let rendered = args_field(&[]);

    assert_eq!(
        rendered, "[]",
        "`sandbox-run -- /bin/true` passes no arguments, and that is not a missing field"
    );
}

/// The escaping the trail's line format depends on, and the one `emit`'s `%` sigil leaves
/// to this function: rendered here, the layer does not escape it a second time.
#[test]
fn a_hostile_argument_is_escaped_not_dropped() {
    let rendered = args_field(&["echo \u{1b}[2J\nrm -rf /".to_owned()]);

    assert!(
        !rendered.contains('\u{1b}') && !rendered.contains('\n'),
        "a raw escape or newline reached the field: {rendered:?}"
    );
    // The other half: dropping both bytes would satisfy the assertion above.
    assert!(
        rendered.contains(r"\u{1b}") && rendered.contains(r"\n"),
        "the bytes were dropped rather than escaped, so the record understates: {rendered:?}"
    );
}

#[test]
fn a_long_argument_list_is_cut_and_marked() {
    // A compile-time check and not an `assert!`, which clippy refuses on a constant: a cap
    // of zero would cut every field to nothing and make both cases below trivially true.
    const { assert!(ARGS_CAP > 0) };

    // Each singleton renders as five characters (`"x", `), so this overruns the cap.
    let rendered = args_field(&singletons(ARGS_CAP));

    assert_eq!(
        rendered.chars().count(),
        ARGS_CAP + 1,
        "the cap bounds the field, and the marker is the one character past it: {rendered:?}"
    );
    assert!(
        rendered.ends_with('…'),
        "the cut was silent, so a reader cannot tell a whole command from a cut one"
    );
}

/// The positive control: without it, a field that always ended in `…` would pass the case
/// above and the marker would mean nothing.
#[test]
fn a_list_within_the_cap_is_not_marked() {
    let rendered = args_field(&singletons(2));

    assert!(
        !rendered.contains('…'),
        "a short command was marked as cut: {rendered:?}"
    );
    assert!(
        rendered.chars().count() < ARGS_CAP,
        "the fixture outgrew the cap, so this proves nothing: {rendered:?}"
    );
}
