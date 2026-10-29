use super::*;

/// Every pin `encode` emits has to be one `decode` accepts, the wire form being the whole
/// of what the helper is told.
#[test]
fn a_pin_round_trips_through_its_own_wire_form() {
    let object = ObjectId {
        dev: 259,
        ino: 2_097_153,
    };

    assert_eq!(
        ObjectId::parse(&object.to_string()),
        Some(object),
        "a pin did not survive its own spelling"
    );
}

#[test]
fn a_pin_that_is_not_two_numbers_is_refused() {
    for token in ["", ":", "259", "259:", ":17", "259:17:4", "a:b", "-1:17"] {
        assert_eq!(
            ObjectId::parse(token),
            None,
            "{token:?} was accepted as a pin"
        );
    }
}

/// A vetted path is resolved by construction, so nothing downstream has to resolve it
/// again to compare it — and the pin belongs to the resolved path, not to the spelling.
#[test]
fn vetting_resolves_the_path_it_pins() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let real = work.path().canonicalize().expect("a resolved directory");
    let link = real.join("link");
    let target = real.join("target");
    std::fs::create_dir(&target).expect("a directory to link to");
    std::os::unix::fs::symlink(&target, &link).expect("a symlink to it");

    let vetted = VettedPath::vet(&link).expect("a symlink to a directory that exists");

    assert_eq!(
        vetted.path(),
        target,
        "a symlinked spelling was pinned as itself"
    );
    assert_eq!(
        vetted.object(),
        VettedPath::vet(&target).expect("the target").object(),
        "the link and its target pinned different objects"
    );
}

/// The rename #212 is about, measured: two real directories, one name.
#[test]
fn a_renamed_directory_is_a_different_object() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let root = work.path().canonicalize().expect("a resolved directory");
    let granted = root.join("granted");
    let other = root.join("other");
    std::fs::create_dir(&granted).expect("the directory to vet");
    std::fs::create_dir(&other).expect("the directory to substitute");

    let vetted = VettedPath::vet(&granted).expect("a directory that exists");
    std::fs::rename(&other, &granted).expect("a substitution at the same name");

    let replaced = VettedPath::vet(&granted).expect("the substituted directory");

    assert_eq!(
        vetted.path(),
        replaced.path(),
        "the substitution changed the spelling, so this asserts nothing about objects"
    );
    assert_ne!(
        vetted.object(),
        replaced.object(),
        "a substituted directory pinned the same object"
    );
}

#[test]
fn a_path_naming_nothing_cannot_be_vetted() {
    let work = tempfile::tempdir().expect("a temporary directory");

    let error = VettedPath::vet(work.path().join("no-such-directory"))
        .expect_err("a path that names nothing");

    assert!(
        matches!(error, SandboxError::GrantUnpinnable { .. }),
        "{error} is not the unpinnable-grant refusal"
    );
}

/// The helper's half: the two producers measure one thing, so a pin taken from a path and
/// one taken from a descriptor on it have to agree.
#[test]
fn a_descriptor_names_the_object_its_path_did() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let vetted = VettedPath::vet(work.path()).expect("a temporary directory to vet");
    let opened = std::fs::File::open(vetted.path()).expect("a directory to open");

    assert_eq!(
        ObjectId::of_fd(&opened).expect("a descriptor on an open directory"),
        vetted.object(),
        "the path and the descriptor on it named different objects"
    );
}

/// The positive the other two are read against: without it the guard could refuse all.
#[test]
fn confirming_a_path_that_did_not_move() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let vetted = VettedPath::vet(work.path()).expect("a temporary directory to vet");

    assert_eq!(
        vetted.confirm(),
        Confirmation::Vetted,
        "an untouched grant did not confirm as the object it was vetted on"
    );
}

/// A refusal names what it found: the operator has one name and two objects to tell apart.
#[test]
fn confirming_a_renamed_over_path_names_it() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let root = work.path().canonicalize().expect("a resolved directory");
    let granted = root.join("granted");
    let other = root.join("other");
    std::fs::create_dir(&granted).expect("the directory to vet");
    std::fs::create_dir(&other).expect("the directory to substitute");

    let vetted = VettedPath::vet(&granted).expect("a directory that exists");
    let substitute = VettedPath::vet(&other).expect("the directory to substitute");
    std::fs::rename(&other, &granted).expect("a substitution at the same name");

    assert_eq!(
        vetted.confirm(),
        Confirmation::Replaced(substitute.object()),
        "the substitution was not reported as the object that is there now"
    );
}

/// Not [`Confirmation::Replaced`]: a path that names nothing has substituted nothing.
#[test]
fn confirming_a_path_that_is_gone() {
    let work = tempfile::tempdir().expect("a temporary directory");
    let granted = work.path().join("granted");
    std::fs::create_dir(&granted).expect("the directory to vet");

    let vetted = VettedPath::vet(&granted).expect("a directory that exists");
    std::fs::remove_dir(&granted).expect("the grant to be removed under it");

    assert_eq!(
        vetted.confirm(),
        Confirmation::Unmeasurable,
        "a grant that is gone was reported as one that moved"
    );
}
