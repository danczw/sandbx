//! The set of tools an agent can be offered, and lookup by the name the model
//! calls back with.

use sandbx_tools::BuiltinTool;

/// Exhaustive by construction: adding a variant without adding it to `ALL`
/// fails to compile here, not at runtime in front of a model.
#[test]
fn all_contains_every_variant() {
    for tool in [
        BuiltinTool::Read,
        BuiltinTool::Write,
        BuiltinTool::Bash,
        BuiltinTool::Edit,
        BuiltinTool::Ls,
        BuiltinTool::Grep,
        BuiltinTool::Find,
    ] {
        // The match is what the compiler checks; the assert is what fails if a
        // variant exists but was never listed in `ALL`.
        let listed = match tool {
            BuiltinTool::Read
            | BuiltinTool::Write
            | BuiltinTool::Bash
            | BuiltinTool::Edit
            | BuiltinTool::Ls
            | BuiltinTool::Grep
            | BuiltinTool::Find => BuiltinTool::ALL.contains(&tool),
        };
        assert!(listed, "{tool:?} missing from BuiltinTool::ALL");
    }
}

#[test]
fn every_listed_tool_resolves_from_its_own_name() {
    for tool in BuiltinTool::ALL {
        assert_eq!(
            BuiltinTool::from_name(tool.name()),
            Some(tool),
            "{tool:?} did not round-trip through its name"
        );
    }
}

/// Names reach the model as an API tool list; a collision would make one of
/// them permanently unreachable.
#[test]
fn names_are_unique() {
    let mut names: Vec<&str> = BuiltinTool::ALL.iter().map(BuiltinTool::name).collect();
    names.sort_unstable();
    let count = names.len();
    names.dedup();

    assert_eq!(names.len(), count, "duplicate tool name");
}

/// A model can hallucinate a tool that does not exist. That must be a lookup
/// miss the agent can report, not a panic or a wrong tool.
#[test]
fn an_unknown_name_is_not_a_tool() {
    assert_eq!(BuiltinTool::from_name("rm"), None);
    assert_eq!(BuiltinTool::from_name(""), None);
}

/// Lookup is exact. "Read" and "read " are not the `read` tool.
#[test]
fn lookup_does_not_normalise_the_name() {
    assert_eq!(BuiltinTool::from_name("Read"), None);
    assert_eq!(BuiltinTool::from_name("read "), None);
}
