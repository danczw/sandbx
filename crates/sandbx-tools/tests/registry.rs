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

/// A tool's name is its variant, lowercased.
///
/// Nothing derives it — the name is a literal, so swapping two of them stays
/// unique, still round-trips through `from_name`, and leaves every other test
/// green while the model is offered a tool called `find` that is handed `ls`'s
/// schema and runs `ls` (#88). `names_are_unique` sees only the half-swap; the
/// round-trip above is self-consistent either way.
///
/// The tie is the variant's own spelling, which `Debug` already prints. That
/// makes a variant whose name is not its lowercased spelling — `MultiEdit`
/// against `multi_edit` — fail here, which is the prompt to pick one or the
/// other; the same trade `every_tool_advertises_its_own_input_struct` makes
/// against schemars' `title`.
#[test]
fn every_tool_is_named_after_its_variant() {
    for tool in BuiltinTool::ALL {
        assert_eq!(
            tool.name(),
            format!("{tool:?}").to_lowercase(),
            "{tool:?} does not answer to its own name"
        );
    }
}

/// Every variant must advertise its *own* input struct.
///
/// `input_schema` was a seven-arm match with nothing tying an arm to its variant,
/// so `Self::Ls => schema_for!(GrepInput)` compiled and — before this test —
/// passed the whole suite, while the model was handed the wrong argument schema
/// and every `ls` call failed at parse time (#55). Each tool's schema now comes
/// from its own module, which narrows what is left to catch to a module naming a
/// neighbour's input struct, or a transposed `spec` arm. Neither is ruled out by
/// the compiler, so this stays.
///
/// The tie is `title`: schemars emits the struct's own name there, so asserting
/// it against the variant name plus `Input` pins each arm to one struct. That
/// depends on the naming convention holding; a struct renamed out of it fails
/// here, which is the intended prompt to update both together.
///
/// A required-property check is not enough on its own. `ReadInput` and `LsInput`
/// are both a lone `path`, so a transposition between those two is invisible to
/// anything that only compares required names.
#[test]
fn every_tool_advertises_its_own_input_struct() {
    for tool in BuiltinTool::ALL {
        let expected = format!("{tool:?}Input");

        assert_eq!(
            tool.input_schema().get("title").and_then(|t| t.as_str()),
            Some(expected.as_str()),
            "{tool:?} advertises a schema for the wrong input struct"
        );
    }
}

/// Every tool must carry its own model-facing prose.
///
/// The description is the one field the model actually steers on, and it is the
/// one of the four nothing can tie to its variant: no content heuristic relates
/// "List a directory's entries" to `ls` — the obvious one, that a description
/// names its own tool, is false for `bash`, `edit`, `ls` and `grep`. So a
/// deliberate swap of two descriptions stays writable, and living in the tool's
/// own module beside the `execute` whose rustdoc contradicts it is the whole
/// mitigation.
///
/// Distinctness is what catches the copied-from-a-neighbour case. Non-empty alone
/// would not, and neither would a length check.
#[test]
fn every_tool_describes_itself_distinctly() {
    let mut seen = std::collections::BTreeMap::new();

    for tool in BuiltinTool::ALL {
        let description = tool.description();

        assert!(
            !description.trim().is_empty(),
            "{tool:?} has no description, so the model has no guide to it"
        );
        // Prose, not a restatement of the name the model was already given.
        assert_ne!(
            description.trim(),
            tool.name(),
            "{tool:?} only restates its own name"
        );
        // These are written with `\` line continuations, which strip the newline
        // *and* the indentation after it — so a missing space before the
        // backslash silently joins two words, and `cargo fmt` will not say so.
        assert!(
            !description.contains("  ") && !description.contains('\n'),
            "{tool:?} has broken line-continuation spacing: {description:?}"
        );

        // The point of the test: a copied arm leaves two tools claiming the
        // same prose, and the model cannot tell them apart.
        if let Some(other) = seen.insert(description, tool) {
            panic!("{tool:?} and {other:?} share one description");
        }
    }
}
