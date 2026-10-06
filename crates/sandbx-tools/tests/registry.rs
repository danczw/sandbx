//! The set of tools an agent can be offered, and lookup by the name the model
//! calls back with.

use sandbx_tools::{BuiltinTool, RiskLevel};

/// Exhaustive by construction: a variant missing from `ALL` fails here, not at
/// runtime in front of a model.
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
        // The match is what the compiler checks; the assert catches a variant that
        // exists but was never listed in `ALL`.
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

/// Names reach the model as an API tool list; a collision makes one of them
/// permanently unreachable.
#[test]
fn names_are_unique() {
    let mut names: Vec<&str> = BuiltinTool::ALL.iter().map(BuiltinTool::name).collect();
    names.sort_unstable();
    let count = names.len();
    names.dedup();

    assert_eq!(names.len(), count, "duplicate tool name");
}

/// A hallucinated tool must be a lookup miss the agent can report, not a panic.
#[test]
fn an_unknown_name_is_not_a_tool() {
    assert_eq!(BuiltinTool::from_name("rm"), None);
    assert_eq!(BuiltinTool::from_name(""), None);
}

#[test]
fn lookup_does_not_normalise_the_name() {
    assert_eq!(BuiltinTool::from_name("Read"), None);
    assert_eq!(BuiltinTool::from_name("read "), None);
}

/// A tool's name is its variant, lowercased.
///
/// Nothing derives it, so swapping two names stays unique and still round-trips:
/// `names_are_unique` sees only a half-swap, and the round-trip above is
/// self-consistent either way. `Debug`'s spelling of the variant is the tie, which
/// also makes a variant whose name is not its lowercased spelling (`MultiEdit`
/// against `multi_edit`) fail here.
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

/// Every variant must advertise its own input struct.
///
/// Nothing the compiler checks stops a module naming a neighbour's input struct, or
/// a transposed `spec` arm. The tie is `title`, where schemars emits the struct's
/// own name, so a struct renamed out of the `<Variant>Input` convention fails here.
/// Comparing required properties instead would miss it: `ReadInput` and `LsInput`
/// are both a lone `path`.
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

/// Every tool must declare what it does beyond looking.
///
/// Spelled out here rather than read off `risk()`: an expectation derived from the same
/// `SPEC`s moves with them, so a `bash` reclassified as read-only would still pass. An
/// approval gate admitting everything at or below `ReadOnly` is what rests on this.
#[test]
fn the_risk_each_tool_carries_is_documented() {
    for tool in BuiltinTool::ALL {
        let expected = match tool {
            BuiltinTool::Read | BuiltinTool::Ls | BuiltinTool::Grep | BuiltinTool::Find => {
                RiskLevel::ReadOnly
            }
            BuiltinTool::Write | BuiltinTool::Edit => RiskLevel::Writes,
            BuiltinTool::Bash => RiskLevel::Executes,
        };

        assert_eq!(tool.risk(), expected, "{tool:?} is classified wrongly");
    }
}

/// Every tool must carry its own model-facing prose.
///
/// The description is the field the model steers on and the one of the four nothing
/// can tie to its variant: no heuristic relates "List a directory's entries" to
/// `ls`, and a description naming its own tool is false for `bash`, `edit`, `ls` and
/// `grep`. Living beside the `execute` it describes is the whole mitigation; what is
/// testable is distinctness, which catches the copied-from-a-neighbour case.
#[test]
fn every_tool_describes_itself_distinctly() {
    let mut seen = std::collections::BTreeMap::new();

    for tool in BuiltinTool::ALL {
        let description = tool.description();

        assert!(
            !description.trim().is_empty(),
            "{tool:?} has no description, so the model has no guide to it"
        );
        assert_ne!(
            description.trim(),
            tool.name(),
            "{tool:?} only restates its own name"
        );
        // Descriptions use `\` line continuations, which strip the newline and the
        // indentation after it: a missing space before the backslash joins two
        // words, and `cargo fmt` will not say so.
        assert!(
            !description.contains("  ") && !description.contains('\n'),
            "{tool:?} has broken line-continuation spacing: {description:?}"
        );

        if let Some(other) = seen.insert(description, tool) {
            panic!("{tool:?} and {other:?} share one description");
        }
    }
}
