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
        // exists but was never listed.
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
/// `Debug`'s spelling of the variant is the tie: nothing derives the name, so a
/// swapped pair stays unique and still round-trips. A variant whose name is not its
/// lowercased spelling (`MultiEdit` against `multi_edit`) also fails here.
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
/// Nothing the compiler checks stops a transposed `spec` arm, or a module naming a
/// neighbour's input struct. The tie is schemars' `title`, the struct's own name, so
/// a struct renamed out of the `<Variant>Input` convention fails too. Required
/// properties would not do: `ReadInput` and `LsInput` are both a lone `path`.
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
/// Spelled out rather than read off `risk()`: an expectation derived from the same
/// `SPEC`s would pass a `bash` reclassified as read-only.
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

/// A gate admits everything at or below a level, so alphabetising the enum would keep
/// every other test green while inverting the meaning of each `<=`.
#[test]
fn the_risk_levels_order_least_to_most() {
    assert!(RiskLevel::ReadOnly < RiskLevel::Writes);
    assert!(RiskLevel::Writes < RiskLevel::Executes);
}

/// Every tool must carry its own model-facing prose.
///
/// The description is what the model steers on, and the one `SPEC` field nothing can
/// tie to its variant: a description naming its own tool is false for `bash`, `edit`,
/// `ls` and `grep`. Living beside the `execute` it describes is the mitigation; what
/// is testable is distinctness, which catches a copy from a neighbour.
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
