//! What the model is told about where it is, before the first request.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`:
//! what the model is told, not what was asked or allowed. A run that names its roots up
//! front spends no rounds probing paths the sandbox refuses (#178).

use sandbx_core::{Axis, SandboxPolicy};

/// The system prompt one run sends: the roots its tools can reach, then the operator's.
///
/// The orientation comes first and `--system` does not replace it: the roots are a fact
/// about the run, and an operator who overrode them by accident would be back to probing.
pub(super) fn system_prompt(policy: &SandboxPolicy, operator: Option<&str>) -> Option<String> {
    let roots = work_roots(policy);

    match (roots.is_empty(), operator) {
        (true, operator) => operator.map(ToString::to_string),
        (false, None) => Some(orientation(&roots)),
        (false, Some(operator)) => Some(format!("{}\n\n{operator}", orientation(&roots))),
    }
}

/// The roots sentence, as the model reads it.
fn orientation(roots: &[String]) -> String {
    format!(
        "Your tools take absolute paths and reach only these directories and what they \
         contain: {}. Every other path is refused; do not search for one.",
        roots.join(", ")
    )
}

/// The granted roots worth naming, each with the access it carries.
///
/// The system binaries every run gets are left out: they are noise to a model, and a host
/// map in a transcript. One entry per path and not per grant, since the derived default
/// grants read and write on the same root.
fn work_roots(policy: &SandboxPolicy) -> Vec<String> {
    let system = SandboxPolicy::default().allow_system_executables();
    let mut roots: Vec<(&std::path::Path, Vec<&str>)> = Vec::new();

    for (axis, path) in policy.granted_paths() {
        if system.paths(axis).iter().any(|granted| granted == path) {
            continue;
        }

        let access = match axis {
            Axis::Read => "read",
            Axis::Write => "write",
            Axis::ReadExecute => "run",
        };

        match roots.iter_mut().find(|(known, _)| *known == path) {
            Some((_, held)) => held.push(access),
            None => roots.push((path, vec![access])),
        }
    }

    roots
        .into_iter()
        .map(|(path, access)| format!("{} ({})", path.display(), access.join(", ")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn granted(policy: SandboxPolicy) -> Option<String> {
        system_prompt(&policy, None)
    }

    #[test]
    fn the_prompt_names_a_granted_root_and_its_access() {
        let prompt = granted(
            SandboxPolicy::default()
                .allow_read("/work")
                .allow_write("/work"),
        )
        .expect("a granted root is worth naming");

        assert!(
            prompt.contains("/work (read, write)"),
            "a root granted twice should be named once, with both; got {prompt:?}"
        );
    }

    #[test]
    fn a_read_only_root_is_never_named_as_writable() {
        let prompt = granted(SandboxPolicy::default().allow_read("/work")).expect("a root");

        assert!(prompt.contains("/work (read)"), "got {prompt:?}");
        assert!(!prompt.contains("write"), "got {prompt:?}");
    }

    #[test]
    fn the_system_binaries_stay_out_of_the_prompt() {
        assert_eq!(
            granted(SandboxPolicy::default().allow_system_executables()),
            None,
            "a run granted nothing of its own has no roots to name"
        );
    }

    #[test]
    fn an_operator_prompt_follows_the_orientation_line() {
        let prompt = system_prompt(
            &SandboxPolicy::default().allow_read("/work"),
            Some("be terse"),
        )
        .expect("both halves");

        let roots = prompt.find("/work").expect("the roots");
        let operator = prompt.find("be terse").expect("the operator's text");
        assert!(roots < operator, "got {prompt:?}");
    }

    #[test]
    fn an_operator_prompt_is_sent_alone_when_nothing_is_granted() {
        assert_eq!(
            system_prompt(&SandboxPolicy::default(), Some("be terse")).as_deref(),
            Some("be terse")
        );
    }
}
