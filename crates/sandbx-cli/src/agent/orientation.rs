//! What the model is told about where it is and what it may call, before the first request.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`.
//! A run that names its roots and its approved tools up front spends no rounds probing
//! refused paths or reaching for refused tools (#178, #197).

use std::path::PathBuf;

use sandbx_core::{Axis, SandboxPolicy};
use sandbx_tools::BuiltinTool;

use super::gate;

/// The system prompt one run sends: its approved tools, its roots, then the operator's.
///
/// `--system` is appended rather than replacing: an operator who overrode the roots by
/// accident would be back to probing. A section with nothing to say is left out — naming
/// all seven tools describes a boundary the run does not have.
pub(super) fn system_prompt(
    policy: &SandboxPolicy,
    allowed: Option<&[BuiltinTool]>,
    operator: Option<&str>,
) -> Option<String> {
    let approved = gate::approved_tools(allowed);
    let roots = work_roots(policy);

    let said = [
        (approved.len() < BuiltinTool::ALL.len()).then(|| tools_line(&approved)),
        (!roots.is_empty()).then(|| roots_line(&roots)),
        operator.map(ToString::to_string),
    ];

    let prompt = said
        .into_iter()
        .flatten()
        .collect::<Vec<String>>()
        .join("\n\n");

    (!prompt.is_empty()).then_some(prompt)
}

/// The tools sentence, as the model reads it.
///
/// Says the rest are offered rather than absent: the request carries all seven schemas,
/// so a model told these are its only tools would distrust the list in front of it.
fn tools_line(approved: &[&str]) -> String {
    format!(
        "Only these tools are approved for this run: {}. The others are offered but \
         refused, and a call to one comes back without running; do not reach for one.",
        approved.join(", ")
    )
}

/// The roots sentence, as the model reads it.
///
/// It admits the system binaries without listing them: a model told every other path is
/// refused may decline a command that would in fact have started.
fn roots_line(roots: &[String]) -> String {
    format!(
        "Your tools take absolute paths and reach only these directories and what they \
         contain: {}. Apart from the system binaries a command needs to start, every other \
         path is refused; do not search for one.",
        roots.join(", ")
    )
}

/// The granted roots worth naming, each with the access it carries.
///
/// The system binaries every run gets are left out, being a host map in a transcript. One
/// entry per path and not per grant, the derived default granting read and write on one root.
fn work_roots(policy: &SandboxPolicy) -> Vec<String> {
    let system = canonical(&SandboxPolicy::default().allow_system_executables());
    let mut roots: Vec<(PathBuf, Vec<&str>)> = Vec::new();

    for (axis, path) in policy.granted_paths() {
        // Named as `FsGuard::new` holds it: it canonicalizes every root and discards the
        // ones that do not resolve, so a grant resolving to nothing reaches nothing, and a
        // relative one is reachable only by the absolute form the tools demand.
        let Ok(path) = path.canonicalize() else {
            continue;
        };

        if system.contains(&path) {
            continue;
        }

        let access = match axis {
            Axis::Read => "read",
            Axis::Write => "write",
            Axis::ReadExecute => "run",
        };

        match roots.iter_mut().find(|(known, _)| *known == path) {
            // `--allow-read X --allow-write X` grants read twice, `Grants::policy` adding
            // it to every write, and `(read, read, write)` reads as a second grant.
            Some((_, held)) if !held.contains(&access) => held.push(access),
            Some(_) => {}
            None => roots.push((path, vec![access])),
        }
    }

    roots
        .into_iter()
        .map(|(path, access)| format!("{} ({})", path.display(), access.join(", ")))
        .collect()
}

/// Every path `policy` grants, in the form the guard compares against.
fn canonical(policy: &SandboxPolicy) -> Vec<PathBuf> {
    policy
        .granted_paths()
        .filter_map(|(_, path)| path.canonicalize().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    /// A directory that exists, an unresolvable grant being named by neither the guard nor
    /// the prompt, and its canonical name, which is the form the prompt holds.
    fn work() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("a temp dir");
        let named = dir
            .path()
            .canonicalize()
            .expect("it exists")
            .display()
            .to_string();
        (dir, named)
    }

    /// The prompt a default run sends. Never `None`: four of the seven tools are always
    /// approved, so there is always a set to name.
    fn granted(policy: SandboxPolicy) -> String {
        system_prompt(&policy, None, None).expect("the approved tools are always named")
    }

    /// The prompt a real invocation produces.
    ///
    /// Driven through argv because the duplicate `read` the `sandbx-core` builder cannot
    /// produce is what `Grants::policy` adds alongside every write.
    fn derived(argv: &[&str]) -> String {
        let args = match crate::Cli::parse_from(argv).command {
            crate::Command::AgentRun(args) => args,
            other => panic!("{other:?} is not agent-run"),
        };

        system_prompt(
            &args.policy().expect("a derived policy"),
            args.allow_tool.as_deref(),
            None,
        )
        .expect("a root to name")
    }

    #[test]
    fn the_prompt_names_a_granted_root_and_its_access() {
        let (work, named) = work();
        let prompt = granted(
            SandboxPolicy::default()
                .allow_read(work.path())
                .allow_write(work.path()),
        );

        assert!(
            prompt.contains(&format!("{named} (read, write)")),
            "a root granted twice should be named once, with both; got {prompt:?}"
        );
    }

    /// The README's own `agent-run` line, for which `(read, read, write)` would read as a
    /// grant the run does not hold.
    #[test]
    fn a_root_granted_read_and_write_is_named_once_each() {
        let (work, named) = work();
        let path = work.path().to_str().expect("utf-8");

        let prompt = derived(&[
            "sandbx",
            "agent-run",
            "--allow-read",
            path,
            "--allow-write",
            path,
            "--",
            "go",
        ]);

        assert!(
            prompt.contains(&format!("{named} (read, write)")),
            "got {prompt:?}"
        );
    }

    /// The flags take a path verbatim, and the tools take only absolute ones — so a grant
    /// named as given would send the model looking for the form it can actually pass.
    #[test]
    fn a_grant_is_named_in_the_form_the_guard_holds() {
        let (work, named) = work();
        // Absolute but not canonical, which `..` makes without a `chdir` a sibling test
        // would race against.
        let detour = work.path().join("inner").join("..");
        std::fs::create_dir(work.path().join("inner")).expect("a nested dir");

        let prompt = granted(SandboxPolicy::default().allow_read(&detour));

        assert!(
            prompt.contains(&format!("{named} (read)")),
            "got {prompt:?}"
        );
        assert!(
            !prompt.contains(".."),
            "the grant was named as given: {prompt:?}"
        );
    }

    /// Compared against the whole tools sentence: a roots sentence over an empty list names
    /// no path either, so a check for one would pass with the guard gone.
    #[test]
    fn a_grant_that_resolves_to_nothing_is_not_named() {
        let prompt = granted(SandboxPolicy::default().allow_read("/no/such/root"));

        assert_eq!(
            prompt,
            tools_line(&gate::approved_tools(None)),
            "the guard discards a root it cannot resolve, so the prompt must not claim it"
        );
    }

    #[test]
    fn a_read_only_root_is_never_named_as_writable() {
        let (work, named) = work();
        let prompt = granted(SandboxPolicy::default().allow_read(work.path()));

        assert!(
            prompt.contains(&format!("{named} (read)")),
            "got {prompt:?}"
        );
        assert!(!prompt.contains("write"), "got {prompt:?}");
    }

    #[test]
    fn the_system_binaries_stay_out_of_the_prompt() {
        let prompt = granted(SandboxPolicy::default().allow_system_executables());

        assert_eq!(
            prompt,
            tools_line(&gate::approved_tools(None)),
            "a run granted nothing of its own has no roots to name"
        );
    }

    /// Owned up to without being listed: a model that read "every other path is refused"
    /// may decline a command the sandbox would have let start.
    #[test]
    fn the_sentence_admits_the_system_binaries_exist() {
        let (work, _) = work();
        let prompt = granted(SandboxPolicy::default().allow_read(work.path()));

        assert!(prompt.contains("system binaries"), "got {prompt:?}");
        assert!(
            !prompt.contains("/usr/bin"),
            "the host was mapped: {prompt:?}"
        );
    }

    #[test]
    fn the_prompt_names_the_tools_a_run_approved() {
        let prompt = granted(SandboxPolicy::default());

        assert!(prompt.contains("read, ls, grep, find"), "got {prompt:?}");
        assert!(
            !prompt.contains("bash"),
            "a refused tool was named as approved: {prompt:?}"
        );
    }

    /// The tool the model reached for second, having spent a round on `write` first (#197).
    #[test]
    fn an_approved_tool_joins_the_named_set() {
        let prompt = system_prompt(&SandboxPolicy::default(), Some(&[BuiltinTool::Edit]), None)
            .expect("the approved tools are named");

        assert!(
            prompt.contains("read, edit, ls, grep, find"),
            "got {prompt:?}"
        );
        assert!(!prompt.contains("write"), "got {prompt:?}");
    }

    /// A bare `--allow-tool` refuses nothing, so a sentence about the rest describes no run.
    #[test]
    fn no_tool_is_named_when_every_tool_is_approved() {
        let (work, named) = work();
        let prompt = system_prompt(
            &SandboxPolicy::default().allow_read(work.path()),
            Some(&[]),
            None,
        )
        .expect("a root to name");

        assert!(prompt.contains(&named), "got {prompt:?}");
        assert!(!prompt.contains("bash"), "got {prompt:?}");
    }

    #[test]
    fn nothing_is_sent_when_there_is_nothing_to_say() {
        assert_eq!(
            system_prompt(&SandboxPolicy::default(), Some(&[]), None),
            None
        );
    }

    /// The model cannot pass a flag mid-turn; `gate::decide`'s refusal is where it reads one.
    #[test]
    fn the_prompt_never_names_the_flag_to_the_model() {
        let prompt = granted(SandboxPolicy::default());

        assert!(!prompt.contains(gate::ALLOW_TOOL), "got {prompt:?}");
    }

    #[test]
    fn the_roots_sit_between_the_tools_and_the_operator() {
        let (work, named) = work();
        let prompt = system_prompt(
            &SandboxPolicy::default().allow_read(work.path()),
            None,
            Some("be terse"),
        )
        .expect("all three sections");

        let tools = prompt.find("grep").expect("the approved tools");
        let roots = prompt.find(&named).expect("the roots");
        let operator = prompt.find("be terse").expect("the operator's text");
        assert!(tools < roots && roots < operator, "got {prompt:?}");
    }

    /// Nothing granted and nothing refused, so there is no boundary left to describe.
    #[test]
    fn an_operator_prompt_can_be_the_whole_prompt() {
        assert_eq!(
            system_prompt(&SandboxPolicy::default(), Some(&[]), Some("be terse")).as_deref(),
            Some("be terse")
        );
    }
}
