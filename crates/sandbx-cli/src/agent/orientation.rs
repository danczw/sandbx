//! What the model is told about where it is, before the first request.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`:
//! what the model is told, not what was asked or allowed. A run that names its roots up
//! front spends no rounds probing paths the sandbox refuses (#178).

use std::path::PathBuf;

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
///
/// The system binaries are owned up to without being listed: a model told every other path
/// is refused may decline to run a command that would in fact have started.
fn orientation(roots: &[String]) -> String {
    format!(
        "Your tools take absolute paths and reach only these directories and what they \
         contain: {}. Apart from the system binaries a command needs to start, every other \
         path is refused; do not search for one.",
        roots.join(", ")
    )
}

/// The granted roots worth naming, each with the access it carries.
///
/// The system binaries every run gets are left out: they are noise to a model, and a host
/// map in a transcript. One entry per path and not per grant, since the derived default
/// grants read and write on the same root.
fn work_roots(policy: &SandboxPolicy) -> Vec<String> {
    let system = canonical(&SandboxPolicy::default().allow_system_executables());
    let mut roots: Vec<(PathBuf, Vec<&str>)> = Vec::new();

    for (axis, path) in policy.granted_paths() {
        // Named as `FsGuard::new` holds it: it canonicalizes every root and discards the
        // ones that do not resolve, so a grant that resolves to nothing reaches nothing,
        // and a relative one — the flags take a path verbatim — is reachable only by its
        // absolute form, which is the form the tools demand.
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

    /// A directory that exists, since an unresolvable grant is named by neither the guard
    /// nor the prompt, and its canonical name, which is what the prompt will hold.
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

    fn granted(policy: SandboxPolicy) -> Option<String> {
        system_prompt(&policy, None)
    }

    /// The prompt a real invocation produces, grants and all.
    ///
    /// Driven through argv rather than the `sandbx-core` builder, because the duplicate
    /// `read` the builder cannot produce is exactly what `Grants::policy` adds: it grants
    /// read alongside every write, so `--allow-read X --allow-write X` holds read twice.
    fn derived(argv: &[&str]) -> String {
        let args = match crate::Cli::parse_from(argv).command {
            crate::Command::AgentRun(args) => args,
            other => panic!("{other:?} is not agent-run"),
        };

        system_prompt(&args.policy().expect("a derived policy"), None).expect("a root to name")
    }

    #[test]
    fn the_prompt_names_a_granted_root_and_its_access() {
        let (work, named) = work();
        let prompt = granted(
            SandboxPolicy::default()
                .allow_read(work.path())
                .allow_write(work.path()),
        )
        .expect("a granted root is worth naming");

        assert!(
            prompt.contains(&format!("{named} (read, write)")),
            "a root granted twice should be named once, with both; got {prompt:?}"
        );
    }

    /// The README's own `agent-run` line. `Grants::policy` grants read twice for it, and
    /// `(read, read, write)` would read as a grant the run does not hold.
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

        let prompt = granted(SandboxPolicy::default().allow_read(&detour)).expect("a root");

        assert!(
            prompt.contains(&format!("{named} (read)")),
            "got {prompt:?}"
        );
        assert!(
            !prompt.contains(".."),
            "the grant was named as given: {prompt:?}"
        );
    }

    #[test]
    fn a_grant_that_resolves_to_nothing_is_not_named() {
        assert_eq!(
            granted(SandboxPolicy::default().allow_read("/no/such/root")),
            None,
            "the guard discards a root it cannot resolve, so the prompt must not claim it"
        );
    }

    #[test]
    fn a_read_only_root_is_never_named_as_writable() {
        let (work, named) = work();
        let prompt = granted(SandboxPolicy::default().allow_read(work.path())).expect("a root");

        assert!(
            prompt.contains(&format!("{named} (read)")),
            "got {prompt:?}"
        );
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

    /// Owned up to without being listed: a model that read "every other path is refused"
    /// may decline a command the sandbox would have let start.
    #[test]
    fn the_sentence_admits_the_system_binaries_exist() {
        let (work, _) = work();
        let prompt = granted(SandboxPolicy::default().allow_read(work.path())).expect("a root");

        assert!(prompt.contains("system binaries"), "got {prompt:?}");
        assert!(
            !prompt.contains("/usr/bin"),
            "the host was mapped: {prompt:?}"
        );
    }

    #[test]
    fn an_operator_prompt_follows_the_orientation_line() {
        let (work, named) = work();
        let prompt = system_prompt(
            &SandboxPolicy::default().allow_read(work.path()),
            Some("be terse"),
        )
        .expect("both halves");

        let roots = prompt.find(&named).expect("the roots");
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
