//! What the model is told about where it is and what it may call, before the first request.
//!
//! Its own module because it changes for a different reason than the rest of `agent-run`.
//! A run that names its roots and its approved tools up front spends no rounds probing
//! refused paths or reaching for refused tools (#178, #197).

use std::path::{Path, PathBuf};

use sandbx_core::{Axis, SandboxPolicy, VettedPath};
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
    let start = start_root(policy, &roots);

    let said = [
        (approved.len() < BuiltinTool::ALL.len()).then(|| tools_line(&approved)),
        (!roots.is_empty()).then(|| roots_line(&named(&roots), start.as_deref())),
        operator.map(ToString::to_string),
    ];

    let prompt = said.into_iter().flatten().collect::<Vec<_>>().join("\n\n");

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
/// refused may decline a command that would in fact have started. `start` is `None` where
/// there is nothing true to say: either the policy grants nowhere to be and the cwd is
/// inherited, or [`start_root`] dropped a directory this sentence leaves out.
fn roots_line(roots: &[String], start: Option<&Path>) -> String {
    let starts_in = start.map_or_else(String::new, |root| {
        format!(
            " A `bash` command starts in {}, and a relative path in one resolves from there.",
            root.display()
        )
    });

    format!(
        "Your tools take absolute paths and reach only these directories and what they \
         contain: {}.{starts_in} Apart from the system binaries a command needs to start, \
         every other path is refused; do not search for one.",
        roots.join(", ")
    )
}

/// The granted roots worth naming, each with the access it carries.
///
/// The system binaries every run gets are left out, being a host map in a transcript. One
/// entry per path and not per grant, the derived default granting read and write on one root.
fn work_roots(policy: &SandboxPolicy) -> Vec<(PathBuf, Vec<&'static str>)> {
    let system = spellings(&SandboxPolicy::default().allow_system_executables());
    let mut roots: Vec<(PathBuf, Vec<&'static str>)> = Vec::new();

    for (axis, granted) in policy.granted_paths() {
        // Re-vetted only as a test, never named: the guard compares the grant whole, so a root
        // resolving elsewhere, holding another directory, or gone grants nothing.
        if !VettedPath::vet(granted.path()).is_ok_and(|now| &now == granted) {
            continue;
        }
        let path = granted.path().to_path_buf();

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
}

/// [`work_roots`] as the sentence spells them.
fn named(roots: &[(PathBuf, Vec<&str>)]) -> Vec<String> {
    roots
        .iter()
        .map(|(path, access)| format!("{} ({})", path.display(), access.join(", ")))
        .collect()
}

/// Where a command starts, when that is one of the roots [`work_roots`] named.
///
/// Both spellings come off the same grants, so the two cannot name one directory two ways.
/// Dropped when absent from the list: under `--allow-read /usr --allow-read /work` a command
/// starts in the system binaries, which the sentence leaves out and calls refused.
fn start_root(policy: &SandboxPolicy, roots: &[(PathBuf, Vec<&str>)]) -> Option<PathBuf> {
    let start = policy.working_root()?.to_path_buf();

    roots
        .iter()
        .any(|(named, _)| *named == start)
        .then_some(start)
}

/// Every path `policy` grants, in the form the guard compares against.
fn spellings(policy: &SandboxPolicy) -> Vec<PathBuf> {
    policy
        .granted_paths()
        .map(|(_, path)| path.path().to_path_buf())
        .collect()
}

#[cfg(test)]
#[path = "agent_orientation_tests.rs"]
mod tests;
