# sandbx

A security-first AI coding agent harness. Seven crates; the version is in the
workspace `Cargo.toml`.

Where to look, and where to put something new:

| Question | Home |
|---|---|
| how a subsystem works | `context/guide-*.md` |
| why a design went the way it did | `context/decision-*.md` |
| which crate owns what, and what depends on what | `context/guide-repo-map.md` |
| how long a code comment may be, and what it must not say | `context/guide-code-comments.md` |
| how long a name may be, and what to cut first | `context/guide-naming.md` |
| how long a module may be, and where its tests belong | `context/guide-module-layout.md` |
| what is claimed, and what is not | `SECURITY.md` |
| what was planned and is still missing | an open issue, on a phase milestone |
| when open work happens, and what it waits on | GitHub milestones, one per phase |
| what shipped in which release | GitHub releases |

There is no roadmap file. There was a `context/plan.md`; it was dissolved because
every line of it belonged somewhere that could not fall out of step with the code.
Planned-but-missing work goes on an issue, where it can be closed. Scheduling goes
on a milestone, which travels with the issue. A decision that held goes in a
`decision-*.md`. If you are about to write "planned" into a doc, file an issue
instead.

## Before opening a PR

Read every comment the branch added or touched against
`context/guide-code-comments.md`, and trim what is over budget. Restatement,
history, rejected alternatives, narration and prose that belongs in
`context/*.md` come out; a kernel quirk, an ordering requirement or the origin of
an ABI number stays, compressed to the load-bearing clause. A trim that deletes
one of those has failed however much shorter it made the file.

This runs before the PR exists, not after: review comments on wording that was
about to be cut anyway cost two passes.

## Review before merging

For a PR with a significant code change, run both skills before merging, in this
order:

1. `/code-review`
2. `/security-review`

Code review first: it surfaces correctness problems that would otherwise show up
as phantom security findings. Fix what each pass reports before moving to the
next. Docs-only, comment-only, or test-rename PRs do not need either — but the
comment pass above still applies to a comment-only PR, which is the one case
where it is the whole diff.
