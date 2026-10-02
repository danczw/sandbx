# sandbx

A security-first AI coding agent harness. Seven crates, at `v0.1.0-alpha.5`.

Where to look, and where to put something new:

| Question | Home |
|---|---|
| how a subsystem works | `context/guide-*.md` |
| why a design went the way it did | `context/decision-*.md` |
| which crate owns what, and what depends on what | `context/guide-repo-map.md` |
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

## Review before merging

For a PR with a significant code change, run both skills before merging, in this
order:

1. `/code-review`
2. `/security-review`

Code review first: it surfaces correctness problems that would otherwise show up
as phantom security findings. Fix what each pass reports before moving to the
next. Docs-only, comment-only, or test-rename PRs do not need either.
