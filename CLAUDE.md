# sandbx

A security-first AI coding agent harness. Seven crates; the version is in the
workspace `Cargo.toml`.

Where to look, and where to put something new:

| Question | Home |
|---|---|
| onboarding onto the repo | `context/onboarding/` |
| how a subsystem works | `context/guide-*.md` |
| why a design went the way it did | `context/decision-*.md` |
| which crate owns what, and what depends on what | `context/guide-repo-map.md` |
| what runs before a push, and what runs after | `context/guide-ci.md` |
| what a code comment may say, and how long | `context/guide-code-comments.md` |
| how long a name may be, and what to cut first | `context/guide-naming.md` |
| a module's budget, where its tests live, what one must assert | `context/guide-module-layout.md` |
| what is claimed, and what is not | `SECURITY.md` |
| what was planned and is still missing | an open issue |
| which crates a change lands in | its `crate:*` labels |
| what shipped in which release | GitHub releases, and that release's milestone |

`SECURITY.md` may never overstate the sandbox. Where the mechanism and the claim
disagree, one of them changes — the claim is weakened, or the mechanism is
widened to match. Neither is left to drift.

There is no roadmap file. Planned-but-missing work goes on an issue, where it can
be closed; a decision that held goes in a `decision-*.md`. If you are about to
write "planned" into a doc, file an issue instead.

Milestones are releases, one per tag: a closed issue or PR takes the one it
shipped in, and open work being worked on now takes the next one. None is not a
defect — it means unscheduled. A `crate:*` label per crate it materially touches
— none where the change is workspace-wide or outside `crates/`.

## Before opening a PR

For a branch with a significant code change, in this order:

1. `/code-review`
2. `/security-review`
3. the comment pass

Code review first: it surfaces correctness problems that would otherwise show up
as phantom security findings. The comment pass last: both reviews land fixes, and
a fix rewords comments. Fix what each pass reports before moving to the next.
Docs-only, comment-only and test-rename branches need neither review — though the
comment pass still applies to a comment-only branch.

**Confirm what each review read, before believing it.** Both commands collect
their own diff from the session's working directory, and three failure modes
report "no findings" indistinguishably from a clean branch. So re-measure
`git diff --stat origin/main...HEAD` for every pass, compare it against the SHA
and diffstat the command reports, and pass the worktree path and the expected
diffstat to every invocation.

- **Three dots, not two.** `origin/main..HEAD` drifts with no commit of the
  branch's own and still reads as current.
- **An empty diff**, from a cwd that is not where the work is — a session in the
  main checkout while the branch lives in a `git worktree`. The tell is the cwd's
  branch, not only a diffstat mismatch.
- **A stale diff**, a tree some commits behind the head, where the diffstat is
  the only tell. `git diff | wc -l` is not the diffstat.

A review over the wrong lines is not a pass.

The comment pass: read every comment the branch added or touched against
`context/guide-code-comments.md`, and trim what is over budget. A trim that
deletes a kernel quirk, an ordering requirement or the origin of an ABI number
has failed however much shorter it made the file.
