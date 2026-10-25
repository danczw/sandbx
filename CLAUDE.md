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
| how the code is written, and where it departs | `context/decision-google-style.md` |
| what a test must assert, where it lives, how long its name may be | `context/guide-testing.md` |
| what is claimed, and what is not | `SECURITY.md` |
| what was planned and is still missing | an open issue |
| which crates a change lands in | its `crate:*` labels |
| what shipped in which release | GitHub releases, and that release's milestone |

The code follows the [Google Rust style
guide](https://google.github.io/styleguide/rustguide.html) — every rule except
those marked *(Chrome)* — except where `context/decision-google-style.md` records
otherwise. While #328's migration runs, existing code is exempt from a rule until
the phase that fixes it has landed; new and changed code follows the guide.

`SECURITY.md` may never overstate the sandbox. Where the mechanism and the claim
disagree, one of them changes — the claim is weakened, or the mechanism is
widened to match. Neither is left to drift.

There is no roadmap file. Planned-but-missing work goes on an issue, where it can
be closed. A *why* earns a place in a crate's `//!` or a `decision-*.md` only if it
backs a `SECURITY.md` claim or warns off an alternative likely to be re-proposed;
otherwise it lives in its issue or PR, cited by number. If you are about to write
"planned" into a doc, file an issue instead.

Issue bodies, PR bodies and comments are **never hard-wrapped**: one sentence is
one line, however long. GitHub reflows them to the reader's width, so a linebreak
inserted mid-sentence shows up as a ragged break nobody chose, and it makes a
later edit re-wrap half the paragraph. The files under `context/`, `SECURITY.md`
and `README.md` are the exception — they are hard-wrapped at ~80 columns
throughout, and an edit there matches the paragraph it lands in rather than
starting a second convention.

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

The comment pass: read every comment the branch added or touched against the Google
guide's documentation rules, and cut what does not earn its line — a restated name, a
type the signature already names, narration, a banner, history that `git log` and the
issue tracker already hold.

Five things are never trimmed, however much shorter it would make the file:

- Why a sequence cannot be reordered.
- Why a syscall, flag or apparent redundancy is required.
- Where a magic constant or ABI number comes from.
- An asymmetry the type system does not enforce (`ReadExecute` confers read;
  nothing confers execute).
- A workaround, and the condition that would let it go.

Compress those to the load-bearing clause; do not delete them to hit a number. Over
budget is a rewrite, not a deletion — find the sentence doing the work and keep that
one. Three traps in the pass itself:

- **clap's `--help` text and schemars' `description` docs are not commentary.** They
  are rendered output, and the exemption follows the item, not the file. Capture
  `--help` before and after, or a trim silently edits the CLI.
- **rustfmt does not wrap comments.** Merging four comment lines into one 216-column
  line reads as three lines cut and passes `cargo fmt --check` silently, so check
  widths in the same pass.
- **A comment-only change leaves the code byte-identical.** `git diff -U0` with the
  comment lines stripped must print nothing. If it prints anything, the branch is not
  comment-only and needs the reviews above.
