# The documentation is held to the code by tests

Every other chapter stands inside one box of
[04 — the architecture](04-the-architecture.md). This one stands beside the
drawing, in front of the table that closes it: *Where each box's detail lives*,
which maps every box to the one `context/` doc that owns it. That table is the
repo's navigation surface, and this chapter is about the rules and the tests
that keep it true — what goes in a doc, what goes on an issue, what runs before
a push, and the small family of Rust tests that fail the build when prose and
code have come apart.

Read it before your first change, not after. Most of what follows is cheap to
comply with and expensive to retrofit.

## `guide-` describes, `decision-` justifies

`context/` holds two kinds of file and the distinction is strict.
[guide-repo-map.md](../guide-repo-map.md) states it in one line at the very
bottom: `guide-` describes a subsystem as it currently is; `decision-` records
why a choice was made, and stays useful after the code moves.

So a `guide-` file is expected to change when the code changes — it is wrong the
moment the code it describes moves. A `decision-` file is expected *not* to.
Several of them are records of something priced and declined, and their value
is precisely that they outlive the branch that priced it: the next person to
propose the same thing meets the reasoning rather than re-deriving it.

What a given change needs:

| the change | where it lands |
|---|---|
| a subsystem now behaves differently | the `guide-*.md` that owns it, edited in the same PR |
| you weighed an alternative and declined it | the `decision-*.md` covering that area, or a new one |
| you found something missing or broken | an issue |
| you want to say what will be built next | an issue, on a milestone |
| the claim about what the sandbox enforces moved | [`SECURITY.md`](../../SECURITY.md), in the same PR |

Two rules govern the whole directory.

- **One home per fact.** `guide-repo-map.md` is explicit that nothing measures a
  doc's length, so the bound is *placement*, not size: a fact lives in one doc,
  and a second mention is a pointer to it. This is the other end of
  [guide-code-comments.md](../guide-code-comments.md), which sends prose out of
  the code and into `context/` — so a comment that has grown into an essay
  usually means a guide needs a paragraph and the code needs a one-line pointer.
- **There is no roadmap file.** [`CLAUDE.md`](../../CLAUDE.md) says it directly:
  planned-but-missing work goes on an issue, where it can be closed, and "if you
  are about to write 'planned' into a doc, file an issue instead."
  [guide-release-notes.md](../guide-release-notes.md) repeats the ban for a
  release body. The reason is falsifiability — a doc saying "planned" has no way
  to stop being true, and an issue does.

A corollary that catches people: **never write a status word about an issue.**
Cite it as a bare `#NNN`, usually parenthesised, and say nothing about whether
it is open, done, fixed or planned. Status lives on GitHub, which is current; a
doc that answered the question starts being wrong the day it merges.

## The three convention guides

Three guides constrain how code is written rather than what it does. Each one is
a budget table plus a shell command that measures it, and each says explicitly
that a hit is a judgement call rather than a failure. The numbers are
deliberately not repeated here — they have changed (#245), and a figure copied
into a second file is a figure that goes stale in one of them.

| guide | what it constrains |
|---|---|
| [guide-naming.md](../guide-naming.md) | how long an identifier may be, per kind of item, with a longer allowance for test functions because the name is what a failure prints |
| [guide-code-comments.md](../guide-code-comments.md) | what a comment may say and how much of it, per kind of item, plus a per-crate ratio of comment lines to all lines |
| [guide-module-layout.md](../guide-module-layout.md) | how long a module may be counted as non-test lines, where its tests live, and what a test has to assert to assert anything |

Four things about them that the tables themselves do not say.

- **Each guide is a budget plus a measurement.** Every one of the three has a
  `## Measuring` section holding a `sh` snippet. Run the snippet, read the
  worst offenders, then read the file. `guide-module-layout.md` adds the rule
  for disagreements: a count that contradicts the module in front of you is the
  command being wrong about that module's shape, not the module being over —
  there is no second method to break the tie, only the file.
- **A hit is a rewrite, not an abbreviation or a deletion.** Over budget on a
  name means a name describing two things; over budget on a comment means
  finding the sentence doing the work and keeping that one. Both guides say that
  a pass which deletes a kernel quirk, an ordering requirement or the origin of
  an ABI number has failed however much shorter it made the file. `CLAUDE.md`
  repeats it for the comment pass, which tells you how often it goes wrong.
- **The comment ratio states its denominator in the same sentence as its
  threshold,** and the denominator is every line of every `.rs` file in the
  crate, test code included. That is not an accident of drafting.
  `guide-code-comments.md` works through the alternative: "non-test" would mean
  three incompatible things, and excluding test code makes every crate's ratio
  *worse*, a test block being mostly code carrying one doc line per test. A
  ratio whose denominator is undefined cannot be read against a threshold at
  all.
- **The ratio needs a width check in the same pass, or it is not a
  measurement.** There is no `rustfmt.toml`, so `max_width` is whatever rustfmt
  defaults to — and rustfmt does not wrap comments. Merging four comment lines
  into one very long line therefore reads as three lines cut, lowers the
  percentage, and passes `cargo fmt --check` silently. The guide ships the width
  loop next to the ratio loop for exactly that reason.

The module budget has one more property worth knowing before you split
something: it is a ceiling for headroom, not a target, and the guide says to
split when a module has two reasons to change rather than when it crosses a
number. A module that reaches the ceiling doing one thing stays whole. Do not
turn the number into a lint — and if yours is over, say so in the PR rather than
carving the code up to satisfy it.

## The hooks and CI run the same commands, on purpose

[guide-ci.md](../guide-ci.md) calls them two halves of one set of checks:
`.githooks/` runs before a commit exists, `.github/workflows/` runs after a
push. The local half is wired by one line, which is why there is no
hook-manager dependency anywhere in the repo:

```sh
git config core.hooksPath .githooks
```

`.githooks/pre-commit` runs three commands — `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, and `cargo doc` under
`RUSTDOCFLAGS="-D warnings"`. Its first comment, and the matching comment on
CI's `Clippy` step, are the whole convention:

```sh
# All three commands are byte-identical to ci.yml's Format, Clippy and Doc steps.
```

Byte-identical is a maintained property, not an observation.
[`ci.yml`](../../.github/workflows/ci.yml) carries "Byte-identical to
`.githooks/pre-commit`; keep them so" on the step itself. The payoff is a
diagnostic one: because no check in that trio exists only on one side, **a red
CI run is a hook someone skipped, not a check only CI knew about.** You never
have to ask what CI does differently, which is where an afternoon usually goes
on a repo whose two halves have drifted.

What is deliberately *not* in the hook is the test suite. A hook that takes
minutes is a hook people pass `--no-verify` to, and the three above are seconds
on a warm target directory. The doc build earns its place by being the only one
of the three that reads a doc comment at all — a broken intra-doc link passes
both fmt and clippy.

`.githooks/commit-msg` checks the **subject only**; the body is free-form. Eight
types (`feat fix docs refactor test chore build ci`), an optional scope, an
optional breaking-change `!`, and a 72-character ceiling, which the hook
annotates as the conventional limit above which logs and UIs truncate. `Merge`,
`Revert`, `fixup!`, `squash!` and `amend!` subjects are exempt because the
rebase they are made for rewrites them. Two traps fall straight out of the
pattern:

- **A scope is optional, so a change spanning crates takes none.** `docs: …` is
  valid, and inventing a scope to look consistent is worse than omitting one.
- **The scope charset is `[a-z0-9._/-]+`, so a comma is not a scope.**
  `docs(providers,session):` is refused outright; drop to no scope.

CI adds four jobs the hooks cannot run: the enforcement suite on a real kernel
for two architectures, a build at the MSRV floor the manifest states, a check
that the version in the manifest has a release-notes file, and an audit job
running cargo-deny plus zizmor over the workflows. `guide-ci.md` owns the
details, including one rule worth absorbing whatever you are writing: **a glob
that matches nothing must fail.** The `notes` job counts the files it checked
and errors on zero, because a loop over a pattern that found no file exits 0,
and a green gate that checked nothing is worse than a red one. Any check that
iterates needs the same guard.

## The Rust tests that pin prose to code

This is the part a newcomer does not expect, and the most characteristic thing
about the repo. Documentation rot is normally caught by a human noticing. Here,
where it can be, it is caught by `cargo test`.

Three mechanisms, four instances.

### A citation must name a file that exists

[`context_docs.rs`](../../crates/sandbx-core/tests/context_docs.rs) holds two
tests, and its module doc opens by admitting that neither is about
`sandbx-core`: they live there because that crate already reaches the repo root
for the floor test below, and because there is no workspace-wide test target to
put them in.

`every_doc_a_citation_names_exists` collects every file that could cite a doc —
Rust sources under `crates/`, three named root docs, and `context/` itself —
scans each for every `guide-…md` or `decision-…md` token whatever path or
punctuation surrounds it, and asserts the named file is on disk. The rot it
catches is stated in one line above the test: a rename takes the file and leaves
the citations behind, and no build step reads them.

What makes it worth reading as a model is the three things it does so that it
cannot pass vacuously, which is `guide-module-layout.md`'s "what a test has to
assert to assert anything" applied to the test itself:

```rust
    // The walk is what a lost `pending` push would silently narrow, and this file's own
    // citations would keep the count below non-zero while it read nothing else.
    for crate_dir in entries(&root.join("crates")).filter(|path| path.is_dir()) {
        assert!(
            files.iter().any(|file| file.starts_with(&crate_dir)),
            "the walk reached no source file in {}",
            crate_dir.display()
        );
    }
```

A scanner that found nothing would pass; so the test first runs the extractor
over a fixture line that plainly holds two citations and asserts it finds both.
A walk that silently narrowed would pass; so the loop above asserts the walk
reached a source file in *every* crate directory. A file set that was somehow
empty would pass; so a `cited > 0` assertion follows, counting citations found
anywhere other than this file. Each of the three closes a way for the suite to
be green while reading nothing.

One more detail worth stealing. The three root docs are a named array, not a
glob, and the comment says why: a `read_dir` of the root would also read
`CLAUDE.local.md`, which is untracked, so the set of files under test would
differ per checkout. A test whose input depends on who checked out the repo is
not a gate.

### The index must name every doc

`the_reading_order_names_every_doc`, in the same file, compares the numbered
reading order at the bottom of `guide-repo-map.md` against the `guide-`/
`decision-` files actually in `context/`, **in both directions**: a doc on disk
and not in the order fails, and an order entry with no file fails. The rot is
the one the first test cannot see — a doc added somewhere with nothing pointing
at it. The reading order is how `CLAUDE.md` reaches a doc at all, so a file
missing from it is invisible rather than merely unindexed.

Two construction details that generalise:

- **It anchors on the heading, not on a line number,** because a trim moves line
  numbers. The order is the last section, so the slice runs to end of file, and
  only numbered entries count — otherwise a closing mention below the list would
  read as indexed.
- **It asserts neither side of the comparison is empty,** with the message "one
  side of the comparison is empty, so it would agree with anything." Two empty
  sets agree perfectly. This is the single most reusable line in the file.

### Every prose copy of the Landlock floor must be current

`every_prose_copy_of_the_floor_is_current` sits beside the constants it is
about, in
[`compat.rs`](../../crates/sandbx-core/src/helper/ruleset/tests/compat.rs)
under `sandbx-core`'s `helper/ruleset/`. The floor — the lowest Landlock ABI
sandbx will enforce under, and the kernel version that implies — has exactly one
home in the code, named by the `BASELINE_ABI` and `BASELINE_KERNEL` constants,
and [`SECURITY.md`](../../SECURITY.md) is the normative statement of it. This
chapter does not repeat the figure, and neither does any other chapter in this
set.

The test `include_str!`s seven named files and asserts each contains the current
floor, with the expected strings built from the constants rather than
hard-coded. The rot it catches is the worst kind in this repo: the test's own
doc comment says a floor bump that misses a prose copy leaves `SECURITY.md`
claiming enforcement the code does not provide. Four things about how it is
built:

- **`include_str!`, not a runtime read.** The files are compiled into the test
  binary, so a path that moved is a compile error rather than a test that
  silently reads nothing.
- **Containment, not equality**, and the comment is honest about the limit: it
  catches a file that never names the current floor, and not one that also
  still names an older one.
- **Two spellings.** `decision-port-allowlist.md` writes the ABI in landlock's
  own variant form rather than as a bare number, so the test carries a second
  expected form for that file — and both forms are built off the constant's
  discriminant, because landlock documents its `Debug` as unstable.
- **The seven include a workflow file.** One of the pinned copies is
  `.github/workflows/ci.yml`, whose "Report kernel sandbox support" step names
  the floor in a comment; a Rust unit test therefore asserts on the contents of
  a YAML comment. That is the mechanism being taken seriously rather than
  decoratively.

And the cost, which the test states against itself: the comment beside the two
`context/` entries notes they are the only two of the directory's files stating
the floor, that a file which never names it cannot drift from it, and that each
copy added is **another way for a trim to break this build**. That is why the
right move, when you need the number, is to name the constants and link
`SECURITY.md` rather than write it down again.

### The mutation check: a table of tests that were actually run

The fourth instance is not a test. It is prose that records tests having been
run, and it is the answer to a problem `guide-module-layout.md` spends a whole
section on: **most of this repo's mechanisms fail by refusing.** A ruleset the
kernel would not take, a filter that did not install, a fixture whose directory
dropped before the assertion read it, a comparison that fell through — every one
of those denies everything, and a suite of denial tests stays green through all
of them.

So [decision-axis-table.md](../decision-axis-table.md) and
[decision-default-policy.md](../decision-default-policy.md) each carry a
`## The mutation check` section: a list of single-line mutations to the code,
each one applied and the suite run, with the tests that failed recorded
underneath. The axis table's framing is the clearest statement of the point —
change one row, see what breaks, because that is what distinguishes a table from
three lists that happen to agree.

The load-bearing column is the one listing tests that **passed**:

```
default becomes unconditional (drop the paths_given guard)
   ──► a_path_flag_replaces_the_working_directory      fails   ◄── the rule itself
       each_allow_flag_widens_only_its_own_axis        fails
       allow_flags_repeat_to_grant_several_paths       fails
       a_path_flag_runs_from_the_home_directory        fails   ◄── the guard now fires on an explicit policy
       the_default_matches_what_sandbox_run_derives    passes  ◄── derives its expectation
```

That last line is a whole lesson. `the_default_matches_what_sandbox_run_derives`
survives the mutation because both sides of its comparison mutate together — it
reads its expectation off the thing under test. `decision-default-policy.md`
names it as the derived-expectation trap, and draws the right conclusion rather
than deleting the test: it is a cross-subcommand *consistency* test, and not the
one pinning what the default is. The same table shows the opposite result too —
dropping the guard breaks tests in two suites that never mention the default,
because both assert on the whole policy, so the suppression turns out to be
pinned by tests older than it is.

The axis table's second round shows the other half: adding a fourth axis breaks
exactly two exhaustive matches, which are "forced to notice", while every other
site derives the new axis for free. That is a map of where the compiler is
helping you and where it is not.

- **Worth questioning:** `context_docs.rs` reads `context/` with a single
  non-recursive `read_dir` filtered to files with an `.md` extension, so
  `context/onboarding/` — a directory, not a `.md` file — is skipped whole.
  Neither of the two tests can see this chapter set: the citation test never
  opens these files, so a chapter citing a `guide-` or `decision-` name that
  does not exist passes, and the chapters cite dozens. (The reading-order test
  is correct to ignore them, the onboarding files being outside the
  `guide-`/`decision-` taxonomy it indexes.) No `decision-*.md` records the
  test's scope; the only rationale is the module doc, which explains why the
  tests live in `sandbx-core` and says nothing about depth. The strongest
  argument the file itself supplies against a wider read is the `ROOT_DOCS` one
  — a glob picks up untracked files, so the set under test would differ per
  checkout — and that applies to a recursive walk of `context/` as much as to
  the repo root. But it is answerable by naming the subdirectory, exactly as the
  root docs are named, which is a one-line change; and the chapters as they
  stand would pass it today. Documenting an on-ramp inside a directory whose
  citations are pinned, in the one subdirectory where they are not, is the gap
  worth closing.

## Issues, milestones and labels

With no roadmap file, the issue tracker carries the whole of what is intended.
`CLAUDE.md` sets three conventions.

- **Milestones are releases, one per tag.** A closed issue or PR takes the
  milestone of the release it shipped in. Open work being actively worked on
  takes the next one. **No milestone is not a defect** — it means unscheduled,
  and stripping one off in-progress work is a mistake in the other direction.
- **One `crate:*` label per crate the change materially touches.** The label set
  is exactly the crate set — `crate:core`, `crate:tools`, `crate:providers`,
  `crate:agent`, `crate:session`, `crate:tui`, `crate:cli` — each described by
  what that crate owns, as in [05](05-seven-crates.md)'s ownership table.
- **No `crate:*` label where the change is workspace-wide or outside
  `crates/`.** A docs-only PR touching `context/`, a workflow change, a
  lint-table change: none of these takes one. The absence is informative, which
  is why it is not filled in for tidiness.

Beyond those there is a topical set — `security` with a `severity:*` pair, `ci`,
`tests`, `tooling`, `refactor`, `audit`, `documentation` — and `security`'s
severity labels are worth reading for their wording alone: high is "escape, or
execution that is not restricted as claimed", low is "contained, but narrower or
wider than documented". Both are about the gap between the mechanism and the
claim, which is the same axis `SECURITY.md` is maintained on.

## Before a PR: three passes, in one order

For a branch with a significant code change, `CLAUDE.md` prescribes three passes
and the order is not arbitrary:

1. `/code-review`
2. `/security-review`
3. the comment pass

Fix what each pass reports before starting the next. The reasons for the
sequence are both about wasted work. **Code review first**, because it surfaces
correctness problems that would otherwise show up as phantom security findings —
a review hunting for an escape will happily report one caused by a plain bug.
**The comment pass last**, because both reviews land fixes and a fix rewords
comments; done first, it would be redone.

The comment pass itself is: read every comment the branch added or touched
against `guide-code-comments.md`, and trim what is over budget — subject to the
rule above that a trim deleting a kernel quirk, an ordering requirement or the
origin of an ABI number has failed.

Docs-only, comment-only and test-rename branches need neither review. The
comment pass still applies to a comment-only branch, which is the only reason it
exists as a separate step rather than part of code review.

### Confirm what each review read, before believing it

This is the part that will actually bite you. Both review commands collect their
own diff from the session's working directory, and three failure modes report
"no findings" in a way indistinguishable from a clean branch. So re-measure,
every pass:

```sh
git diff --stat origin/main...HEAD
```

and compare the result against the SHA and diffstat the command reports back.
Pass the worktree path and the expected diffstat to every invocation. The three
modes:

- **Three dots, not two.** The distinction matters for `git diff` specifically.
  `git diff A..B` compares the two endpoint trees — identical to `git diff A B`
  — so `origin/main..HEAD` includes, *inverted*, everything `origin/main` gained
  since you branched, as though your branch had deleted it. `git diff A...B`
  compares from the **merge base**, which is your branch's own work and nothing
  else. The two-dot form "drifts with no commit of the branch's own and still
  reads as current", which is the dangerous property: it looks like a diff.
- **An empty diff, from a cwd that is not where the work is.** A session running
  in the main checkout while the branch lives in a `git worktree` sees nothing
  to review and says so cleanly. The tell is the cwd's branch, not only a
  diffstat mismatch — check which branch you are standing on, not just the
  numbers.
- **A stale diff**, over a tree some commits behind the head, where the diffstat
  is the only tell. And `git diff | wc -l` is not a diffstat: it counts diff
  lines, including context and headers, and will not distinguish the tree you
  meant from one a few commits back.

`CLAUDE.md`'s closing line on all of this is the one to remember: **a review
over the wrong lines is not a pass.** A logged diffstat also goes stale the
moment a fix lands, so measure immediately before each pass rather than once at
the start.

## Your first PR, end to end

Assume a small change to `sandbx-cli`.

- **Wire the hooks, once per clone.** `git config core.hooksPath .githooks`.
  Nothing else does this; a fresh clone has no hooks until you run it.
- **Branch as `<type>/<slug>`,** using the same type vocabulary the commit
  subjects use — `docs/onboarding`, `refactor/root-derivation`,
  `test/context-guards`. Nothing enforces it; it is what the branch list looks
  like.
- **Make the change, and decide where the explanation lives.** If the *why* is a
  kernel quirk or an ordering requirement, it belongs in a comment next to the
  code. If it is an argument, it belongs in a `guide-` or `decision-` file with
  a one-line pointer left in the code. Do not write it in both places — one home
  per fact.
- **Commit.** `pre-commit` runs fmt, clippy and the doc build; `commit-msg`
  checks the subject against `<type>(<scope>): <description>`, with the type
  from the list of eight, the scope optional and lowercase, and the whole
  subject under the 72-character ceiling. The house habit, which no hook
  enforces, is a subject stating what is true after the change rather than
  instructing: "the cli map names the new module", not "update the cli map".
- **If the version in the workspace manifest moved, write the release notes in
  the same commit.** `docs/release-notes/v<version>.md`, copied from
  `TEMPLATE.md`, is a required check on `main` — CI's `notes` job looks for the
  file by name *and* re-checks every other `v*.md`, so an older file that has
  drifted over budget fails your PR too. `guide-release-notes.md` has the budget
  and the convention for when several branches converge on one release.
- **Run the three passes,** in order, if the change is a significant code one,
  re-measuring the diffstat before each.
- **Open the PR against the template's three sections.**
  [`pull_request_template.md`](../../.github/pull_request_template.md) asks for
  *What* in a line or two; an *Issue reference*; and a statement about
  `SECURITY.md`. Both of the latter two carry a warning earned the hard way:

  - A closing keyword closes the **whole** issue, because GitHub drops any
    qualifier after it — `Closes #52 items 1 and 2` closes #52 outright. The
    template records that this happened twice on one issue and that the second
    time went unnoticed. For partial progress, write `#52 items 1 and 2. Items
    3-5 stay open.` with no closing keyword at all.
  - The `SECURITY.md` section must state either what the PR changed in it or
    that nothing changed — and any change ships in this PR, not a follow-up,
    because "a merge that leaves the policy overstating the sandbox is itself a
    security defect".
- **Label and milestone it.** A `crate:*` label per crate materially touched and
  none if the change is workspace-wide or outside `crates/`; the next release's
  milestone if the work is in flight, and none if it is not scheduled.
- **Watch all six checks**, not one: `test`, `sandbox (x86_64)`,
  `sandbox (aarch64)`, `msrv`, `notes` and `audit` — five jobs, the sandbox one
  being a two-architecture matrix. If `test`'s fmt, clippy or doc step is what
  went red, a hook was skipped.

One closing note that ties back to the tests above. `guide-naming.md` warns that
renaming a test can break a prose reference, because `context/*.md` cites test
names as the evidence for a claim — `decision-default-policy.md`'s mutation
table is a claim-to-test-name map outright. Nothing automated catches that one.
Grep `context/` for the old name before you consider a rename done.

## You should now be able to explain

- The difference between a `guide-` and a `decision-` file, and which of the two
  is expected to go stale.
- Why there is no roadmap file, and what a doc may say about an issue's status.
- Which three guides constrain how code is written, what each one bounds, and
  why this chapter cites none of their numbers.
- Why the comment ratio's denominator includes test code, and why reading the
  ratio without a line-width check does not measure anything.
- What "byte-identical" buys between `.githooks/pre-commit` and `ci.yml`, and
  what a red CI run therefore tells you.
- What class of rot each of `every_doc_a_citation_names_exists`,
  `the_reading_order_names_every_doc` and
  `every_prose_copy_of_the_floor_is_current` catches, and the trick each uses to
  avoid passing vacuously.
- Why a mutation check lists the tests that *passed*, and what the
  derived-expectation trap is.
- Why code review runs before security review, and the comment pass after both.
- What `git diff origin/main..HEAD` shows that `origin/main...HEAD` does not,
  and the two other ways a review reports a clean branch without having read it.
- When a PR takes no `crate:*` label and no milestone, and why neither absence
  is a defect.

## Next

[17 — gaps and open questions](17-gaps-and-open-questions.md), the last chapter:
what this project says is still missing, and what the earlier chapters said
looked wrong. If you are about to make a change rather than read another
chapter, the two files to have open are [`CLAUDE.md`](../../CLAUDE.md) and
[`SECURITY.md`](../../SECURITY.md).
