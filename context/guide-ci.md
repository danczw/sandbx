# The gates

Two halves of one set of checks: `.githooks/` runs before a commit exists,
`.github/workflows/` runs after a push. They are deliberately not independent —
`pre-commit` and `ci.yml`'s `Format`, `Clippy` and `Doc` steps are
byte-identical, so a red CI run is a hook someone skipped rather than a check
only CI knows about.

## The local half

Wired by one line, which is why there is no hook-manager dependency:

```sh
git config core.hooksPath .githooks
```

`pre-commit` is `cargo fmt --all -- --check`, then
`cargo clippy --workspace --all-targets -- -D warnings`, then the `Doc` step
under `RUSTDOCFLAGS: -D warnings`. Not the test suite: a hook that takes minutes
is a hook people pass `--no-verify` to, and the three together are seconds on a
warm target dir. The doc build earns its place by being the only one of them that
reads a doc comment at all — a broken intra-doc link passes fmt and clippy, so
without it the first thing to notice is CI after the push.

`commit-msg` checks the **subject only**; the body is free-form. Eight types
(`feat fix docs refactor test chore build ci`), the scope and the breaking-change
`!` both optional, and a 72-character ceiling. `Merge`, `Revert`, `fixup!`,
`squash!` and `amend!` subjects are exempt, because the rebase they are made for
rewrites them.

Two things fall out of that pattern that are easy to trip over:

- **A scope is optional, so a change spanning crates takes none.** `docs: …` is
  valid. Inventing a scope to look consistent is worse than omitting it.
- **The scope charset is `[a-z0-9._/-]+`, so a comma is not a scope.**
  `docs(providers,session):` is refused; drop to no scope.

## The remote half

| job | what it proves |
|---|---|
| `test` | fmt, clippy, the default-feature suite, and rustdoc |
| `sandbox (x86_64)`, `sandbox (aarch64)` | the enforcement suite on a real kernel, gnu then the published musl triple |
| `msrv` | the suite still builds at the floor the manifest states |
| `notes` | the manifest's version has a notes file, and every `v*.md` is within budget |
| `audit` | cargo-deny, both release-channel tables, and zizmor over the workflows |

`permissions: contents: read` replaces the repo default and
`persist-credentials: false` drops the clone's token, so a compromised action
cannot push or publish. The scheduled run is weekly on Monday because an advisory
appears without a code change.

**Branch protection pins job names.** `sandbox (${{ matrix.arch }})` is spelled
out in a `name:` for that reason: renaming a job blocks every merge on a status
that will never report.

### Ordering: `cargo metadata` before any toolchain step

`msrv` cannot install its toolchain until it knows which one, and `notes` cannot
find its file until it knows the version. Both therefore read the manifest with
whatever cargo the runner image ships, before `dtolnay/rust-toolchain` runs at
all. Two traps in that read:

- `rust_version` from `cargo metadata` is the **inherited** value. A
  `[workspace.package]` entry no member inherits is inert and reads as `null`,
  so the job errors rather than silently testing on stable.
- The default shell is `bash -e` without `pipefail`, so piping cargo into `jq`
  takes `jq`'s exit status. Hence two statements, not one pipeline.

`--locked` is the whole point of `msrv`: resolver 3 *prefers* MSRV-compatible
versions, so an unlocked run resolves around a broken lockfile and passes.

### A glob that matches nothing must fail

`notes` counts the files it checked and errors on zero. A loop over
`docs/release-notes/v*.md` that found no file would otherwise exit 0, and a
green gate that checked nothing is worse than a red one. Any check that iterates
needs the same guard.

### `RUSTDOCFLAGS`, not a `[lints.rustdoc]` table

Not a cargo limitation — `[lints.rustdoc]` does work, verified on cargo 1.95:
`private_intra_doc_links = "deny"` there fails the build exactly as
`RUSTDOCFLAGS: -D warnings` does. The reason is coverage. A lints table
enumerates lints by name and has to be kept current; `-D warnings` denies the
whole class, including lints a future toolchain adds.

The Doc step also passes `--all-features`, unlike Clippy: a feature-gated item's
intra-doc links are checked there or nowhere.

## Publication: the two questions a tag answers

`release.yml` asks `release-channel.sh` two things, and neither answer may be a
default — a mis-marked release cannot be un-pushed, which is why both are decided
in a script with a table in `--self-test` rather than inline in the workflow.

**Which channel.** Only an exact 1.0-or-later version is a `release`; everything
else is a `prerelease`. This implements the support policy in `SECURITY.md`.

**Whether it takes GitHub's "latest" link.** Highest semver wins: a tag takes the
link only if no published non-draft release carries a higher version. A
pre-release never takes it. The rule exists because the REST API defaults
`make_latest` to `true`, so omitting the flag lets *publication* order decide —
post-1.0, a `v1.5.1` backport tagged after `v2.0.0` would demote `v2.0.0`.
`gh release create` is therefore always passed an explicit `--latest=true|false`.

The rejected alternative is worth naming because it reads as the simpler one:
"only the newest `MAJOR.MINOR` line may be latest" still needs the set of
published releases to know which line is newest, so it buys no simplicity, and it
re-promotes an older patch of the current line — `v1.5.1` published while
`v1.5.3` exists would take the link back.

**A published tag the comparison cannot parse is an error, not a skip.** Every
unrecognised shape classifies `prerelease`, so skipping one would read as
"nothing higher is published" and hand the link away — the exact demotion this
rule exists to stop. A tag therefore has to be `M.m.p` with optional pre-release
and build parts to be skipped as a non-competitor; anything else fails the step,
which is recoverable, where a wrong `latest` is not. Version fields are capped at
nine digits for the same reason: a wider one reaches `[ -gt ]`, which reports a
parse error rather than an order, and `if` reads that as "not higher".

### Why the query is in the workflow and the comparison is not

`guide-repo-map.md` requires everything in `.github/scripts/` to run without a
workflow, and this decision needs the published set, which only an API call
supplies. So `release-channel.sh --latest <tag>` reads candidate tags on
**stdin**: the script makes no network call, stays runnable by hand, and the
self-test feeds it synthetic sets. The `gh api` call lives in the `notes` job,
which is the only one with a checkout — `publish` deliberately has none, so that
`contents: write` is confined to a job holding no source.

Two traps in that step, both of which have bitten:

- **The handoff is validated, not defaulted.** An empty `$CHANNEL` or `$LATEST`
  means the job-output wiring broke; the step errors. Defaulting either would be
  right for every pre-1.0 tag and would hide the break until 1.0.
- **`gh api` gets its own statement, not a pipe into the script.** The default
  shell has no `pipefail`, so a pipeline reports the script's status and a failed
  API call reads as an empty release set — which answers `true`. The empty set is
  tested for separately, because a call that succeeds and matches nothing lands
  in the same place by a route no exit status reports.

The version compare is hand-rolled and field-wise rather than `sort -V`, which is
GNU-only; the scripts are `#!/bin/sh` and the self-test runs under `dash`.

### One release run at a time

Reading the published set makes the decision a snapshot, and two `v*` tags pushed
close together would each take theirs before either published — so the later
publisher wins and can demote the higher version. `release.yml` therefore groups
on `github.workflow` **alone**. `ci.yml` groups on workflow-plus-ref and cancels,
which is the opposite of what a release wants on both keys: the collision here is
between two different tags, so a per-ref group would not see it, and a half-done
publish must not be cancelled.

The cost is that `cancel-in-progress: false` queues at most one run per group — a
third tag pushed while one is publishing and one is queued cancels the queued run,
which then has to be re-run by hand. That is the trade taken deliberately: a
cancelled run is visible and repeatable, and a tag that took the "latest" link
wrongly cannot be un-pushed.

## Pinned actions, and what updates them

Every action is pinned to a SHA with a `# vX.Y.Z` comment beside it. Dependabot
rewrites **both**, so nothing may follow that comment on the line — a version it
cannot match is left stale.

`dtolnay/rust-toolchain` is pinned from `v1`, not `stable`: the `stable` branch
is regenerated as master plus one commit, so a SHA taken from it is reachable
from no ref and never bumps again.

zizmor runs through `pipx run zizmor==1.30.1` rather than its own action, because
an action would add a third-party action to the surface that step audits. The
version is pinned by hand since dependabot does not track it.

### The dependabot policy

Weekly on Monday — one batch at the start of the week rather than a trickle
through it — with a seven-day `cooldown`, on the basis that a compromised
release is usually yanked within days. `default-days` is the only cooldown key
the `github-actions` ecosystem reads; the `semver-*-days` ones are inert.

Minor and patch updates are **grouped into one PR**; majors are deliberately
left ungrouped, so each arrives alone and gets read. `directory: /` is required
for this ecosystem, which finds `.github/workflows` from there. Dependabot
commits through the API, so `.githooks/commit-msg` never sees them — the
`ci` prefix is what keeps a squash merge's subject conventional.
