# Release notes

A release body is two parts: one or two short paragraphs written by hand, and
GitHub's generated list of merged PRs appended beneath them.

The prose is a **claim about what changed**, in the same register as
`SECURITY.md`: what breaks, what is true now, and what the reader must do. The
PR list already says what landed, so the prose never restates it.

## Where it lives

One file per tag, `docs/release-notes/v<version>.md`, copied from
`TEMPLATE.md` and committed with the change it describes — so the prose is
reviewed before the tag exists, not written under time pressure after.

`release.yml`'s `notes` job runs `.github/scripts/check-release-notes.sh`
against it and the whole release gates on the result: no notes, no release.
`build` waits on that job, so a malformed file fails in seconds rather than
after two native legs. `publish` then fetches the PR list from
`POST /repos/{owner}/{repo}/releases/generate-notes` and publishes prose plus
list as one body.

`ci.yml`'s own `notes` job runs the same script on each pull request — over
every `docs/release-notes/v*.md`, and by name over the file for the version in
the manifest, so a bump that forgets its notes fails at review time rather than
with the tag already pushed. It is a required check on `main`, so a red `notes`
blocks the merge and the tag cannot get ahead of the prose.

## When several branches converge on one release

One release holds one notes file, so concurrent branches cannot each commit their
own. The first branch to need the file creates it; the **last to land owns the
final text** and rewrites it to cover every change in the release, being the only
one that can see them all.

A non-owning branch carries no file. It puts its one-sentence claim verbatim in
its **PR body**, so the prose is reviewed against the diff it describes even
though it does not ship from there; the owning branch's PR is where that prose is
reviewed as prose. Agree the sentences across the branches before any of them
lands — merging three accounts afterwards is the time pressure the convention
exists to avoid.

There is no allowance per change. The owner's rewrite fits every change into one
file within the budget below, which is a ceiling for the release and not a sum of
per-branch shares (#193).

## The budget

Two paragraphs, thirty lines, no headings and no bullets. The checker enforces
all of it. Anything longer belongs in `context/` or on an issue, linked from
the prose.

Thirty is a ceiling, not a target, and the shortest notes that carry every claim
are the best ones. A reader who stops after the first sentence must not be
surprised later, which gets harder with every sentence added.

## What earns its place

- **Bold the claim.** `**A write grant handed out read in the child.**` A reader
  scanning bold text gets the release.
- **The upgrade hazard, first.** If something breaks, it is the first sentence.
  If nothing does, say so — absence of change is information.
- **Quantify when it is load-bearing.** *"on a 6.18 kernel whose effective
  Landlock ABI is V8, every run was partly enforced"*. A severity claim without
  a number is an opinion.
- **The consequence a reader would not predict.** PID namespaces: an unhandled
  `SIGTERM` is ignored, and `/proc/self/stat` disagrees with `getpid()`. Neither
  follows from "process lifetime is now enforced".
- **An issue number per substantive item**, `(#50)`. The one place issue
  archaeology belongs — `guide-code-comments.md` cuts it from code.

Not: a per-PR summary, a theme-by-theme tour, a verification checklist, or
anything the generated list carries.

## Verification, after the fact

A claim that the published archive was downloaded and exercised has to be true
when written, and the artifact does not exist until `publish` has run. So it is
not in the committed file. Exercise the archive, then amend the published body:

```sh
gh release edit <tag> --notes-file notes.md
```

Two paragraphs still. A verification note that pushes the prose over budget is
a sign it belongs on an issue.

## Two things that are not release notes

- **A migration guide.** If upgrading needs more than a sentence or two, the
  hazard is too large for an alpha's notes; say so and link an issue.
- **A roadmap.** What is planned goes on an issue, on a milestone — see
  `CLAUDE.md`.
