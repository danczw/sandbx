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

Run the script locally before tagging — the CI failure arrives after the tag is
public.

## The budget

Two paragraphs, twelve lines, no headings and no bullets. The checker enforces
all of it. Anything longer belongs in `context/` or on an issue, linked from
the prose.

The ceiling is the point. A reader who stops after the first sentence must not
be surprised later, which is only achievable if there are few sentences.

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
