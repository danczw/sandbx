//! Two facts about `context/` that nothing else in the repo can see: a doc name cited from
//! Rust or from the markdown around it still names a file, and `guide-repo-map.md`'s reading
//! order still names every doc. Neither is about `sandbx-core`. This crate holds them because
//! it already reaches the repo root for `every_prose_copy_of_the_floor_is_current`, and
//! because there is no workspace-wide test target to put them in.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const TAXONOMY: [&str; 2] = ["guide-", "decision-"];

/// Named rather than globbed: a `read_dir` of the root would also read `CLAUDE.local.md`,
/// which is untracked, so the set of files under test would differ per checkout.
const ROOT_DOCS: [&str; 3] = ["CLAUDE.md", "README.md", "SECURITY.md"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("this crate sits two levels under the workspace root")
        .to_path_buf()
}

fn entries(dir: &Path) -> impl Iterator<Item = PathBuf> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", dir.display()))
        .map(|entry| entry.expect("a readable directory entry").path())
}

fn has_extension(path: &Path, wanted: &str) -> bool {
    path.extension()
        .is_some_and(|extension| extension == wanted)
}

/// Every `guide-…md` / `decision-…md` name in `text`, whatever path or punctuation is around
/// it — a mention with no `context/` in front of it is a citation too.
fn doc_names(text: &str) -> BTreeSet<&str> {
    let mut found = BTreeSet::new();

    for prefix in TAXONOMY {
        let mut rest = text;
        while let Some(at) = rest.find(prefix) {
            let from = &rest[at..];
            rest = &rest[at + prefix.len()..];

            let end = from
                .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || "-.".contains(c)))
                .unwrap_or(from.len());
            // A trailing sentence period is not part of the name; `.md` is.
            let name = from[..end].trim_end_matches('.');
            if name.ends_with(".md") {
                found.insert(name);
            }
        }
    }

    found
}

/// Every file that may cite a doc: Rust under `crates/`, the three root docs, and `context/`
/// itself. `docs/release-notes/` is out — those name releases, not subsystems.
fn citing_files(root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = ROOT_DOCS.iter().map(|name| root.join(name)).collect();
    found.extend(entries(&root.join("context")).filter(|path| has_extension(path, "md")));

    let mut pending = vec![root.join("crates")];
    while let Some(dir) = pending.pop() {
        for path in entries(&dir) {
            if path.is_dir() {
                pending.push(path);
            } else if has_extension(&path, "rs") {
                found.push(path);
            }
        }
    }

    found
}

/// A rename takes the file and leaves the citations behind; no build step reads them.
#[test]
fn every_doc_a_citation_names_exists() {
    // A made-up name here would be a citation like any other — this file is under `crates/`
    // and the walk below reads it — so the fixture names docs that exist.
    assert_eq!(
        doc_names("see `context/guide-sandboxing.md`, and decision-axis-table.md."),
        BTreeSet::from(["guide-sandboxing.md", "decision-axis-table.md"]),
        "the scanner missed a citation in a line that plainly holds two"
    );

    let root = repo_root();
    let files = citing_files(&root);

    // The walk is what a lost `pending` push would silently narrow, and this file's own
    // citations would keep the count below non-zero while it read nothing else.
    for crate_dir in entries(&root.join("crates")).filter(|path| path.is_dir()) {
        assert!(
            files.iter().any(|file| file.starts_with(&crate_dir)),
            "the walk reached no source file in {}",
            crate_dir.display()
        );
    }

    let mut cited = 0usize;
    let mut missing = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|error| panic!("{} is readable: {error}", file.display()));
        for name in doc_names(&text) {
            if !file.ends_with(file!()) {
                cited += 1;
            }
            if !root.join("context").join(name).is_file() {
                missing.push(format!("{} cites {name}", file.display()));
            }
        }
    }

    assert!(
        cited > 0,
        "no citation outside this file across {} of them, so the scan proves nothing",
        files.len()
    );
    assert!(
        missing.is_empty(),
        "a citation names a file that is not in context/: {missing:#?}"
    );
}

/// The index is how `CLAUDE.md` reaches a doc, and it rots by a file being added elsewhere.
#[test]
fn the_reading_order_names_every_doc() {
    const HEADING: &str = "## Reading order";

    let root = repo_root();
    let map = std::fs::read_to_string(root.join("context/guide-repo-map.md"))
        .expect("guide-repo-map.md is readable");

    // Heading-anchored: a trim moves line numbers. The order is the last section, so the
    // slice runs to EOF — only numbered entries count, or a closing mention reads as indexed.
    let at = map
        .find(HEADING)
        .expect("guide-repo-map.md has a reading order");
    let section = &map[at + HEADING.len()..];
    let section = &section[..section.find("\n## ").unwrap_or(section.len())];
    let listed: BTreeSet<&str> = section
        .lines()
        .filter_map(numbered_entry)
        .flat_map(doc_names)
        .collect();

    let on_disk: BTreeSet<String> = entries(&root.join("context"))
        .filter_map(|path| path.file_name()?.to_str().map(str::to_owned))
        .filter(|name| name.ends_with(".md") && TAXONOMY.iter().any(|p| name.starts_with(p)))
        .collect();

    assert!(
        !on_disk.is_empty() && !listed.is_empty(),
        "one side of the comparison is empty, so it would agree with anything"
    );

    let unlisted: Vec<&String> = on_disk
        .iter()
        .filter(|name| !listed.contains(name.as_str()))
        .collect();
    assert!(
        unlisted.is_empty(),
        "a doc is in context/ and not in the reading order, so nothing points at it: \
         {unlisted:#?}"
    );

    let absent: Vec<&&str> = listed
        .iter()
        .filter(|name| !on_disk.contains(**name))
        .collect();
    assert!(
        absent.is_empty(),
        "the reading order names a doc that is not in context/: {absent:#?}"
    );
}

/// The text after `N. `, where the whole prefix is digits — so an entry's wrapped
/// continuation line, which carries no doc name, is not one.
fn numbered_entry(line: &str) -> Option<&str> {
    let (number, rest) = line.split_once(". ")?;
    let numbered = !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit());
    numbered.then_some(rest)
}
