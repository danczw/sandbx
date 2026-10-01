use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput};

/// Files above this size are skipped without reading.
///
/// A source file is never this large, while a repository checkout is full of
/// pack files, build output and vendored binaries that are. Reading them costs
/// time and peak memory to produce nothing, since they fail UTF-8 validation
/// anyway — and `read_to_string` only discovers that *after* allocating the
/// whole file.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Arguments for the `grep` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GrepInput {
    /// Absolute path of the directory to search.
    pub path: PathBuf,
    /// Literal text to look for. Not a regular expression.
    pub pattern: String,
}

/// Search file contents beneath a directory for a literal string.
///
/// Deliberately a literal search, not a regex: a regex would pull in a
/// dependency and a whole class of pathological-pattern behaviour, for a tool
/// whose common use is "find where this symbol is mentioned".
pub fn execute(input: GrepInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let files = ctx
        .guard()
        .walk_readable(&input.path)
        .map_err(|error| crate::denied(&input.path, error))?;

    let mut hits = Vec::new();

    // Already ordered, so nothing is sorted afterwards: `walk_readable` returns
    // files sorted and lines are visited ascending within each file. Sorting the
    // rendered lines instead would be wrong anyway — it orders line numbers
    // lexicographically, putting `:10` before `:2`.
    for file in files {
        // Checked before opening rather than after: `read_to_string` would read
        // the whole file before failing UTF-8 validation on a binary.
        if file.metadata().is_ok_and(|m| m.len() > MAX_FILE_BYTES) {
            continue;
        }

        // Read through the guard, so the handle rather than a re-resolved path is
        // what gets read. A binary file fails UTF-8 validation and is skipped.
        let Ok(content) = crate::read_file(&file, ctx) else {
            continue;
        };

        for (number, line) in content.lines().enumerate() {
            if line.contains(&input.pattern) {
                hits.push(format!(
                    "{}:{}: {}",
                    file.display(),
                    number + 1,
                    line.trim()
                ));
            }
        }
    }

    Ok(crate::listing(hits, ctx))
}
