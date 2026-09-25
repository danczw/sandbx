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
        .map_err(crate::denied(&input.path))?;

    let mut hits = Vec::new();

    for file in files {
        // Checked before opening rather than after: `read_to_string` would read
        // the whole file before failing UTF-8 validation on a binary.
        if file.metadata().is_ok_and(|m| m.len() > MAX_FILE_BYTES) {
            continue;
        }

        // Opened through the guard so the handle, not a re-resolved path, is
        // what gets read. Binary files fail UTF-8 validation and are skipped.
        let Ok(mut handle) = ctx.guard().open_read(&file) else {
            continue;
        };
        let mut content = String::new();
        if std::io::Read::read_to_string(&mut handle, &mut content).is_err() {
            continue;
        }

        for (number, line) in content.lines().enumerate() {
            if line.contains(&input.pattern) {
                hits.push((file.clone(), number + 1, line.trim().to_string()));
            }
        }
    }

    // Sort on the parts, not on the rendered line: sorting formatted strings
    // orders line numbers lexicographically, putting `:10` before `:2`.
    hits.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));

    Ok(crate::listing(
        hits.into_iter()
            .map(|(path, line, text)| format!("{}:{}: {}", path.display(), line, text))
            .collect(),
        ctx,
    ))
}
