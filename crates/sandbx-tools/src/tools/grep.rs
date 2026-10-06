use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, RiskLevel, ToolError, ToolOutput, ToolSpec};

pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "grep",
    description: "Search file contents beneath a directory for a literal string. \
                  Not a regular expression.",
    risk: RiskLevel::ReadOnly,
    schema,
    run,
};

fn schema() -> serde_json::Value {
    schemars::schema_for!(GrepInput).to_value()
}

fn run(input: serde_json::Value, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    execute(crate::parse(input)?, ctx)
}

/// Files above this size are skipped without reading.
///
/// No source file is this large; a checkout's pack files and binaries are, and they
/// fail UTF-8 validation anyway — which `read_to_string` discovers only after
/// allocating the whole file.
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
/// A literal search, not a regex: a regex adds a dependency and a class of
/// pathological-pattern behaviour, for a tool mostly asked where a symbol appears.
pub fn execute(input: GrepInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let walk = ctx
        .guard()
        .walk_readable(&input.path, ctx.limits().max_files_scanned())
        .map_err(|error| crate::denied(&input.path, error))?;

    let mut hits = Vec::new();
    let mut scanned = 0usize;
    let mut stopped_early = walk.truncated;

    // Nothing is sorted afterwards: `walk_readable` returns files sorted and lines
    // are visited ascending. Sorting the rendered lines would put `:10` before `:2`.
    for file in walk.files {
        // Before the read, so the budget bounds what is read rather than noticing
        // once it is spent. A file skipped below is not charged for.
        if scanned >= ctx.limits().max_bytes_scanned() {
            stopped_early = true;
            break;
        }

        if file.metadata().is_ok_and(|m| m.len() > MAX_FILE_BYTES) {
            continue;
        }

        // A binary that slipped under the size cap fails UTF-8 validation here.
        let Ok(content) = crate::read_file(&file, ctx) else {
            continue;
        };
        scanned += content.len();

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

    Ok(crate::listing(hits, ctx, stopped_early))
}
