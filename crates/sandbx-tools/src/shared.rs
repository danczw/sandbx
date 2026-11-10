//! What the tool modules reach for: the guard-checked reads, the two shapes an error
//! takes, and the bounded rendering of a result list.

use std::fmt;
use std::fs::File;
use std::path::Path;

use crate::{ExecutionContext, ToolError, ToolOutput};

/// Turn a guard verdict into the form the model sees, one shape for every tool.
///
/// Absence is the one verdict that is not a refusal: no policy objected, so the agent's
/// move is to fix the name rather than ask for a wider grant (#180).
pub(crate) fn guard_error(path: &Path, error: sandbx_core::SandboxError) -> ToolError {
    let subject = path.display().to_string();

    match error {
        sandbx_core::SandboxError::NotFound { .. } => ToolError::Failed {
            subject,
            detail: error.to_string(),
        },
        // `RootReplaced`'s `Display` names both `(dev, ino)` pairs, which the operator's trail
        // needs and the model cannot act on; it is told the grant is gone, its only move.
        sandbx_core::SandboxError::RootReplaced { granted, .. } => ToolError::Denied {
            subject,
            reason: format!(
                "granted root {} is no longer the directory the policy judged",
                granted.display()
            ),
        },
        error => ToolError::Denied {
            subject,
            reason: error.to_string(),
        },
    }
}

/// Turn a failed filesystem operation into the form the model sees. `verb` names
/// what was attempted (`read /etc/hosts`, `list /tmp`), not the syscall.
pub(crate) fn failed(verb: &str, path: &Path, error: impl fmt::Display) -> ToolError {
    ToolError::Failed {
        subject: format!("{verb} {}", path.display()),
        detail: error.to_string(),
    }
}

/// The most a tool holds of one file: `edit` refuses past it, `grep` skips past it, and
/// `read` stops at it whatever `max_bytes` is set to.
///
/// No source file is this large; a checkout's pack files and binaries are, and they
/// fail UTF-8 validation anyway — which is discovered only after reading them.
pub(crate) const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Read a whole file for `edit`, refusing one past [`MAX_FILE_BYTES`]: `edit` holds it
/// twice, and cannot work on part of one.
pub(crate) fn read_file(path: &Path, ctx: &ExecutionContext) -> Result<String, ToolError> {
    let file = open(path, ctx)?;

    let (bytes, Cut::Whole) = read_bounded(file, path, MAX_FILE_BYTES)? else {
        let detail = format!("the file is larger than the {MAX_FILE_BYTES} bytes it can edit");
        return Err(failed("edit", path, detail));
    };
    String::from_utf8(bytes).map_err(|error| failed("read", path, error))
}

/// The first `max` bytes of a file, read through the guard, and how it was cut.
///
/// Only the head is judged, so a file whose head is text reads as text whatever follows.
/// An invalid byte inside the head fails as `read_file` would; at a cut, up to three
/// trailing bytes that start a character without finishing it are dropped, being either a
/// split character or a stray lead byte.
pub(crate) fn read_head(
    path: &Path,
    ctx: &ExecutionContext,
    max: u64,
) -> Result<(String, Cut), ToolError> {
    let file = open(path, ctx)?;

    let (mut bytes, cut) = read_bounded(file, path, max)?;
    if let (Cut::Short { .. }, Err(error)) = (cut, std::str::from_utf8(&bytes))
        && error.error_len().is_none()
    {
        bytes.truncate(error.valid_up_to());
    }
    let text = String::from_utf8(bytes).map_err(|error| failed("read", path, error))?;
    Ok((text, cut))
}

/// Read a file through the guard, or `None` when it answers nothing: refused, past
/// `max`, not measurable, or not text. The size comes off the handle, never off the
/// path: a path `stat` is a second resolution the guard did not vet, and need not
/// answer for the file opened (#275).
pub(crate) fn read_capped(path: &Path, ctx: &ExecutionContext, max: u64) -> Option<String> {
    let file = open(path, ctx).ok()?;
    if file.metadata().ok()?.len() > max {
        return None;
    }

    // A binary under the cap fails UTF-8 validation here, and so does a read that died
    // mid-file; neither is a file with no match in it.
    let (bytes, Cut::Whole) = read_bounded(file, path, max).ok()? else {
        return None;
    };
    String::from_utf8(bytes).ok()
}

/// Whether a bounded read reached the end of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cut {
    Whole,
    /// More was left. `total` is the size the handle reports, dropped where it is no more
    /// than what was read, since it is then provably false: a device or a procfs file
    /// reports 0. A pseudo-filesystem's placeholder above that, sysfs's 4096, passes.
    Short {
        total: Option<u64>,
    },
}

/// Open `path` through the guard, the one place an in-process tool's read starts.
///
/// The check lives here, not at the call sites, so no tool can read a file by forgetting
/// it. The handle the guard returns is what gets read, not the path again: re-resolving
/// on open leaves a window to swap the leaf for a symlink — which is why no tool calls
/// the bare `check_read` or `check_write`.
fn open(path: &Path, ctx: &ExecutionContext) -> Result<File, ToolError> {
    ctx.guard()
        .open_read(path)
        .map_err(|error| guard_error(path, error))
}

/// Read at most `max` bytes off an open handle, the path being for the error only.
///
/// The bound is on the read, not on the handle's size: `/dev/zero` reports 0 and never
/// ends, and a file can grow between the `fstat` and the read. Reading one byte past
/// `max` is how a file of exactly `max` bytes tells itself apart from a longer one.
fn read_bounded(file: File, path: &Path, max: u64) -> Result<(Vec<u8>, Cut), ToolError> {
    use std::io::Read;

    let size = file.metadata().map(|metadata| metadata.len()).ok();
    // `Take` hides the size hint `File` gives `read_to_end`, which would then grow the
    // buffer by doubling to up to twice the bound.
    let hint = size.unwrap_or(0).min(max.saturating_add(1));
    let mut bytes = Vec::with_capacity(usize::try_from(hint).unwrap_or(0));
    file.take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| failed("read", path, error))?;

    if bytes.len() as u64 <= max {
        return Ok((bytes, Cut::Whole));
    }
    // More than `max` bytes are held, so `max` fits in a `usize`.
    bytes.truncate(max as usize);
    let total = size.filter(|&size| size > max);
    Ok((bytes, Cut::Short { total }))
}

/// Whether a search covered everything it was asked to, or left some of it unsearched: a
/// walk cut short, or a file skipped on the way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scan {
    Complete,
    StoppedEarly,
}

impl Scan {
    /// How far the walk itself got, before anything the caller skips on top.
    pub(crate) fn of(walk: &sandbx_core::ReadableWalk) -> Self {
        if walk.truncated {
            Self::StoppedEarly
        } else {
            Self::Complete
        }
    }
}

/// Render a list of results, bounded, distinguishing "none" from empty output.
///
/// [`Scan::StoppedEarly`]'s marker is appended after the entry cap is applied, not
/// before: a marker inside the list is a line the cap can trim away, which would leave a
/// partial search looking complete.
pub(crate) fn listing(lines: Vec<String>, ctx: &ExecutionContext, scan: Scan) -> ToolOutput {
    if lines.is_empty() && scan == Scan::Complete {
        return ToolOutput::new("no matches".to_string());
    }

    let mut rendered = ctx.limits().cap_entries(lines);
    if scan == Scan::StoppedEarly {
        rendered.push(PARTIAL_SEARCH.to_string());
    }

    ToolOutput::new(rendered.join("\n"))
}

/// Tells the model its search was abandoned, not exhausted — otherwise a scan that
/// gave up reads as one that found nothing, and the symbol looks absent.
///
/// Names no cause. A budget, an oversized file, a binary and a refused open all leave
/// part of the tree unsearched, and the caller's one move is the same for each (#274).
/// The cost: at a repo root it is close to always on, a checkout's pack files being both
/// oversized and not text, and narrowing the path does not clear it.
const PARTIAL_SEARCH: &str = "... stopped early: results are incomplete";

/// Parse tool arguments, reporting a schema mismatch rather than a panic.
pub(crate) fn parse<T: serde::de::DeserializeOwned>(
    input: serde_json::Value,
) -> Result<T, ToolError> {
    serde_json::from_value(input).map_err(|error| ToolError::BadInput {
        detail: error.to_string(),
    })
}
