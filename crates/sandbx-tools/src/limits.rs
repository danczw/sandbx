/// How much a tool may do, and how much it may return.
///
/// Output goes straight into the model's context, and the tokens are spent before
/// `sandbx-agent` sees the result, so an uncapped result cannot be fixed
/// downstream — it evicts the conversation that explains what the agent was doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolLimits {
    max_entries: usize,
    max_bytes: usize,
    max_files_scanned: usize,
    max_bytes_scanned: usize,
}

impl Default for ToolLimits {
    fn default() -> Self {
        Self {
            // A pattern of matches, far short of a whole tree.
            max_entries: 200,
            // Larger than a source file, well short of a context window.
            max_bytes: 256 * 1024,
            // A source tree fits; one padded with vendored deps and build output does
            // not. The walk holds a `PathBuf` per file, so this bounds memory too.
            max_files_scanned: 10_000,
            // Every source file in a large project, short of its pack files and
            // binaries. Counted across the whole search: a hundred 2 MiB files cost
            // what one 200 MiB file does, and only a total sees that.
            max_bytes_scanned: 64 * 1024 * 1024,
        }
    }
}

impl ToolLimits {
    /// Set the entry cap.
    #[must_use]
    pub fn with_max_entries(mut self, entries: usize) -> Self {
        self.max_entries = entries;
        self
    }

    /// Set the byte cap.
    #[must_use]
    pub fn with_max_bytes(mut self, bytes: usize) -> Self {
        self.max_bytes = bytes;
        self
    }

    /// Cap on the files a searching tool may visit before giving up.
    pub fn max_files_scanned(&self) -> usize {
        self.max_files_scanned
    }

    /// Cap on the bytes a searching tool may read across a whole search.
    pub fn max_bytes_scanned(&self) -> usize {
        self.max_bytes_scanned
    }

    /// Set the scanned-file cap.
    #[must_use]
    pub fn with_max_files_scanned(mut self, files: usize) -> Self {
        self.max_files_scanned = files;
        self
    }

    /// Set the scanned-byte budget.
    #[must_use]
    pub fn with_max_bytes_scanned(mut self, bytes: usize) -> Self {
        self.max_bytes_scanned = bytes;
        self
    }

    /// Trim `lines` to the entry cap, reporting how many were dropped.
    ///
    /// The count, not a bare "truncated": a model that knows it saw 200 of 4000
    /// matches can narrow its search.
    pub(crate) fn take_entries(&self, mut lines: Vec<String>) -> Vec<String> {
        let total = lines.len();
        if total <= self.max_entries {
            return lines;
        }

        lines.truncate(self.max_entries);
        lines.push(format!(
            "... truncated: showing {} of {total} results",
            self.max_entries
        ));
        lines
    }

    /// Trim `content` to the byte cap, reporting how much was dropped.
    pub(crate) fn take_bytes(&self, content: String) -> String {
        if content.len() <= self.max_bytes {
            return content;
        }

        // Cutting at a byte offset can land mid-character; back up to a boundary.
        let mut end = self.max_bytes;
        while end > 0 && !content.is_char_boundary(end) {
            end -= 1;
        }

        let total = content.len();
        let mut trimmed = content;
        trimmed.truncate(end);
        trimmed.push_str(&format!("\n... truncated: showing {end} of {total} bytes"));
        trimmed
    }
}
