/// How much a tool may do, and how much it may return.
///
/// Output goes straight into the model's context, and the tokens are spent before
/// `sandbx-turn` sees the result, so an uncapped result cannot be fixed
/// downstream — it evicts the conversation that explains what the agent was doing.
///
/// Two kinds of bound, and they are different propositions. An output bound trims a
/// complete answer and says how much was cut; an input bound stops the tool looking, and
/// the answer is incomplete. Conflated, a search that gave up reads the same as one that
/// found 4,000 matches and showed 200. These are the only bound on the six in-process
/// tools: no clock reaches them, `ExecutionContext`'s timeout being `bash`'s alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolLimits {
    max_entries: usize,
    max_bytes: usize,
    /// Cap on the files a searching tool may visit before giving up.
    pub max_files_scanned: usize,
    /// Cap on the bytes a searching tool may read across a whole search.
    ///
    /// Checked before each read, not clamped, so one file can overshoot it;
    /// `MAX_FILE_BYTES` is what bounds that overshoot. The worst case is this plus 2 MiB, and
    /// setting this field cannot move the second half.
    pub max_bytes_scanned: usize,
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

    /// Trim `lines` to the entry cap, reporting how many were dropped.
    ///
    /// The count, not a bare "truncated": a model that knows it saw 200 of 4000
    /// matches can narrow its search.
    pub(crate) fn cap_entries(&self, mut lines: Vec<String>) -> Vec<String> {
        let total = lines.len();
        if total > self.max_entries {
            lines.truncate(self.max_entries);
            lines.push(format!(
                "... truncated: showing {} of {total} results",
                self.max_entries
            ));
        }
        lines
    }

    pub(crate) fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Trim `content` to the byte cap, reporting how much was dropped.
    pub(crate) fn cap_bytes(&self, mut content: String) -> String {
        if content.len() > self.max_bytes {
            // Cutting at a byte offset can land mid-character; back up to a boundary.
            let mut end = self.max_bytes;
            while end > 0 && !content.is_char_boundary(end) {
                end -= 1;
            }

            let total = content.len();
            content.truncate(end);
            content.push_str(&format!("\n... truncated: showing {end} of {total} bytes"));
        }
        content
    }
}
