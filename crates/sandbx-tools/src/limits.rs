/// How much a tool may return.
///
/// Output goes straight into the model's context, so an uncapped result can
/// evict the conversation that explains what the agent was doing — and the
/// tokens are spent before `sandbx-agent` ever sees the result, so it cannot be
/// fixed downstream.
///
/// Defaults are deliberately generous enough that ordinary work never notices
/// them, and small enough that one broad search cannot swamp a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputLimits {
    max_entries: usize,
    max_bytes: usize,
}

impl Default for OutputLimits {
    fn default() -> Self {
        Self {
            // Enough to see a real pattern of matches; far short of a whole tree.
            max_entries: 200,
            // Comfortably larger than a source file, well short of a context window.
            max_bytes: 256 * 1024,
        }
    }
}

impl OutputLimits {
    /// Cap on the number of result lines a listing tool may return.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Cap on the bytes a content tool may return.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

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
    /// The count is included rather than a bare "truncated" because a model that
    /// knows it saw 200 of 4000 matches can narrow its search, where one that
    /// only knows it was cut off cannot judge by how much.
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

        // Cutting at a byte offset can land mid-character, which would leave
        // invalid UTF-8. Back up to the nearest boundary.
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
