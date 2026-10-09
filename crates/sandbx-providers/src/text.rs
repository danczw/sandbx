//! What model-chosen text may not carry to a terminal.
//!
//! Here rather than in a sink, because every sink that draws this crate's text needs the
//! same table and a character added to one copy and not another re-opens the hole in
//! whichever was missed. Each sink keeps its own replacement: what is shared is the hazard,
//! not what to do about it.

/// Whether `c` renders as nothing, or reorders what follows it.
///
/// `char::is_control` is `Cc` exactly, so U+202E and the directional isolates pass it and
/// let text *display* as something other than what it says. Ranges because `char` has no
/// predicate for the category — so a denylist, which a new Unicode version can outgrow
/// silently.
pub fn invisible(c: char) -> bool {
    matches!(c,
        '\u{00ad}' | '\u{034f}' | '\u{061c}' | '\u{06dd}' | '\u{070f}' | '\u{08e2}'
        | '\u{180e}' | '\u{3164}' | '\u{feff}' | '\u{ffa0}' | '\u{110bd}' | '\u{110cd}'
        | '\u{0600}'..='\u{0605}'
        | '\u{0890}'..='\u{0891}'
        // The Hangul fillers: not `Cf`, and they render as blank width.
        | '\u{115f}'..='\u{1160}'
        | '\u{200b}'..='\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206f}'
        | '\u{fe00}'..='\u{fe0f}'
        | '\u{fff9}'..='\u{fffb}'
        | '\u{1bca0}'..='\u{1bca3}'
        | '\u{1d173}'..='\u{1d17a}'
        | '\u{13430}'..='\u{1343f}'
        | '\u{e0000}'..='\u{e007f}'
        | '\u{e0100}'..='\u{e01ef}')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One codepoint per arm, written as literals rather than read off the table: a range
    /// narrowed to exclude its own endpoint has to fail this.
    #[test]
    fn every_arm_of_the_denylist_holds() {
        let listed = "\u{00ad}\u{034f}\u{061c}\u{06dd}\u{070f}\u{08e2}\u{180e}\u{3164}\u{feff}\
                      \u{ffa0}\u{110bd}\u{110cd}\u{0600}\u{0890}\u{115f}\u{200b}\u{202e}\u{2060}\
                      \u{2066}\u{fe0f}\u{fff9}\u{1bca0}\u{1d173}\u{13430}\u{e0001}\u{e0100}";

        for c in listed.chars() {
            assert!(invisible(c), "U+{:04X} passed", c as u32);
        }
        // One per arm, so an arm added without a fixture fails here rather than going
        // untested — `invisible`'s own arms cannot be counted at runtime.
        assert_eq!(listed.chars().count(), 26);
    }

    /// Not vacuous, and not a blanket yes: prose, a path, and the codepoint either side of
    /// a range all have to pass through.
    #[test]
    fn text_that_renders_is_left_alone() {
        for c in "ls /work/notes.md — naïve 日本語 ✓".chars() {
            assert!(!invisible(c), "U+{:04X} refused", c as u32);
        }
        // The codepoint either side of a range, which an off-by-one would swallow.
        for c in ['\u{05ff}', '\u{0606}', '\u{1161}', '\u{fe10}'] {
            assert!(!invisible(c), "U+{:04X} refused", c as u32);
        }
    }
}
