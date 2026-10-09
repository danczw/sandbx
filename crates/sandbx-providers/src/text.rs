//! What model-chosen text may not carry to a terminal.
//!
//! Here rather than in a sink, because a character added to one copy and not another
//! re-opens the hole in whichever was missed. Each sink keeps its own replacement: only the
//! hazard is shared.

/// Whether `c` renders as nothing, or reorders what follows it.
///
/// `char::is_control` is `Cc` exactly, so U+202E and the directional isolates pass it and
/// let text *display* as something other than what it says. A denylist because `char` has
/// no predicate for the category, so a new Unicode version can outgrow it silently.
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

    /// Every single arm, and *both* endpoints of every range, as literals rather than read
    /// off the table: one fixture per range pins only the end it names, so narrowing
    /// `200b..=200f` to `200b..=200d` would pass while U+200E and U+200F reached a terminal.
    #[test]
    fn every_arm_of_the_denylist_holds() {
        let singles = "\u{00ad}\u{034f}\u{061c}\u{06dd}\u{070f}\u{08e2}\
                       \u{180e}\u{3164}\u{feff}\u{ffa0}\u{110bd}\u{110cd}";
        let bounds = "\u{0600}\u{0605}\u{0890}\u{0891}\u{115f}\u{1160}\u{200b}\u{200f}\
                      \u{202a}\u{202e}\u{2060}\u{2064}\u{2066}\u{206f}\u{fe00}\u{fe0f}\
                      \u{fff9}\u{fffb}\u{1bca0}\u{1bca3}\u{1d173}\u{1d17a}\u{13430}\u{1343f}\
                      \u{e0000}\u{e007f}\u{e0100}\u{e01ef}";

        for c in singles.chars().chain(bounds.chars()) {
            assert!(invisible(c), "U+{:04X} passed", c as u32);
        }
        // Counted, so a fixture deleted rather than edited is caught. A new *arm* is not:
        // nothing can count `matches!`'s arms, so one added there needs its fixtures here.
        assert_eq!(singles.chars().count(), 12);
        assert_eq!(bounds.chars().count(), 28);
    }

    /// Not vacuous, and not a blanket yes: prose and a path have to pass through whole.
    #[test]
    fn text_that_renders_is_left_alone() {
        for c in "ls /work/notes.md — naïve 日本語 ✓".chars() {
            assert!(!invisible(c), "U+{:04X} refused", c as u32);
        }
        // Just outside a range at each end, and the gap between two adjacent ones: a range
        // widened by one takes a codepoint that renders, which is the error the other way.
        let outside = "\u{05ff}\u{0606}\u{1161}\u{2065}\u{fe10}\u{e0080}";
        for c in outside.chars() {
            assert!(!invisible(c), "U+{:04X} refused", c as u32);
        }
    }
}
