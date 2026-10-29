//! What model-chosen text may not carry to a terminal.
//!
//! A crate rather than a module in either sink, because a character added to one copy and
//! not another re-opens the hole in whichever was missed: `sandbx-cli`'s line sink and
//! `sandbx-tui-transcript`'s cell read the same [`invisible`], and a drift between them
//! would be a terminal-injection difference between two surfaces users read as the same.
//! Each sink keeps its own replacement: only the hazard is shared.
//!
//! Not `sandbx-core`, which is Linux-only, so a pure-Unicode predicate would be too — and
//! it would add a terminal-UI → `core` edge. Not `sandbx-tui-transcript`, which would put
//! a `char` predicate in a drawing crate's public API and have the gate read that crate
//! for text bound for stderr and `/dev/tty` (#363).

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
#[path = "text_tests.rs"]
mod tests;
