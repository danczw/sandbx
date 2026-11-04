//! How a failed run reaches the operator: the error, and every cause below it.

use std::error::Error;

/// `error` and every cause below it, each joined to the last by `: `.
///
/// Every sandbx error already writes its source into its own message, so a link is
/// printed only when its parent's did not include it. That check is against the parent
/// and not the line so far, so a short cause is not hidden by unrelated text above it.
/// What this adds is the foreign links: reqwest's message names only the URL, and the
/// DNS failure, the refused connection or the rejected certificate sits below it (#457).
///
/// The walk follows `source()` and nothing else, so an error that withholds a cause
/// keeps it withheld — `AuthError::Malformed` has none because toml's quotes the key.
///
/// A foreign link is text sandbx did not write — a certificate's names come through
/// rustls-webpki raw — so an escape in one would rewrite the operator's terminal. Each
/// control or [`sandbx_text::invisible`] character is replaced with U+FFFD rather than
/// dropped, and `\n` and `\t` are spelled, so the report stays the one line it reads as.
#[must_use]
pub fn error_line(error: &dyn Error) -> String {
    let mut line = error.to_string();
    let mut parent = line.clone();
    let mut cause = error.source();
    while let Some(link) = cause {
        let text = link.to_string();
        if !parent.contains(&text) {
            line.push_str(": ");
            line.push_str(&text);
        }
        parent = text;
        cause = link.source();
    }

    let mut out = String::with_capacity(line.len());
    for c in line.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || sandbx_text::invisible(c) => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[path = "error_line_tests.rs"]
mod tests;
