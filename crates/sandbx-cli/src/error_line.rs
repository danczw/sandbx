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
/// Every link is escaped, the top one too: `SandboxError` writes a model-chosen path back,
/// and a cause is text sandbx did not write — a certificate's names come through
/// rustls-webpki raw. Each control or [`sandbx_text::invisible`] character becomes U+FFFD
/// rather than dropped, and `\n` and `\t` are spelled, so the report stays one line.
#[must_use]
pub fn error_line(error: &dyn Error) -> String {
    let mut parent = error.to_string();
    let mut line = String::with_capacity(parent.len());
    push_inert(&mut line, &parent);
    let mut cause = error.source();
    while let Some(link) = cause {
        let text = link.to_string();
        if !parent.contains(&text) {
            line.push_str(": ");
            push_inert(&mut line, &text);
        }
        parent = text;
        cause = link.source();
    }
    line
}

/// `text` onto `line`, with everything that could rewrite the terminal replaced.
fn push_inert(line: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '\n' => line.push_str("\\n"),
            '\t' => line.push_str("\\t"),
            c if c.is_control() || sandbx_text::invisible(c) => line.push('\u{fffd}'),
            c => line.push(c),
        }
    }
}

#[cfg(test)]
#[path = "error_line_tests.rs"]
mod tests;
