//! Text from peers and from file names, made safe for terminals and logs.
//! Only what is shown changes; file names keep their raw bytes wherever the
//! filesystem sees them.

use std::borrow::Cow;
use std::fmt::Write;

/// `text` with control characters and bidirectional-text controls written
/// as Rust escapes (`\n`, `\u{1b}`, `\u{202e}`), so a name or a peer's
/// message cannot move the cursor, recolor or retitle the terminal, or
/// forge a line of log output.
pub fn escape(text: &str) -> Cow<'_, str> {
    if !text.chars().any(hazardous) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        if hazardous(c) {
            write!(out, "{}", c.escape_default()).expect("writing to a String");
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

fn hazardous(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

/// At most `max` bytes of `text`, cut at a character boundary and marked
/// with an ellipsis when cut.
pub fn truncate(text: &str, max: usize) -> Cow<'_, str> {
    if text.len() <= max {
        return Cow::Borrowed(text);
    }
    let end = (0..=max)
        .rev()
        .find(|&i| text.is_char_boundary(i))
        .unwrap_or(0);
    Cow::Owned(format!("{}...", &text[..end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_are_escaped_and_plain_text_is_borrowed() {
        assert!(matches!(escape("plain caf\u{e9}.bin"), Cow::Borrowed(_)));
        assert_eq!(
            escape("a\x1b]52;c;ZXZpbA==\x07\nwarning: forged\u{202e}gpj.exe\u{9b}"),
            "a\\u{1b}]52;c;ZXZpbA==\\u{7}\\nwarning: forged\\u{202e}gpj.exe\\u{9b}"
        );
    }

    #[test]
    fn truncate_cuts_at_a_char_boundary() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("abcdef", 3), "abc...");
        assert_eq!(truncate("\u{e9}\u{e9}", 3), "\u{e9}...");
    }
}
