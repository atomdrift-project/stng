//! What counts as readable text in a decoder's output.

/// Whether `c` could appear in text a person reads: anything but a control
/// character, except the whitespace controls tab, newline and carriage return.
pub(crate) fn is_readable(c: char) -> bool {
    !c.is_control() || matches!(c, '\n' | '\r' | '\t')
}

/// `bytes` as a string, if they are UTF-8 made of readable characters.
pub(crate) fn readable(bytes: Vec<u8>) -> Option<String> {
    String::from_utf8(bytes)
        .ok()
        .filter(|s| s.chars().all(is_readable))
}
