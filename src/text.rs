//! What counts as readable text in a decoder's output.

/// Whether `c` could appear in text a person reads: anything but a control
/// character, except the whitespace controls tab, newline and carriage return.
pub(crate) fn is_readable(c: char) -> bool {
    !c.is_control() || matches!(c, '\n' | '\r' | '\t')
}

/// `c` rotated `n` places through the ASCII alphabet (ROT13 for `n` = 13);
/// anything but an ASCII letter is unchanged.
pub(crate) fn rot(c: char, n: u8) -> char {
    let base = match c {
        'a'..='z' => b'a',
        'A'..='Z' => b'A',
        _ => return c,
    };
    char::from((c as u8 - base + n % 26) % 26 + base)
}

/// `bytes` as a string, if they are UTF-8 made of readable characters.
pub(crate) fn readable(bytes: Vec<u8>) -> Option<String> {
    String::from_utf8(bytes)
        .ok()
        .filter(|s| s.chars().all(is_readable))
}

/// How much `bytes` read like natural-language ASCII text, 0 to 100, and the
/// percentage of its letters that are vowels: `(quality, vowel_ratio)`.
pub(crate) fn quality(bytes: &[u8]) -> (u32, u32) {
    if bytes.is_empty() {
        return (0, 0);
    }

    let mut alpha = 0usize;
    let mut vowel = 0usize;
    let mut printable = 0usize;

    for &b in bytes {
        if b.is_ascii_alphabetic() {
            alpha += 1;
            if matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u') {
                vowel += 1;
            }
        }
        if b.is_ascii_graphic() || b == b' ' {
            printable += 1;
        }
    }

    let printable_ratio = (printable * 100) / bytes.len();
    let vowel_ratio = (vowel * 100).checked_div(alpha).unwrap_or(0);

    // Weighted combination: printability matters most, vowel ratio indicates natural language
    let quality = u32::try_from((printable_ratio * 7 + vowel_ratio * 3) / 10).unwrap_or(0);
    (quality, u32::try_from(vowel_ratio).unwrap_or(0))
}
