//! Reads from untrusted bytes: `None` when the value would run past the end of
//! the slice or is malformed, never a panic.

use std::fmt::Write as _;

pub(crate) fn u16_le(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

pub(crate) fn u32_le(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// A hex digit's value.
pub(crate) fn hex_digit(c: u8) -> Option<u8> {
    char::from(c)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// `text` as a hexadecimal number: `None` unless it is one or more hex digits
/// and fits a `u32`. Unlike `u32::from_str_radix`, a `+` sign is not taken.
pub(crate) fn hex_number(text: &str) -> Option<u32> {
    if text.is_empty() {
        return None;
    }
    text.bytes().try_fold(0u32, |n, b| {
        n.checked_mul(16)?.checked_add(u32::from(hex_digit(b)?))
    })
}

/// Hex text as bytes: `None` unless it is an even number of hex digits.
pub(crate) fn from_hex(text: &[u8]) -> Option<Vec<u8>> {
    let (pairs, []) = text.as_chunks::<2>() else {
        return None; // an odd digit left over
    };
    pairs
        .iter()
        .map(|&[h, l]| Some(hex_digit(h)? << 4 | hex_digit(l)?))
        .collect()
}

/// Bytes as lowercase hex.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(text, "{b:02x}");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_stop_at_the_end() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(u16_le(&data, 0), Some(0x0201));
        assert_eq!(u32_le(&data, 4), Some(0x0807_0605));
        assert_eq!(u32_le(&data, 5), None);
        assert_eq!(u16_le(&data, usize::MAX), None);
    }

    #[test]
    fn hex_round_trips_and_rejects_malformed_text() {
        assert_eq!(from_hex(b"00ff7Fa0"), Some(vec![0x00, 0xff, 0x7f, 0xa0]));
        assert_eq!(from_hex(b""), Some(vec![]));
        assert_eq!(from_hex(b"abc"), None);
        assert_eq!(from_hex(b"zz"), None);
        assert_eq!(from_hex("é1".as_bytes()), None);
        assert_eq!(to_hex(&[0x00, 0xff, 0x7f, 0xa0]), "00ff7fa0");
    }

    #[test]
    fn hex_numbers_are_digits_only() {
        assert_eq!(hex_number("ff"), Some(0xff));
        assert_eq!(hex_number("0000000041"), Some(0x41));
        assert_eq!(hex_number("10FFFF"), Some(0x10_ffff));
        assert_eq!(hex_number("+f"), None);
        assert_eq!(hex_number(""), None);
        assert_eq!(hex_number("1_0"), None);
        assert_eq!(hex_number("100000000"), None);
    }
}
