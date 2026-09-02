//! Composable decode pipeline for script deobfuscation.
//!
//! Each `DecodeStep` represents a single transform (base64, zlib, XOR, etc.).
//! Steps are applied in sequence to recover the original payload.

use base64::Engine;

/// Maximum decoded output size to prevent memory exhaustion (10 MB).
const MAX_DECODED_SIZE: usize = 10 * 1024 * 1024;

/// Maximum recursion depth for nested obfuscation.
pub const MAX_DECODE_DEPTH: usize = 3;

/// A single step in a decode chain.
#[derive(Debug, Clone)]
pub enum DecodeStep {
    /// Standard base64 decoding
    Base64,
    /// Zlib inflate (raw deflate stream)
    Zlib,
    /// Gzip decompression
    Gzip,
    /// Single-byte XOR with a known key
    Xor(u8),
    /// ROT13 on ASCII letters
    Rot13,
    /// Caesar rotation of ASCII letters by an arbitrary amount. ROT13 is the
    /// self-inverse special case that gets its own variant; packers routinely
    /// pick another shift precisely because 13 is the one people try.
    Rot(u8),
    /// UTF-16LE to UTF-8
    Utf16Le,
    /// Reverse the byte sequence
    Reverse,
    /// Decode a list of integer char codes to a string (already parsed to bytes)
    CharCodes(Vec<u8>),
    /// Hex decoding (e.g., "48656c6c6f" → "Hello")
    HexDecode,
}

impl std::fmt::Display for DecodeStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rot(n) => write!(f, "rot{n}"),
            Self::Base64 => write!(f, "base64"),
            Self::Zlib => write!(f, "zlib"),
            Self::Gzip => write!(f, "gzip"),
            Self::Xor(key) => write!(f, "xor(0x{key:02x})"),
            Self::Rot13 => write!(f, "rot13"),
            Self::Utf16Le => write!(f, "utf16le"),
            Self::Reverse => write!(f, "reverse"),
            Self::CharCodes(_) => write!(f, "charcodes"),
            Self::HexDecode => write!(f, "hex"),
        }
    }
}

/// Result of successfully applying a decode chain.
#[derive(Debug, Clone)]
pub struct DecodeResult {
    /// The decoded payload as a UTF-8 string
    pub payload: String,
    /// Human-readable description of the decode chain, e.g. "base64+zlib+xor(0x86)"
    pub chain_description: String,
}

/// Apply a sequence of decode steps to a byte buffer.
///
/// Returns `None` if any step fails or the result is not valid UTF-8.
pub fn apply_chain(input: &[u8], steps: &[DecodeStep]) -> Option<DecodeResult> {
    if input.is_empty() || steps.is_empty() {
        return None;
    }

    let mut buf = input.to_vec();
    let mut descriptions = Vec::with_capacity(steps.len());

    for step in steps {
        if buf.len() > MAX_DECODED_SIZE {
            tracing::warn!(
                "Decode chain exceeded max size ({} bytes), aborting",
                buf.len()
            );
            return None;
        }

        buf = apply_step(&buf, step)?;
        descriptions.push(step.to_string());
    }

    // Convert final result to UTF-8
    let payload = String::from_utf8(buf).ok()?;
    if payload.is_empty() {
        return None;
    }

    Some(DecodeResult {
        payload,
        chain_description: descriptions.join("+"),
    })
}

/// Apply a single decode step to a byte buffer.
fn apply_step(input: &[u8], step: &DecodeStep) -> Option<Vec<u8>> {
    match step {
        DecodeStep::Base64 => {
            let engine = base64::engine::general_purpose::STANDARD;
            // Try standard first, then try without padding
            engine
                .decode(input)
                .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(input))
                .ok()
        }
        DecodeStep::Zlib => {
            use flate2::read::ZlibDecoder;
            use std::io::Read;
            let mut decoder = ZlibDecoder::new(input);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).ok()?;
            if out.is_empty() {
                return None;
            }
            Some(out)
        }
        DecodeStep::Gzip => {
            use flate2::read::GzDecoder;
            use std::io::Read;
            let mut decoder = GzDecoder::new(input);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).ok()?;
            if out.is_empty() {
                return None;
            }
            Some(out)
        }
        DecodeStep::Xor(key) => Some(input.iter().map(|b| b ^ key).collect()),
        DecodeStep::Rot13 => Some(
            input
                .iter()
                .map(|&b| match b {
                    b'a'..=b'm' | b'A'..=b'M' => b + 13,
                    b'n'..=b'z' | b'N'..=b'Z' => b - 13,
                    _ => b,
                })
                .collect(),
        ),
        DecodeStep::Rot(n) => {
            let n = n % 26;
            Some(
                input
                    .iter()
                    .map(|&b| match b {
                        b'a'..=b'z' => (b - b'a' + n) % 26 + b'a',
                        b'A'..=b'Z' => (b - b'A' + n) % 26 + b'A',
                        _ => b,
                    })
                    .collect(),
            )
        }
        DecodeStep::Utf16Le => {
            if input.len() < 2 || !input.len().is_multiple_of(2) {
                return None;
            }
            let code_units: Vec<u16> = input
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16(&code_units).ok()?;
            Some(s.into_bytes())
        }
        DecodeStep::Reverse => {
            let mut reversed = input.to_vec();
            reversed.reverse();
            Some(reversed)
        }
        DecodeStep::CharCodes(codes) => {
            // Already pre-parsed to bytes
            Some(codes.clone())
        }
        DecodeStep::HexDecode => hex::decode(input).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_step() {
        let input = b"SGVsbG8gV29ybGQ="; // "Hello World"
        let result = apply_step(input, &DecodeStep::Base64);
        assert_eq!(result.as_deref(), Some(b"Hello World".as_slice()));
    }

    #[test]
    fn test_xor_step() {
        let key = 0x42u8;
        let input: Vec<u8> = b"Hello".iter().map(|b| b ^ key).collect();
        let result = apply_step(&input, &DecodeStep::Xor(key));
        assert_eq!(result.as_deref(), Some(b"Hello".as_slice()));
    }

    #[test]
    fn test_rot13_step() {
        let input = b"Uryyb Jbeyq"; // ROT13 of "Hello World"
        let result = apply_step(input, &DecodeStep::Rot13);
        assert_eq!(result.as_deref(), Some(b"Hello World".as_slice()));
    }

    #[test]
    fn test_utf16le_step() {
        let input = b"H\x00e\x00l\x00l\x00o\x00";
        let result = apply_step(input, &DecodeStep::Utf16Le);
        assert_eq!(result.as_deref(), Some(b"Hello".as_slice()));
    }

    #[test]
    fn test_reverse_step() {
        let input = b"dlroW olleH";
        let result = apply_step(input, &DecodeStep::Reverse);
        assert_eq!(result.as_deref(), Some(b"Hello World".as_slice()));
    }

    #[test]
    fn test_hex_step() {
        let input = b"48656c6c6f";
        let result = apply_step(input, &DecodeStep::HexDecode);
        assert_eq!(result.as_deref(), Some(b"Hello".as_slice()));
    }

    #[test]
    fn test_zlib_step() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"Hello World").ok();
        let compressed = encoder.finish().unwrap();
        let result = apply_step(&compressed, &DecodeStep::Zlib);
        assert_eq!(result.as_deref(), Some(b"Hello World".as_slice()));
    }

    #[test]
    fn test_chain_base64_then_xor() {
        // Encode: "Hello" → XOR(0x42) → base64
        let xored: Vec<u8> = b"Hello".iter().map(|b| b ^ 0x42).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&xored);

        let steps = vec![DecodeStep::Base64, DecodeStep::Xor(0x42)];
        let result = apply_chain(encoded.as_bytes(), &steps);
        assert!(result.is_some());
        assert_eq!(result.as_ref().unwrap().payload, "Hello");
        assert_eq!(result.unwrap().chain_description, "base64+xor(0x42)");
    }

    #[test]
    fn test_chain_base64_zlib() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        // Encode: "Hello World" → zlib → base64
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"Hello World").ok();
        let compressed = encoder.finish().unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&compressed);

        let steps = vec![DecodeStep::Base64, DecodeStep::Zlib];
        let result = apply_chain(encoded.as_bytes(), &steps);
        assert!(result.is_some());
        assert_eq!(result.unwrap().payload, "Hello World");
    }

    #[test]
    fn test_chain_base64_zlib_xor() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        // Encode: "import os" → XOR(134) → zlib → base64
        let xored: Vec<u8> = b"import os".iter().map(|b| b ^ 134u8).collect();
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&xored).ok();
        let compressed = encoder.finish().unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&compressed);

        let steps = vec![DecodeStep::Base64, DecodeStep::Zlib, DecodeStep::Xor(134)];
        let result = apply_chain(encoded.as_bytes(), &steps);
        assert!(result.is_some());
        assert_eq!(result.unwrap().payload, "import os");
    }

    #[test]
    fn test_empty_input_returns_none() {
        let result = apply_chain(b"", &[DecodeStep::Base64]);
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_steps_returns_none() {
        let result = apply_chain(b"Hello", &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_invalid_base64_returns_none() {
        let result = apply_chain(b"not!valid!base64!!!", &[DecodeStep::Base64]);
        assert!(result.is_none());
    }
}
