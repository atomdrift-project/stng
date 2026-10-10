//! Base64 → zlib must stay binary until inflation has completed.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::{Compression, write::ZlibEncoder};
use std::io::Write;

fn compress(bytes: &[u8], level: u32) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn source(value: &str) -> ExtractedString {
    ExtractedString {
        value: value.to_owned(),
        data_offset: 37,
        data_len: u32::try_from(value.len()).unwrap(),
        method: StringMethod::RawScan,
        kind: Some(StringKind::Base64),
        ..Default::default()
    }
}

fn decode(bytes: &[u8]) -> Option<ExtractedString> {
    decode_base64_string(
        &source(&STANDARD.encode(bytes)),
        &AtomicUsize::new(usize::MAX),
    )
}

#[test]
fn base64_zlib_all_compression_levels_and_headers() {
    let text = "import os\nprint('hello world')\n";
    for level in 0..=9 {
        let compressed = compress(text.as_bytes(), level);
        assert!(std::str::from_utf8(&compressed).is_err());
        let encoded = STANDARD.encode(&compressed);
        let decoded =
            decode_base64_string(&source(&encoded), &AtomicUsize::new(usize::MAX)).unwrap();
        assert_eq!(decoded.value, text, "compression level {level}");
        assert_eq!(decoded.method, StringMethod::Base64Decode);
        assert_eq!(decoded.data_offset, 37);
        assert_eq!(decoded.data_len as usize, encoded.len());
        assert_eq!(
            decoded.source_spans().collect::<Vec<_>>(),
            vec![(37, encoded.len() as u64)]
        );
    }
}

#[test]
fn base64_zlib_utf8_is_not_rejected_by_ascii_quality_score() {
    let text = "# 日本語 🦀\nprint('Здравствуйте')\n\t# café\n";
    assert_eq!(decode(&compress(text.as_bytes(), 9)).unwrap().value, text);
}

#[test]
fn base64_zlib_utf16le_is_decoded_after_inflation() {
    let text = "Invoke-WebRequest https://example.com/payload.ps1";
    let mut bytes = vec![0xff, 0xfe];
    bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    assert_eq!(decode(&compress(&bytes, 6)).unwrap().value, text);
}

#[test]
fn base64_zlib_omitted_and_partial_terminal_padding() {
    for text in ["print('one')\n", "print('two!!')\n", "print('three!!!')\n"] {
        let encoded = STANDARD.encode(compress(text.as_bytes(), 9));
        for removed in 0..=encoded.bytes().rev().take_while(|b| *b == b'=').count() {
            let unpadded = &encoded[..encoded.len() - removed];
            assert_eq!(
                decode_base64_string(&source(unpadded), &AtomicUsize::new(usize::MAX))
                    .unwrap()
                    .value,
                text
            );
        }
    }
}

#[test]
fn base64_zlib_concatenated_literals_keep_source_extent() {
    let text = "import socket\nprint('example.com')\n";
    let encoded = STANDARD.encode(compress(text.as_bytes(), 6));
    let split = encoded.len() / 2;
    let expression = format!("'{}' + '{}'", &encoded[..split], &encoded[split..]);
    let mut input = source(&expression);
    input.kind = None;
    let found = decode_base64_strings(&[input]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].value, text);
    assert_eq!(found[0].data_offset, 37);
    assert_eq!(found[0].data_len as usize, expression.len());
}

#[test]
fn base64_zlib_embedded_literals_have_byte_offsets_and_encoded_lengths() {
    let text = "print('decoded module')\n";
    let encoded = STANDARD.encode(compress(text.as_bytes(), 9));
    let prefix = "# café\nexec(_z.decompress(_b.b64decode('";
    let wrapper = format!("{prefix}{encoded}')).decode('utf-8'), globals())");
    let found = extract_embedded_base64(&[source(&wrapper)]);
    let decoded = found.iter().find(|s| s.value == text.trim()).unwrap();
    assert_eq!(decoded.method, StringMethod::Base64Decode);
    assert_eq!(decoded.data_offset, 37 + prefix.len() as u64);
    assert_eq!(decoded.data_len as usize, encoded.len());
}

#[test]
fn base64_zlib_rejects_every_truncation_of_a_valid_stream() {
    let compressed = compress(b"import os\nprint('a complete module')\n", 9);
    for end in 0..compressed.len() {
        assert!(
            decode(&compressed[..end]).is_none(),
            "accepted prefix {end}"
        );
    }
}

#[test]
fn base64_zlib_checks_adler32_before_returning_text() {
    let compressed = compress(b"print('checksum must be checked')\n", 6);
    for position in compressed.len() - 4..compressed.len() {
        let mut damaged = compressed.clone();
        damaged[position] ^= 0x80;
        assert!(decode(&damaged).is_none());
    }
}

#[test]
fn base64_zlib_trailing_data_does_not_hide_the_first_stream() {
    let text = "print('first module')\n";
    let compressed = compress(text.as_bytes(), 9);
    for suffix in [
        vec![0],
        b"hidden trailing data".to_vec(),
        compressed.clone(),
    ] {
        let mut bytes = compressed.clone();
        bytes.extend(suffix);
        assert_eq!(decode(&bytes).unwrap().value, text);
    }
}

#[test]
fn base64_zlib_accepts_all_rfc1950_window_headers() {
    // This short DEFLATE body needs no back-reference beyond the smallest
    // window, so its window declaration can validly range from 256 to 32768.
    let text = "print('small window')\n";
    for window in 0u8..=7 {
        let mut compressed = compress(text.as_bytes(), 6);
        let cmf = (window << 4) | 8;
        let flags = 0x80u8;
        let check = (31 - u16::from_be_bytes([cmf, flags]) % 31) % 31;
        compressed[..2].copy_from_slice(&[cmf, flags | check as u8]);
        assert_eq!(decode(&compressed).unwrap().value, text, "window {window}");
    }
}

#[test]
fn base64_zlib_rejects_reserved_deflate_block_type() {
    let mut compressed = compress(b"print('valid module')\n", 9);
    compressed[2] = 0x07; // BFINAL=1, BTYPE=3 (reserved)
    assert!(decode(&compressed).is_none());
}

#[test]
fn base64_zlib_size_limit_applies_to_base64_input_too() {
    let mut bytes = vec![b'A'; MAX_DECODED_SIZE];
    assert_eq!(
        decode_base64_bytes(&STANDARD.encode(&bytes)).unwrap(),
        bytes
    );
    for _ in 0..3 {
        bytes.push(b'A');
        assert!(decode_base64_bytes(&STANDARD.encode(&bytes)).is_none());
    }
    assert!(decode_base64_bytes(&"A".repeat(MAX_DECODED_SIZE.div_ceil(3) * 4 + 4)).is_none());
}

#[test]
fn base64_zlib_damaged_embedded_token_does_not_suppress_other_payloads() {
    let text = "print('the valid payload')\n";
    let compressed = compress(text.as_bytes(), 9);
    let good = STANDARD.encode(&compressed);
    let broken = STANDARD.encode(&compressed[..compressed.len() - 1]);
    let wrapper = format!("first='{broken}'; second='{good}'");
    let found = extract_embedded_base64(&[source(&wrapper)]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].value, text.trim());
    assert_eq!(
        found[0].data_offset,
        37 + wrapper.find(&good).unwrap() as u64
    );
    assert_eq!(found[0].data_len as usize, good.len());
}

#[test]
fn base64_zlib_bad_stream_never_leaks_partial_text_in_embedded_path() {
    let mut compressed = compress(b"print('do not return a fragment')\n", 9);
    compressed.pop();
    let wrapper = format!(
        "exec(_z.decompress(_b.b64decode('{}')))",
        STANDARD.encode(compressed)
    );
    assert!(extract_embedded_base64(&[source(&wrapper)]).is_empty());
}

#[test]
fn base64_zlib_decoded_content_is_classified_as_content() {
    let text = "https://example.com/payload.py";
    let result = decode(&compress(text.as_bytes(), 6)).unwrap();
    assert_eq!(result.value, text);
    assert_eq!(result.kind, crate::classify_string(text));
    assert_ne!(result.kind, Some(StringKind::Base64));
}

#[test]
fn base64_zlib_rejects_binary_and_malformed_wide_text() {
    for binary in [
        &b"\xff\xfe\xfd\xfc\xfb\xfa"[..],
        &b"MZ\0\0\x01\0\0\0binary image"[..],
        &b"a\0b\0c\0\0\xd8"[..], // unpaired UTF-16 surrogate
    ] {
        assert!(decode(&compress(binary, 9)).is_none());
    }
}

#[test]
fn base64_zlib_rejects_empty_short_and_whitespace_payloads() {
    for bytes in [&b""[..], &b"abc"[..], &b" \t\r\n"[..]] {
        let compressed = compress(bytes, 9);
        assert!(decode(&compressed).is_none());
        let wrapper = format!(
            "exec(zlib.decompress(base64.b64decode('{}')))",
            STANDARD.encode(&compressed)
        );
        assert!(extract_embedded_base64(&[source(&wrapper)]).is_empty());
    }
}

#[test]
fn base64_zlib_rejects_invalid_headers_and_dictionary_streams() {
    let compressed = compress(b"print('valid module')\n", 9);
    for header in [[0x78, 0xdb], [0x79, 0xda], [0x88, 0xda], [0x78, 0x20]] {
        let mut damaged = compressed.clone();
        damaged[..2].copy_from_slice(&header);
        assert!(decode(&damaged).is_none());
    }
    // RFC 1950 preset-dictionary header; no external dictionary is available.
    assert_eq!(u16::from_be_bytes([0x78, 0x20]) % 31, 0);
}

#[test]
fn base64_zlib_accepts_exact_output_cap_and_rejects_one_byte_over() {
    let mut text = vec![b'A'; MAX_DECODED_SIZE];
    assert_eq!(
        decode(&compress(&text, 9)).unwrap().value.len(),
        MAX_DECODED_SIZE
    );
    text.push(b'A');
    assert!(decode(&compress(&text, 9)).is_none());
}

#[test]
fn base64_zlib_rejects_a_high_ratio_decompression_bomb() {
    let bomb = compress(&vec![b'A'; MAX_DECODED_SIZE * 2], 9);
    assert!(bomb.len() < 32 * 1024);
    assert!(decode(&bomb).is_none());
}

#[test]
fn base64_zlib_does_not_weaken_plain_base64_false_positive_checks() {
    assert!(
        decode_base64_string(
            &source("IWorkItemQueriesExt2"),
            &AtomicUsize::new(usize::MAX)
        )
        .is_none()
    );
    let text = "Hello World!";
    assert_eq!(
        decode_base64_string(
            &source(&STANDARD.encode(text)),
            &AtomicUsize::new(usize::MAX)
        )
        .unwrap()
        .value,
        text
    );
    assert!(decode(&[0xff, 0x00, 0x8b, 0x01, 0xfe, 0x98, 0xab, 0xcd]).is_none());
}

#[test]
fn base64_zlib_header_collision_does_not_hide_ordinary_base64_text() {
    for text in [
        "x = the answer to this question",
        "x^ hello world, this is readable text",
    ] {
        assert_eq!(
            u16::from_be_bytes([text.as_bytes()[0], text.as_bytes()[1]]) % 31,
            0
        );
        let encoded = STANDARD.encode(text);
        assert_eq!(
            decode_base64_string(&source(&encoded), &AtomicUsize::new(usize::MAX))
                .unwrap()
                .value,
            text
        );
        let wrapper = format!("text='{encoded}'");
        let found = extract_embedded_base64(&[source(&wrapper)]);
        assert!(found.iter().any(|s| s.value == text));
    }
}
