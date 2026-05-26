//! PHP script deobfuscation patterns.
//!
//! Detects and decodes common PHP webshell obfuscation:
//! - `eval(base64_decode("..."))`
//! - `eval(gzinflate(base64_decode("...")))`
//! - `eval(gzuncompress(base64_decode("...")))`
//! - `eval(str_rot13("..."))`

use base64::Engine;
use regex::Regex;
use std::sync::LazyLock;

use super::DeobfuscationResult;
use super::decode_chain::DecodeStep;

/// eval(base64_decode("..."))
#[allow(clippy::expect_used)]
static EVAL_B64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"eval\s*\(\s*base64_decode\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)"#)
        .expect("static regex")
});

/// eval(gzinflate(base64_decode("..."))) — the classic PHP webshell
#[allow(clippy::expect_used)]
static EVAL_GZINFLATE_B64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"eval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)"#,
    )
    .expect("static regex")
});

/// eval(gzuncompress(base64_decode("...")))
#[allow(clippy::expect_used)]
static EVAL_GZUNCOMPRESS_B64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"eval\s*\(\s*gzuncompress\s*\(\s*base64_decode\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)"#,
    )
    .expect("static regex")
});

/// eval(str_rot13("...")) — uses double-quote delimited capture to handle embedded single quotes
#[allow(clippy::expect_used)]
static EVAL_ROT13_DOUBLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"eval\s*\(\s*str_rot13\s*\(\s*"([^"]+)"\s*\)"#).expect("static regex")
});

/// eval(str_rot13('...')) — single-quote delimited
#[allow(clippy::expect_used)]
static EVAL_ROT13_SINGLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"eval\s*\(\s*str_rot13\s*\(\s*'([^']+)'\s*\)"#).expect("static regex")
});

/// Extract all obfuscated payloads from a PHP source.
pub(super) fn extract_obfuscated_payloads(source: &str) -> Vec<DeobfuscationResult> {
    let mut results = Vec::new();

    results.extend(try_eval_gzinflate_b64(source));
    results.extend(try_eval_gzuncompress_b64(source));
    results.extend(try_eval_b64(source));
    results.extend(try_eval_rot13(source));

    results
}

fn try_eval_b64(source: &str) -> Vec<DeobfuscationResult> {
    EVAL_B64_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let blob = cap.get(1)?.as_str().replace(char::is_whitespace, "");
            let offset = cap.get(0)?.start();
            let steps = vec![DecodeStep::Base64];
            let result = super::decode_chain::apply_chain(blob.as_bytes(), &steps)?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("php:{}", result.chain_description),
                language: "php",
            })
        })
        .collect()
}

fn try_eval_gzinflate_b64(source: &str) -> Vec<DeobfuscationResult> {
    EVAL_GZINFLATE_B64_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let blob = cap.get(1)?.as_str().replace(char::is_whitespace, "");
            let offset = cap.get(0)?.start();
            // PHP gzinflate expects raw deflate data (no zlib header)
            let decoded_b64 = base64::engine::general_purpose::STANDARD
                .decode(blob.as_bytes())
                .ok()?;
            let inflated = inflate_raw(&decoded_b64)?;
            let payload = String::from_utf8(inflated).ok()?;
            if payload.is_empty() {
                return None;
            }
            Some(DeobfuscationResult {
                decoded: payload,
                offset,
                chain_description: "php:base64+gzinflate".to_string(),
                language: "php",
            })
        })
        .collect()
}

fn try_eval_gzuncompress_b64(source: &str) -> Vec<DeobfuscationResult> {
    EVAL_GZUNCOMPRESS_B64_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let blob = cap.get(1)?.as_str().replace(char::is_whitespace, "");
            let offset = cap.get(0)?.start();
            // PHP gzuncompress expects zlib-compressed data (with header)
            let steps = vec![DecodeStep::Base64, DecodeStep::Zlib];
            let result = super::decode_chain::apply_chain(blob.as_bytes(), &steps)?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("php:{}", result.chain_description),
                language: "php",
            })
        })
        .collect()
}

fn try_eval_rot13(source: &str) -> Vec<DeobfuscationResult> {
    let iter = EVAL_ROT13_DOUBLE_RE
        .captures_iter(source)
        .chain(EVAL_ROT13_SINGLE_RE.captures_iter(source));
    iter.filter_map(|cap| {
        let encoded = cap.get(1)?.as_str();
        let offset = cap.get(0)?.start();
        let steps = vec![DecodeStep::Rot13];
        let result = super::decode_chain::apply_chain(encoded.as_bytes(), &steps)?;
        Some(DeobfuscationResult {
            decoded: result.payload,
            offset,
            chain_description: format!("php:{}", result.chain_description),
            language: "php",
        })
    })
    .collect()
}

/// Raw deflate decompression (no zlib/gzip header).
/// This is what PHP's `gzinflate()` expects.
fn inflate_raw(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;
    let mut decoder = DeflateDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    if out.is_empty() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn test_eval_base64_decode() {
        let src = r#"<?php eval(base64_decode("ZWNobyAiaGVsbG8iOw==")); ?>"#;
        // "echo \"hello\";"
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "echo \"hello\";");
        assert!(results[0].chain_description.contains("php"));
    }

    #[test]
    fn test_eval_gzinflate_base64() {
        // Create: "echo 'hello';" → raw deflate → base64
        use flate2::Compression;
        use flate2::write::DeflateEncoder;
        use std::io::Write;

        let payload = b"echo 'hello';";
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).ok();
        let compressed = encoder.finish().unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&compressed);

        let src = format!(r#"<?php eval(gzinflate(base64_decode("{encoded}"))); ?>"#);
        let results = extract_obfuscated_payloads(&src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "echo 'hello';");
    }

    #[test]
    fn test_eval_gzuncompress_base64() {
        // Create: "echo 'hello';" → zlib compress → base64
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let payload = b"echo 'hello';";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).ok();
        let compressed = encoder.finish().unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&compressed);

        let src = format!(r#"<?php eval(gzuncompress(base64_decode("{encoded}"))); ?>"#);
        let results = extract_obfuscated_payloads(&src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "echo 'hello';");
    }

    #[test]
    fn test_eval_str_rot13() {
        let src = r#"<?php eval(str_rot13("rpub 'uryyb';")); ?>"#;
        // ROT13 of "echo 'hello';"
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "echo 'hello';");
    }

    #[test]
    fn test_no_false_positive_on_non_eval_base64() {
        let src = r#"<?php $data = base64_decode("YWJj"); echo $data; ?>"#;
        let results = extract_obfuscated_payloads(src);
        assert!(results.is_empty());
    }
}
