//! PHP script deobfuscation patterns.
//!
//! Detects and decodes common PHP webshell obfuscation:
//! - `eval(base64_decode("..."))`
//! - `eval(gzinflate(base64_decode("...")))`
//! - `eval(gzuncompress(base64_decode("...")))`
//! - `eval(str_rot13("..."))`

use crate::script::detect::ScriptLanguage;
use base64::Engine;
use regex::Regex;
use std::sync::LazyLock;

use super::DeobfuscationResult;
use super::decode_chain::DecodeStep;

/// eval(base64_decode("..."))
static EVAL_B64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"eval\s*\(\s*base64_decode\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)"#)
        .unwrap_or_else(crate::invalid_pattern)
});

/// eval(gzinflate(base64_decode("..."))) — the classic PHP webshell
static EVAL_GZINFLATE_B64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"eval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)"#,
    )
    .unwrap_or_else(crate::invalid_pattern)
});

/// eval(gzuncompress(base64_decode("...")))
static EVAL_GZUNCOMPRESS_B64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"eval\s*\(\s*gzuncompress\s*\(\s*base64_decode\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)"#,
    )
    .unwrap_or_else(crate::invalid_pattern)
});

/// eval(str_rot13("...")) — uses double-quote delimited capture to handle embedded single quotes
static EVAL_ROT13_DOUBLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"eval\s*\(\s*str_rot13\s*\(\s*"([^"]+)"\s*\)"#)
        .unwrap_or_else(crate::invalid_pattern)
});

/// eval(str_rot13('...')) — single-quote delimited
static EVAL_ROT13_SINGLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eval\s*\(\s*str_rot13\s*\(\s*'([^']+)'\s*\)")
        .unwrap_or_else(crate::invalid_pattern)
});

/// Extract all obfuscated payloads from a PHP source.
pub(super) fn extract_obfuscated_payloads(source: &str) -> Vec<DeobfuscationResult> {
    let mut results = Vec::new();

    results.extend(try_eval_gzinflate_b64(source));
    results.extend(super::decode_captures(
        source,
        &[&EVAL_GZUNCOMPRESS_B64_RE],
        &[DecodeStep::Base64, DecodeStep::Zlib],
        ScriptLanguage::Php,
    ));
    results.extend(super::decode_captures(
        source,
        &[&EVAL_B64_RE],
        &[DecodeStep::Base64],
        ScriptLanguage::Php,
    ));
    results.extend(super::decode_captures(
        source,
        &[&EVAL_ROT13_DOUBLE_RE, &EVAL_ROT13_SINGLE_RE],
        &[DecodeStep::Rot(13)],
        ScriptLanguage::Php,
    ));

    results
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
            // Raw deflate, no zlib or gzip header: what gzinflate() expects.
            let inflated = super::decode_chain::inflate(flate2::read::DeflateDecoder::new(
                decoded_b64.as_slice(),
            ))?;
            let payload = String::from_utf8(inflated).ok()?;
            if payload.is_empty() {
                return None;
            }
            Some(DeobfuscationResult {
                decoded: payload,
                offset,
                chain_description: "php:base64+gzinflate".to_string(),
                language: ScriptLanguage::Php,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn decodes_eval_base64_decode() {
        let src = r#"<?php eval(base64_decode("ZWNobyAiaGVsbG8iOw==")); ?>"#;
        // "echo \"hello\";"
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "echo \"hello\";");
        assert!(results[0].chain_description.contains("php"));
    }

    #[test]
    fn decodes_eval_gzinflate() {
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
    fn decodes_eval_gzuncompress() {
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
    fn decodes_eval_str_rot13() {
        let src = r#"<?php eval(str_rot13("rpub 'uryyb';")); ?>"#;
        // ROT13 of "echo 'hello';"
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "echo 'hello';");
    }

    #[test]
    fn ignores_base64_decode_outside_eval() {
        let src = r#"<?php $data = base64_decode("YWJj"); echo $data; ?>"#;
        let results = extract_obfuscated_payloads(src);
        assert!(results.is_empty());
    }
}
