//! JavaScript script deobfuscation patterns.
//!
//! Detects and decodes common JavaScript/Node.js obfuscation recipes:
//! - `eval(atob("..."))`
//! - `eval(Buffer.from("...", "base64").toString())`
//! - `eval(String.fromCharCode(...))`
//! - `eval("...".split("").reverse().join(""))`

use regex::Regex;
use std::sync::LazyLock;

use super::DeobfuscationResult;
use super::decode_chain::DecodeStep;

/// eval(atob("..."))
#[allow(clippy::expect_used)]
static EVAL_ATOB_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"eval\s*\(\s*atob\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)"#).expect("static regex")
});

/// eval(Buffer.from("...", "base64").toString())
#[allow(clippy::expect_used)]
static EVAL_BUFFER_B64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"eval\s*\(\s*Buffer\.from\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*,\s*['"]base64['"]\s*\)\.toString\s*\(\s*\)"#)
        .expect("static regex")
});

/// eval(String.fromCharCode(...)) or Function(String.fromCharCode(...))()
#[allow(clippy::expect_used)]
static EVAL_CHARCODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:eval|Function)\s*\(\s*String\.fromCharCode\s*\(([0-9xXa-fA-F,\s]+)\)"#)
        .expect("static regex")
});

/// eval("...".split("").reverse().join(""))
#[allow(clippy::expect_used)]
static EVAL_REVERSE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"eval\s*\(\s*['"]([^'"]+)['"]\s*\.split\s*\(\s*['"]['"]?\s*\)\s*\.reverse\s*\(\s*\)\s*\.join\s*\(\s*['"]['"]?\s*\)"#)
        .expect("static regex")
});

/// Extract all obfuscated payloads from a JavaScript source.
pub(super) fn extract_obfuscated_payloads(source: &str) -> Vec<DeobfuscationResult> {
    let mut results = Vec::new();

    results.extend(try_eval_atob(source));
    results.extend(try_eval_buffer_b64(source));
    results.extend(try_eval_charcode(source));
    results.extend(try_eval_reverse(source));

    results
}

fn try_eval_atob(source: &str) -> Vec<DeobfuscationResult> {
    EVAL_ATOB_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let blob = cap.get(1)?.as_str().replace(char::is_whitespace, "");
            let offset = cap.get(0)?.start();
            let steps = vec![DecodeStep::Base64];
            let result = super::decode_chain::apply_chain(blob.as_bytes(), &steps)?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("javascript:{}", result.chain_description),
                language: "javascript",
            })
        })
        .collect()
}

fn try_eval_buffer_b64(source: &str) -> Vec<DeobfuscationResult> {
    EVAL_BUFFER_B64_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let blob = cap.get(1)?.as_str().replace(char::is_whitespace, "");
            let offset = cap.get(0)?.start();
            let steps = vec![DecodeStep::Base64];
            let result = super::decode_chain::apply_chain(blob.as_bytes(), &steps)?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("javascript:{}", result.chain_description),
                language: "javascript",
            })
        })
        .collect()
}

fn try_eval_charcode(source: &str) -> Vec<DeobfuscationResult> {
    EVAL_CHARCODE_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let nums_str = cap.get(1)?.as_str();
            let offset = cap.get(0)?.start();
            let bytes: Vec<u8> = nums_str
                .split(',')
                .filter_map(|n| {
                    let n = n.trim();
                    if let Some(hex) = n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        n.parse::<u32>().ok()
                    }
                })
                .filter(|&n| n <= 0x10FFFF)
                .filter_map(char::from_u32)
                .collect::<String>()
                .into_bytes();
            if bytes.is_empty() {
                return None;
            }
            let payload = String::from_utf8(bytes).ok()?;
            Some(DeobfuscationResult {
                decoded: payload,
                offset,
                chain_description: "javascript:charcodes".to_string(),
                language: "javascript",
            })
        })
        .collect()
}

fn try_eval_reverse(source: &str) -> Vec<DeobfuscationResult> {
    EVAL_REVERSE_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let reversed = cap.get(1)?.as_str();
            let offset = cap.get(0)?.start();
            let steps = vec![DecodeStep::Reverse];
            let result = super::decode_chain::apply_chain(reversed.as_bytes(), &steps)?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("javascript:{}", result.chain_description),
                language: "javascript",
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eval_atob() {
        let src = r#"eval(atob("YWxlcnQoMSk="))"#; // alert(1)
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "alert(1)");
        assert!(results[0].chain_description.contains("javascript"));
    }

    #[test]
    fn test_eval_atob_single_quotes() {
        let src = r#"eval(atob('YWxlcnQoMSk='))"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "alert(1)");
    }

    #[test]
    fn test_eval_buffer_from() {
        let src = r#"eval(Buffer.from("YWxlcnQoMSk=", "base64").toString())"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "alert(1)");
    }

    #[test]
    fn test_eval_charcode_decimal() {
        // "alert(1)" as char codes
        let src = r#"eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41))"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "alert(1)");
    }

    #[test]
    fn test_eval_charcode_hex() {
        let src = r#"eval(String.fromCharCode(0x61, 0x6c, 0x65, 0x72, 0x74, 0x28, 0x31, 0x29))"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "alert(1)");
    }

    #[test]
    fn test_eval_reverse() {
        let src = r#"eval(")1(trela".split("").reverse().join(""))"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "alert(1)");
    }

    #[test]
    fn test_no_false_positive_on_atob_in_variable() {
        // atob not inside eval should not trigger
        let src = r#"var data = atob("YWxlcnQoMSk=");"#;
        let results = extract_obfuscated_payloads(src);
        assert!(results.is_empty());
    }
}
