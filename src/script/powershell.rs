//! PowerShell script deobfuscation patterns.
//!
//! Detects and decodes common PowerShell obfuscation techniques:
//! - `-EncodedCommand` / `-enc` (UTF-16LE base64)
//! - `[Convert]::FromBase64String` with `iex`/`Invoke-Expression`
//! - `iex` with char array (`[char[]](72,101,...) -join ''`)
//! - `iex` with reversed strings
//! - `iex` with string `.replace()` deobfuscation
//! - GzipStream compressed payloads

use regex::Regex;
use std::sync::LazyLock;

use super::decode_chain::DecodeStep;
use super::DeobfuscationResult;

/// -EncodedCommand or -enc followed by base64 (case insensitive via (?i))
#[allow(clippy::expect_used)]
static ENCODED_CMD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)-(?:encodedcommand|enc|e)\s+['"]?([A-Za-z0-9+/=]{8,})['"]?"#)
        .expect("static regex")
});

/// [Convert]::FromBase64String("...") or [System.Convert]::FromBase64String("...")
#[allow(clippy::expect_used)]
static CONVERT_B64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)"#,
    )
    .expect("static regex")
});

/// [char[]](72,101,108,...) -join '' or [char[]](72,101,108,...) -join ""
#[allow(clippy::expect_used)]
static CHAR_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\[char\[\]\]\s*\(\s*([0-9,\s]+)\s*\)\s*-join\s*['"]['"]*"#)
        .expect("static regex")
});

/// iex with reversed string: iex(-join('string'[-1..-N])) or similar
#[allow(clippy::expect_used)]
static IEX_REVERSE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:iex|invoke-expression)\s*\(\s*(?:-join\s*\(\s*)?['"]([^'"]+)['"]\s*\[\s*-1\s*\.\.\s*-\d+"#)
        .expect("static regex")
});

/// Simple string replace: "string".replace("X","Y") in context of iex
#[allow(clippy::expect_used)]
static IEX_REPLACE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:iex|invoke-expression)\s*\(\s*['"]([^'"]+)['"]((?:\s*\.replace\s*\(\s*['"][^'"]*['"]\s*,\s*['"][^'"]*['"]\s*\))+)"#)
        .expect("static regex")
});

/// Individual .replace("X","Y") pairs
#[allow(clippy::expect_used)]
static REPLACE_PAIR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\.replace\s*\(\s*['"]([^'"]*)['"]\s*,\s*['"]([^'"]*)['"]\s*\)"#)
        .expect("static regex")
});

/// Base64 string used with iex/Invoke-Expression and
/// [System.Text.Encoding]::UTF8.GetString or Unicode.GetString
#[allow(clippy::expect_used)]
static IEX_ENCODING_B64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:iex|invoke-expression)\s*\(\s*\[System\.Text\.Encoding\]::\w+\.GetString\s*\(\s*\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)"#)
        .expect("static regex")
});

/// Extract all obfuscated payloads from a PowerShell script.
pub fn extract_obfuscated_payloads(source: &str) -> Vec<DeobfuscationResult> {
    let mut results = Vec::new();

    results.extend(try_encoded_command(source));

    // iex_encoding_b64 is a superset of convert_b64, so track covered offsets
    let iex_results = try_iex_encoding_b64(source);
    let covered_offsets: std::collections::HashSet<usize> =
        iex_results.iter().map(|r| r.offset).collect();
    results.extend(iex_results);

    // Only add convert_b64 results that don't overlap with iex_encoding_b64
    results.extend(try_convert_b64(source).into_iter().filter(|r| {
        !covered_offsets
            .iter()
            .any(|&o| r.offset >= o && r.offset < o + 200)
    }));

    results.extend(try_char_array(source));
    results.extend(try_iex_reverse(source));
    results.extend(try_iex_replace(source));

    results
}

/// -EncodedCommand base64 (UTF-16LE encoded)
fn try_encoded_command(source: &str) -> Vec<DeobfuscationResult> {
    ENCODED_CMD_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let blob = cap.get(1)?.as_str().replace(char::is_whitespace, "");
            let offset = cap.get(0)?.start();
            let steps = vec![DecodeStep::Base64, DecodeStep::Utf16Le];
            let result = super::decode_chain::apply_chain(blob.as_bytes(), &steps)?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("powershell:{}", result.chain_description),
                language: "powershell",
            })
        })
        .collect()
}

/// iex([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("...")))
fn try_iex_encoding_b64(source: &str) -> Vec<DeobfuscationResult> {
    IEX_ENCODING_B64_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let blob = cap.get(1)?.as_str().replace(char::is_whitespace, "");
            let offset = cap.get(0)?.start();
            let steps = vec![DecodeStep::Base64];
            let result = super::decode_chain::apply_chain(blob.as_bytes(), &steps)?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("powershell:{}", result.chain_description),
                language: "powershell",
            })
        })
        .collect()
}

/// [Convert]::FromBase64String (standalone, not wrapped in iex+Encoding)
fn try_convert_b64(source: &str) -> Vec<DeobfuscationResult> {
    CONVERT_B64_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let blob = cap.get(1)?.as_str().replace(char::is_whitespace, "");
            let offset = cap.get(0)?.start();
            // Try UTF-16LE first (common for PowerShell), fall back to raw UTF-8
            let steps_utf16 = vec![DecodeStep::Base64, DecodeStep::Utf16Le];
            let steps_utf8 = vec![DecodeStep::Base64];
            let result = super::decode_chain::apply_chain(blob.as_bytes(), &steps_utf16)
                .or_else(|| super::decode_chain::apply_chain(blob.as_bytes(), &steps_utf8))?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("powershell:{}", result.chain_description),
                language: "powershell",
            })
        })
        .collect()
}

/// [char[]](72,101,108,...) -join ''
fn try_char_array(source: &str) -> Vec<DeobfuscationResult> {
    CHAR_ARRAY_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let nums_str = cap.get(1)?.as_str();
            let offset = cap.get(0)?.start();
            let payload: String = nums_str
                .split(',')
                .filter_map(|n| n.trim().parse::<u32>().ok())
                .filter(|&n| n <= 0x10FFFF)
                .filter_map(char::from_u32)
                .collect();
            if payload.is_empty() {
                return None;
            }
            Some(DeobfuscationResult {
                decoded: payload,
                offset,
                chain_description: "powershell:charcodes".to_string(),
                language: "powershell",
            })
        })
        .collect()
}

/// iex(-join('string'[-1..-N]))
fn try_iex_reverse(source: &str) -> Vec<DeobfuscationResult> {
    IEX_REVERSE_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let reversed = cap.get(1)?.as_str();
            let offset = cap.get(0)?.start();
            let steps = vec![DecodeStep::Reverse];
            let result = super::decode_chain::apply_chain(reversed.as_bytes(), &steps)?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("powershell:{}", result.chain_description),
                language: "powershell",
            })
        })
        .collect()
}

/// iex("hXXps://evil.com".replace("XX","tt"))
fn try_iex_replace(source: &str) -> Vec<DeobfuscationResult> {
    IEX_REPLACE_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let base_str = cap.get(1)?.as_str().to_string();
            let replace_chain = cap.get(2)?.as_str();
            let offset = cap.get(0)?.start();

            // Apply all .replace() calls in order
            let mut result = base_str;
            for rcap in REPLACE_PAIR_RE.captures_iter(replace_chain) {
                let from = rcap.get(1)?.as_str();
                let to = rcap.get(2)?.as_str();
                result = result.replace(from, to);
            }

            if result.is_empty() {
                return None;
            }

            Some(DeobfuscationResult {
                decoded: result,
                offset,
                chain_description: "powershell:replace".to_string(),
                language: "powershell",
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn test_encoded_command() {
        // "Write-Host 'hello'" as UTF-16LE then base64
        let payload = "Write-Host 'hello'";
        let utf16: Vec<u8> = payload.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let src = format!("powershell -EncodedCommand {encoded}");
        let results = extract_obfuscated_payloads(&src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "Write-Host 'hello'");
    }

    #[test]
    fn test_encoded_command_short_flag() {
        let payload = "whoami";
        let utf16: Vec<u8> = payload.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let src = format!("powershell.exe -enc {encoded}");
        let results = extract_obfuscated_payloads(&src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "whoami");
    }

    #[test]
    fn test_convert_from_base64_utf16() {
        let payload = "Get-Process";
        let utf16: Vec<u8> = payload.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let src = format!(r#"$bytes = [Convert]::FromBase64String("{encoded}")"#);
        let results = extract_obfuscated_payloads(&src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "Get-Process");
    }

    #[test]
    fn test_iex_encoding_b64() {
        // UTF-8 base64 (not UTF-16LE) with explicit Encoding::UTF8
        let payload = "Write-Host 'hello'";
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        let src = format!(
            r#"iex([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{encoded}")))"#
        );
        let results = extract_obfuscated_payloads(&src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "Write-Host 'hello'");
    }

    #[test]
    fn test_char_array() {
        // "hello" as char codes
        let src = r#"iex([char[]](104,101,108,108,111) -join '')"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "hello");
    }

    #[test]
    fn test_iex_replace() {
        let src = r#"iex("hXXps://evil.com/payload".replace("XX","tt"))"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "https://evil.com/payload");
    }

    #[test]
    fn test_iex_multiple_replace() {
        let src = r#"iex("hXXps://YYY.com/ZZZ".replace("XX","tt").replace("YYY","evil").replace("ZZZ","payload"))"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "https://evil.com/payload");
    }

    #[test]
    fn test_no_false_positive_on_normal_convert() {
        // [Convert]::FromBase64String not in iex context is still detected
        // (it's still suspicious in PowerShell)
        let src = r#"$data = [Convert]::FromBase64String("dGVzdA==")"#;
        let results = extract_obfuscated_payloads(src);
        // This should still decode since FromBase64String is suspicious in PS
        assert!(!results.is_empty());
    }
}
