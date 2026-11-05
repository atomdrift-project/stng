//! PowerShell script deobfuscation patterns.
//!
//! Detects and decodes common PowerShell obfuscation techniques:
//! - `-EncodedCommand` / `-enc` (UTF-16LE base64)
//! - `[Convert]::FromBase64String` with `iex`/`Invoke-Expression`
//! - `iex` with char array (`[char[]](72,101,...) -join ''`)
//! - `iex` with reversed strings
//! - `iex` with string `.replace()` deobfuscation
//! - GzipStream compressed payloads

use crate::script::detect::ScriptLanguage;
use regex::Regex;
use std::sync::LazyLock;

use super::DeobfuscationResult;
use super::decode_chain::DecodeStep;

/// `-EncodedCommand` followed by base64. powershell.exe takes any
/// unambiguous prefix (`-e`, `-en`, …, `-encodedcomman`) and the `-ec`
/// alias; the flag is captured so [`is_encoded_command_flag`] can check it.
static ENCODED_CMD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)-(e[a-z]{0,13})\s+['"]?([A-Za-z0-9+/=]{8,})['"]?"#)
        .unwrap_or_else(crate::invalid_pattern)
});

// The one-letter `-e` option is also common in other programs (for example,
// `grep -E`), so it needs a PowerShell executable on the same command line.
static POWERSHELL_EXEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:^|[^a-z0-9_])(?:powershell|pwsh)(?:\.exe)?(?:[\s"']|$)"#)
        .unwrap_or_else(crate::invalid_pattern)
});

/// `[Convert]::FromBase64String("...")` or `[System.Convert]::FromBase64String("...")`
static CONVERT_B64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)"#,
    )
    .unwrap_or_else(crate::invalid_pattern)
});

/// [char[]](72,101,108,...) -join '' or [char[]](72,101,108,...) -join ""
static CHAR_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\[char\[\]\]\s*\(\s*([0-9,\s]+)\s*\)\s*-join\s*['"]['"]*"#)
        .unwrap_or_else(crate::invalid_pattern)
});

/// iex with reversed string: iex(-join('string'[-1..-N])) or similar
static IEX_REVERSE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:iex|invoke-expression)\s*\(\s*(?:-join\s*\(\s*)?['"]([^'"]+)['"]\s*\[\s*-1\s*\.\.\s*-\d+"#)
        .unwrap_or_else(crate::invalid_pattern)
});

/// Simple string replace: "string".replace("X","Y") in context of iex
static IEX_REPLACE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:iex|invoke-expression)\s*\(\s*['"]([^'"]+)['"]((?:\s*\.replace\s*\(\s*['"][^'"]*['"]\s*,\s*['"][^'"]*['"]\s*\))+)"#)
        .unwrap_or_else(crate::invalid_pattern)
});

/// Individual .replace("X","Y") pairs
static REPLACE_PAIR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\.replace\s*\(\s*['"]([^'"]*)['"]\s*,\s*['"]([^'"]*)['"]\s*\)"#)
        .unwrap_or_else(crate::invalid_pattern)
});

/// Base64 string used with iex/Invoke-Expression and
/// [System.Text.Encoding]::UTF8.GetString or Unicode.GetString
static IEX_ENCODING_B64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:iex|invoke-expression)\s*\(\s*\[System\.Text\.Encoding\]::\w+\.GetString\s*\(\s*\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)"#)
        .unwrap_or_else(crate::invalid_pattern)
});

/// Extract all obfuscated payloads from a PowerShell script.
pub(super) fn extract_obfuscated_payloads(source: &str) -> Vec<DeobfuscationResult> {
    let mut results = Vec::new();

    results.extend(try_encoded_command(source));

    // iex_encoding_b64 is a superset of convert_b64, so track covered offsets
    let iex_results = super::decode_captures(
        source,
        &[&IEX_ENCODING_B64_RE],
        &[DecodeStep::Base64],
        ScriptLanguage::PowerShell,
    );
    let covered_offsets: std::collections::BTreeSet<usize> =
        iex_results.iter().map(|r| r.offset).collect();
    results.extend(iex_results);

    // Only add convert_b64 results that don't overlap with iex_encoding_b64:
    // none starting in the 200 bytes before. A range query, since a scan of
    // every covered offset per result was quadratic in the repetitions.
    results.extend(try_convert_b64(source).into_iter().filter(|r| {
        covered_offsets
            .range(r.offset.saturating_sub(199)..=r.offset)
            .next()
            .is_none()
    }));

    results.extend(try_char_array(source));
    results.extend(super::decode_captures(
        source,
        &[&IEX_REVERSE_RE],
        &[DecodeStep::Reverse],
        ScriptLanguage::PowerShell,
    ));
    results.extend(try_iex_replace(source));

    results
}

/// -EncodedCommand base64 (UTF-16LE encoded)
fn try_encoded_command(source: &str) -> Vec<DeobfuscationResult> {
    let bytes = source.as_bytes();
    // Matches arrive in offset order, so the current line and where its first
    // PowerShell executable ends are found once per line, not once per match.
    let mut scanned = 0;
    let mut line_start = 0;
    let mut exec_end: Option<Option<usize>> = None;
    ENCODED_CMD_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let matched = cap.get(0)?;
            let offset = matched.start();
            let flag = cap.get(1)?.as_str().to_ascii_lowercase();
            if !is_encoded_command_flag(&flag) {
                return None;
            }
            // The one-letter form is common in other programs (`grep -e`),
            // so it needs a PowerShell executable on the same line.
            if flag == "e" {
                if let Some(nl) = memchr::memrchr(b'\n', &bytes[scanned..offset]) {
                    line_start = scanned + nl + 1;
                    exec_end = None;
                }
                scanned = offset;
                let end = *exec_end.get_or_insert_with(|| {
                    let line_end = memchr::memchr(b'\n', &bytes[line_start..])
                        .map_or(source.len(), |nl| line_start + nl);
                    POWERSHELL_EXEC_RE
                        .find(&source[line_start..line_end])
                        .map(|m| line_start + m.end())
                });
                if end.is_none_or(|end| end > offset) {
                    return None;
                }
            }
            let blob = cap.get(2)?.as_str().replace(char::is_whitespace, "");
            let steps = vec![DecodeStep::Base64, DecodeStep::Utf16Le];
            let result = super::decode_chain::apply_chain(blob.as_bytes(), &steps)?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("powershell:{}", result.chain_description),
                language: ScriptLanguage::PowerShell,
            })
        })
        .collect()
}

/// Whether `flag` (lowercase, without its `-`) names `-EncodedCommand`.
fn is_encoded_command_flag(flag: &str) -> bool {
    flag == "ec" || "encodedcommand".starts_with(flag)
}

/// `[Convert]::FromBase64String` (standalone, not wrapped in iex+Encoding)
fn try_convert_b64(source: &str) -> Vec<DeobfuscationResult> {
    CONVERT_B64_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let blob = cap.get(1)?.as_str().replace(char::is_whitespace, "");
            let offset = cap.get(0)?.start();
            // The bytes have no declared encoding. UTF-16LE is PowerShell's
            // own, but only bytes that look wide are read that way:
            // "dGVzdA==" is "test", not two CJK characters.
            let utf8 = super::decode_chain::apply_chain(blob.as_bytes(), &[DecodeStep::Base64]);
            let wide = utf8
                .as_ref()
                .is_none_or(|r| crate::decoders::looks_like_utf16le(r.payload.as_bytes()));
            let utf16 = || {
                super::decode_chain::apply_chain(
                    blob.as_bytes(),
                    &[DecodeStep::Base64, DecodeStep::Utf16Le],
                )
            };
            let result = if wide { utf16().or(utf8) } else { utf8 }?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("powershell:{}", result.chain_description),
                language: ScriptLanguage::PowerShell,
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
            let payload = super::char_codes(nums_str, false);
            if payload.is_empty() {
                return None;
            }
            Some(DeobfuscationResult {
                decoded: payload,
                offset,
                chain_description: "powershell:charcodes".to_string(),
                language: ScriptLanguage::PowerShell,
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

            // Apply all .replace() calls in order. .NET rejects an empty
            // search string, and each replace can multiply the length, so
            // bound the result rather than trust the chain.
            let mut result = base_str;
            for rcap in REPLACE_PAIR_RE.captures_iter(replace_chain) {
                let from = rcap.get(1)?.as_str();
                let to = rcap.get(2)?.as_str();
                if from.is_empty() {
                    return None;
                }
                // Size the result before building it: checked afterwards,
                // three short replaces had already allocated gigabytes.
                let hits = result.matches(from).count();
                let len = (result.len() - hits * from.len())
                    .saturating_add(hits.saturating_mul(to.len()));
                if len > super::decode_chain::MAX_DECODED_SIZE
                    || !super::decode_chain::spend_expansion(len)
                {
                    return None;
                }
                result = result.replace(from, to);
            }

            if result.is_empty() {
                return None;
            }

            Some(DeobfuscationResult {
                decoded: result,
                offset,
                chain_description: "powershell:replace".to_string(),
                language: ScriptLanguage::PowerShell,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &str =
        "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABwAHcAbgBlAGQALQBiAHkALQB0AGUAcwB0AA==";

    #[test]
    fn every_encoded_command_spelling_is_decoded() {
        for flag in [
            "-e",
            "-ec",
            "-en",
            "-enco",
            "-EncodedCommand",
            "-encodedcomman",
        ] {
            let src = format!("powershell.exe -nop {flag} {PAYLOAD}");
            let found = try_encoded_command(&src);
            assert!(
                found.iter().any(|r| r.decoded.contains("pwned-by-test")),
                "{flag}: {found:?}"
            );
        }
    }

    #[test]
    fn other_e_flags_are_not_encoded_commands() {
        for flag in ["-ep", "-execute", "-ex"] {
            let src = format!("powershell.exe {flag} {PAYLOAD}");
            assert!(try_encoded_command(&src).is_empty(), "{flag}");
        }
    }
    use base64::Engine;

    #[test]
    fn replace_chain_with_empty_search_is_rejected() {
        // `"".replace` would insert between every character, 10x per call.
        let chain = ".replace('','xxxxxxxxx')".repeat(12);
        let src = format!("iex('aaaa'{chain})");
        assert!(try_iex_replace(&src).is_empty());
        let ok = try_iex_replace("iex('hXXps://evil.example'.replace('XX','tt'))");
        assert_eq!(ok[0].decoded, "https://evil.example");
    }

    #[test]
    fn decodes_encoded_command() {
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
    fn decodes_enc_short_flag() {
        let payload = "whoami";
        let utf16: Vec<u8> = payload.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let src = format!("powershell.exe -enc {encoded}");
        let results = extract_obfuscated_payloads(&src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "whoami");
    }

    #[test]
    fn short_e_requires_powershell_command_context() {
        let utf16: Vec<u8> = "Write-Host hello"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
        assert!(try_encoded_command(&format!("grep -E '{encoded}'")).is_empty());
        assert!(
            try_encoded_command(&format!("powershell -Command noop\ngrep -E '{encoded}'"))
                .is_empty()
        );
        for command in ["powershell.exe", "pwsh"] {
            let result = try_encoded_command(&format!("{command} -e {encoded}"));
            assert_eq!(result.len(), 1);
            assert_eq!(result[0].decoded, "Write-Host hello");
        }
        assert!(try_encoded_command("grep -E '/var/backups/shadow\\.bak$'").is_empty());
    }

    #[test]
    fn decodes_utf16_from_base64_string() {
        let payload = "Get-Process";
        let utf16: Vec<u8> = payload.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let src = format!(r#"$bytes = [Convert]::FromBase64String("{encoded}")"#);
        let results = extract_obfuscated_payloads(&src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "Get-Process");
    }

    #[test]
    fn decodes_iex_utf8_get_string() {
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
    fn decodes_iex_char_array() {
        // "hello" as char codes
        let src = r"iex([char[]](104,101,108,108,111) -join '')";
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "hello");
    }

    #[test]
    fn decodes_iex_replace() {
        let src = r#"iex("hXXps://evil.com/payload".replace("XX","tt"))"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "https://evil.com/payload");
    }

    #[test]
    fn decodes_chained_replaces() {
        let src = r#"iex("hXXps://YYY.com/ZZZ".replace("XX","tt").replace("YYY","evil").replace("ZZZ","payload"))"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "https://evil.com/payload");
    }

    #[test]
    fn decodes_bare_from_base64_string() {
        // [Convert]::FromBase64String not in iex context is still detected
        // (it's still suspicious in PowerShell)
        let src = r#"$data = [Convert]::FromBase64String("dGVzdA==")"#;
        let results = extract_obfuscated_payloads(src);
        // This should still decode since FromBase64String is suspicious in PS
        assert_eq!(results.len(), 1, "{results:?}");
        assert_eq!(results[0].offset, src.find("[Convert]").unwrap());
        assert_eq!(results[0].language, ScriptLanguage::PowerShell);
        assert_eq!(results[0].chain_description, "powershell:base64");
        assert_eq!(results[0].decoded, "test");
    }

    #[test]
    fn decodes_wide_from_base64_string_as_utf16() {
        // "calc" in UTF-16LE.
        let src = r#"$data = [Convert]::FromBase64String("YwBhAGwAYwA=")"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1, "{results:?}");
        assert_eq!(results[0].decoded, "calc");
        assert_eq!(results[0].chain_description, "powershell:base64+utf16le");
    }
}
