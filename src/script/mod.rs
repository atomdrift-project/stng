//! Script deobfuscation module.
//!
//! Detects and decodes obfuscated payloads in Python, JavaScript, PHP, and PowerShell scripts.
//! This module targets common malware obfuscation patterns found in PyPI/npm packages,
//! PHP webshells, and PowerShell droppers.

pub mod decode_chain;
pub mod detect;
mod javascript;
mod php;
mod powershell;
mod python;

use detect::ScriptLanguage;

/// Result of successfully deobfuscating a script payload.
#[derive(Debug, Clone)]
pub struct DeobfuscationResult {
    /// The decoded payload text
    pub decoded: String,
    /// Byte offset in the source where the obfuscated blob was found
    pub offset: usize,
    /// Human-readable description of the decode chain, e.g. "python:base64+zlib+xor(0x86)"
    pub chain_description: String,
    /// Source language
    pub language: &'static str,
}

/// Attempt to deobfuscate a script file.
///
/// Detects the scripting language, then runs language-specific pattern matchers
/// to find and decode obfuscated payloads. Returns decoded payloads (if any)
/// along with the detected language.
///
/// For nested obfuscation (decoded payload is itself obfuscated), re-runs
/// detection up to `MAX_DECODE_DEPTH` times.
pub fn deobfuscate_script(data: &[u8]) -> Vec<DeobfuscationResult> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Vec::new();
    };

    let mut all_results = Vec::new();
    let mut current_text = text.to_string();

    for depth in 0..decode_chain::MAX_DECODE_DEPTH {
        let Some(language) = detect::detect_script_language(current_text.as_bytes()) else {
            // If first iteration found no language, try all extractors
            // (the file might be a script without strong language markers)
            if depth == 0 {
                let mut results = Vec::new();
                results.extend(python::extract_obfuscated_payloads(&current_text));
                results.extend(javascript::extract_obfuscated_payloads(&current_text));
                results.extend(php::extract_obfuscated_payloads(&current_text));
                results.extend(powershell::extract_obfuscated_payloads(&current_text));
                all_results.extend(results);
            }
            break;
        };

        let results = match language {
            ScriptLanguage::Python => python::extract_obfuscated_payloads(&current_text),
            ScriptLanguage::JavaScript => javascript::extract_obfuscated_payloads(&current_text),
            ScriptLanguage::Php => php::extract_obfuscated_payloads(&current_text),
            ScriptLanguage::PowerShell => powershell::extract_obfuscated_payloads(&current_text),
        };

        if results.is_empty() {
            break;
        }

        // Check if the largest decoded payload is itself obfuscated
        let largest = results
            .iter()
            .max_by_key(|r| r.decoded.len())
            .map(|r| r.decoded.clone());

        all_results.extend(results);

        // Try to recurse into the largest decoded payload
        if let Some(payload) = largest {
            if payload.len() > 20 {
                current_text = payload;
                continue;
            }
        }
        break;
    }

    all_results
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn test_deobfuscate_python_b64() {
        let src = br#"import base64
exec(base64.b64decode("aW1wb3J0IG9z"))
"#;
        let results = deobfuscate_script(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "import os");
        assert_eq!(results[0].language, "python");
    }

    #[test]
    fn test_deobfuscate_javascript_eval_atob() {
        let src = br#"const x = 1;
eval(atob("YWxlcnQoMSk="))
"#;
        let results = deobfuscate_script(src);
        assert!(!results.is_empty());
        assert_eq!(results[0].decoded, "alert(1)");
    }

    #[test]
    fn test_deobfuscate_php_eval_b64() {
        let src = br#"<?php eval(base64_decode("ZWNobyAnaGVsbG8nOw==")); ?>"#;
        let results = deobfuscate_script(src);
        assert!(!results.is_empty());
        assert_eq!(results[0].decoded, "echo 'hello';");
    }

    #[test]
    fn test_deobfuscate_powershell_enc() {
        // "whoami" as UTF-16LE base64
        let payload = "whoami";
        let utf16: Vec<u8> = payload.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let src = format!("powershell -EncodedCommand {encoded}");
        let results = deobfuscate_script(src.as_bytes());
        assert!(!results.is_empty());
        assert_eq!(results[0].decoded, "whoami");
    }

    #[test]
    fn test_deobfuscate_no_obfuscation() {
        let src = b"print('hello world')\n";
        let results = deobfuscate_script(src);
        assert!(results.is_empty());
    }

    #[test]
    fn test_deobfuscate_binary_data() {
        let data = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        let results = deobfuscate_script(&data);
        assert!(results.is_empty());
    }
}
