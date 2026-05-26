#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use stng::{ExtractOptions, StringMethod, extract_strings_with_options};

/// Integration test against rtc.dll — a PE binary that uses XOR 0xC6 to hide
/// dynamically-loaded DLL names and Windows API function names.
///
/// The malware encodes narrow ASCII bytes with XOR 0xC6, then zero-extends each decoded
/// byte to a UTF-16LE word for use with wide Windows APIs (LoadLibraryW, GetProcAddress).
///
/// Hidden strings confirmed via manual analysis:
///   DLLs loaded covertly: bcrypt.dll, user32.dll
///   AES-CBC crypto API:   BCryptOpenAlgorithmProvider, BCryptSetProperty,
///                         BCryptGenerateSymmetricKey, BCryptDecrypt,
///                         BCryptDestroyKey, BCryptCloseAlgorithmProvider
///   Process/window API:   CreateProcessW, ShowWindow, FindWindowExW,
///                         GetWindowThreadProcessId
#[test]
fn test_pe_xor_c6_dll_and_api_detection() {
    let sample_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/rtc.dll");

    let data = match std::fs::read(sample_path) {
        Ok(data) => data,
        Err(err) => panic!("Failed to read rtc.dll testdata: {err}"),
    };
    let opts = ExtractOptions::new(10).with_xor(None);
    let results = extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<&str> = results
        .iter()
        .filter(|r| r.method == StringMethod::XorDecode)
        .map(|r| r.value.as_str())
        .collect();

    // DLL names loaded via LoadLibraryW - indicate covert capability loading
    assert!(
        xor_strings.iter().any(|s| s.contains("bcrypt.dll")),
        "Should detect XOR 0xC6-encoded 'bcrypt.dll' (AES capability). Found XOR strings: {:?}",
        xor_strings
    );
    assert!(
        xor_strings.iter().any(|s| s.contains("user32.dll")),
        "Should detect XOR 0xC6-encoded 'user32.dll' (UI control). Found XOR strings: {:?}",
        xor_strings
    );

    // BCrypt API names resolved via GetProcAddress - full AES-CBC decryption capability
    assert!(
        xor_strings
            .iter()
            .any(|s| s.contains("BCryptOpenAlgorithmProvider")),
        "Should detect XOR 0xC6-encoded 'BCryptOpenAlgorithmProvider'. Found: {:?}",
        xor_strings
    );
    assert!(
        xor_strings
            .iter()
            .any(|s| s.contains("BCryptGenerateSymmetricKey")),
        "Should detect XOR 0xC6-encoded 'BCryptGenerateSymmetricKey'. Found: {:?}",
        xor_strings
    );
    assert!(
        xor_strings.iter().any(|s| s.contains("BCryptDecrypt")),
        "Should detect XOR 0xC6-encoded 'BCryptDecrypt'. Found: {:?}",
        xor_strings
    );

    // Process/window control APIs - indicate process injection or window manipulation
    assert!(
        xor_strings.iter().any(|s| s.contains("CreateProcessW")),
        "Should detect XOR 0xC6-encoded 'CreateProcessW'. Found: {:?}",
        xor_strings
    );
    assert!(
        xor_strings.iter().any(|s| s.contains("ShowWindow")),
        "Should detect XOR 0xC6-encoded 'ShowWindow'. Found: {:?}",
        xor_strings
    );
    assert!(
        xor_strings.iter().any(|s| s.contains("FindWindowExW")),
        "Should detect XOR 0xC6-encoded 'FindWindowExW'. Found: {:?}",
        xor_strings
    );

    // Verify the key annotation (must be flagged as 0xC6)
    let Some(bcrypt_dll) = results
        .iter()
        .find(|r| r.value.contains("bcrypt.dll") && r.method == StringMethod::XorDecode)
    else {
        panic!("bcrypt.dll XOR string not found");
    };
    assert!(
        bcrypt_dll
            .source
            .as_ref()
            .map(|s| s.contains("C6"))
            .unwrap_or(false),
        "bcrypt.dll source should indicate 0xC6 key, got: {:?}",
        bcrypt_dll.source
    );
}
