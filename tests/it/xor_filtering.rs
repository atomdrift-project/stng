/// Tests for XOR string filtering logic
///
/// These tests ensure that legitimate XOR-decoded malware strings
/// are NOT filtered out as garbage.
// We'll test this indirectly through the public API
use stng::{ExtractOptions, StringMethod};

/// Helper function to create XOR'd test data and verify extraction
fn test_xor_extraction(test_strings: &[&str], test_name: &str) {
    let key = b"TESTKEY123";

    // Create XOR'd data
    let mut data = Vec::new();
    for s in test_strings {
        for (i, &b) in s.as_bytes().iter().enumerate() {
            data.push(b ^ key[i % key.len()]);
        }
        // Add garbage separator
        data.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
    }

    // Extract with filtering enabled
    let opts = ExtractOptions::new(4)
        .with_xor_min_length(4) // Set XOR min_length to 4 (default is 10)
        .with_xor(stng::XorMode::Key(key.to_vec()))
        .with_garbage_filter(true); // Important: testing WITH filtering

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<&str> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value.as_str())
        .collect();

    for expected in test_strings {
        assert!(
            xor_strings.iter().any(|s| s.contains(expected)),
            "{test_name}: {expected:?} not recovered; XOR strings: {xor_strings:?}"
        );
    }
}

#[test]

fn test_applescript_strings_not_filtered() {
    // AppleScript commands from real malware
    let applescript_strings = vec![
        "set end of aflst to item i of fl",
        "set end of aflst to linefeed",
        "end repeat",
        "set sub_folders_list to folders of tf",
        "tf to POSIX file \"%s\" as alias",
        "set aflst to {}",
        "tell application \"Finder\"",
        "set fl to (every file of tf)",
        "repeat with i from 1 to (count fl)",
    ];

    test_xor_extraction(&applescript_strings, "AppleScript");
}

#[test]

fn test_xml_plist_strings_not_filtered() {
    let xml_strings = vec![
        ">ProgramArguments</key>",
        "<array>",
        "<string>%s</string>",
        "</array>",
        "<key>StartInterval</key>",
        "<integer>60</integer>",
        "</dict>",
        "</plist>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<plist version=\"1.0\">",
        "<dict>",
        "<key>Label</key>",
    ];

    test_xor_extraction(&xml_strings, "XML/plist");
}

#[test]
fn test_shell_commands_not_filtered() {
    let shell_strings = vec![
        "xattr -d com.apple.quarantine \"%s\" 2>&1",
        "osascript 2>&1 <<EOD",
    ];

    test_xor_extraction(&shell_strings, "Shell commands");
}

#[test]
fn test_file_paths_not_filtered() {
    let path_strings = vec![
        "%s/Library/LaunchAgents/%s",
        "Wallets/atomic/Local Storage",
        "Ledger Live/app.json",
        "%s/.walletwasabi/client/Wallets",
        "%s/Library/Ethereum/keystore",
    ];

    test_xor_extraction(&path_strings, "File paths");
}

#[test]
fn test_wallet_and_crypto_not_filtered() {
    let crypto = vec![
        "Ethereum", "keystore", "Wallet", "wallets", "tdata", "Ledger", "atomic",
    ];

    test_xor_extraction(&crypto, "Crypto/Wallet");
}
