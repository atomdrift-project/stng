/// Tests for validation::is_garbage() special cases
/// These ensure that important malware indicators aren't filtered out
use stng::ExtractOptions;

#[test]
fn test_shell_commands_with_redirections() {
    // Shell commands with redirections should NOT be filtered
    // Note: We check for the most distinctive part of each command that's
    // likely to be preserved during XOR scanning at various positions
    let test_cases = vec![
        ("osascript 2>&1 <<EOD", "osascript"),
        ("osascript 2>/dev/null <<EOD", "osascript"),
        ("bash -c command 2>&1", "2>&1"), // "bash" alone may be split by XOR scanning
        ("/bin/sh -c script", " -c "),    // -c flag is distinctive for shell commands
        ("command <<EOF", "<<E"),         // check for heredoc marker
    ];

    for (cmd, expected_substring) in &test_cases {
        // Extract with XOR to trigger filtering
        let key = b"KEY";
        let mut xored = Vec::new();
        for (i, &b) in cmd.as_bytes().iter().enumerate() {
            xored.push(b ^ key[i % key.len()]);
        }

        let opts = ExtractOptions::new(4)
            .with_xor(Some(4))
            .with_xor_key(key.to_vec())
            .with_garbage_filter(true);

        let extracted = stng::extract_strings_with_options(&xored, &opts);
        let found = extracted
            .iter()
            .any(|s| s.value.contains(expected_substring));

        if !found {
            println!(
                "Failed to find '{}' in command '{}'",
                expected_substring, cmd
            );
            println!(
                "Extracted strings: {:?}",
                extracted.iter().map(|s| &s.value).collect::<Vec<_>>()
            );
        }

        assert!(
            found,
            "Shell command '{}' should NOT be filtered out (looking for '{}')",
            cmd, expected_substring
        );
    }
}

#[test]
fn test_shell_commands_with_garbage_prefix() {
    // Shell commands with garbage bytes before them (like from XOR misalignment)
    // should still be recognized
    let key = b"XOR";

    let test_cases = vec![
        // Simulating garbage + osascript
        "\x03=fosascript 2>&1 <<EOD", // control char + garbage + command
        "Wfosascript 2>/dev/null <<EOD", // garbage letter + command
        "#+J8VSgafosascript 2>&1 <<EOD", // multiple garbage chars + command
    ];

    for cmd in &test_cases {
        let mut xored = Vec::new();
        for (i, &b) in cmd.as_bytes().iter().enumerate() {
            xored.push(b ^ key[i % key.len()]);
        }

        let opts = ExtractOptions::new(4)
            .with_xor(Some(4))
            .with_xor_key(key.to_vec())
            .with_garbage_filter(true);

        let extracted = stng::extract_strings_with_options(&xored, &opts);
        let found = extracted.iter().any(|s| s.value.contains("osascript"));

        assert!(
            found,
            "Command with garbage prefix '{}' should NOT be filtered (should find 'osascript')",
            cmd.escape_debug()
        );
    }
}

#[test]
fn test_locale_strings_pass_filter() {
    let key = b"KEY";
    let locales = vec!["en_US", "zh_CN", "ja_JP", "ru_RU", "fr_FR"];

    for locale in &locales {
        let mut xored = Vec::new();
        for (i, &b) in locale.as_bytes().iter().enumerate() {
            xored.push(b ^ key[i % key.len()]);
        }

        let opts = ExtractOptions::new(4)
            .with_xor(Some(4))
            .with_xor_key(key.to_vec())
            .with_garbage_filter(true);

        let extracted = stng::extract_strings_with_options(&xored, &opts);
        let found = extracted.iter().any(|s| s.value.contains(locale));

        assert!(found, "Locale '{}' should NOT be filtered out", locale);
    }
}

#[test]
fn test_xml_tags_pass_filter() {
    let key = b"KEY";
    let tags = vec!["<array>", "<dict>", "<key>", "<string>", "</plist>"];

    for tag in &tags {
        let mut xored = Vec::new();
        for (i, &b) in tag.as_bytes().iter().enumerate() {
            xored.push(b ^ key[i % key.len()]);
        }

        let opts = ExtractOptions::new(4)
            .with_xor(Some(4))
            .with_xor_key(key.to_vec())
            .with_garbage_filter(true);

        let extracted = stng::extract_strings_with_options(&xored, &opts);
        let found = extracted.iter().any(|s| s.value.contains(tag));

        assert!(found, "XML tag '{}' should NOT be filtered out", tag);
    }
}

#[test]
fn test_heredoc_patterns() {
    let key = b"KEY";
    let heredocs = vec!["<<EOD", "<<EOF", "command <<END\ncontent\nEND"];

    for heredoc in &heredocs {
        let mut xored = Vec::new();
        for (i, &b) in heredoc.as_bytes().iter().enumerate() {
            xored.push(b ^ key[i % key.len()]);
        }

        let opts = ExtractOptions::new(4)
            .with_xor(Some(4))
            .with_xor_key(key.to_vec())
            .with_garbage_filter(true);

        let extracted = stng::extract_strings_with_options(&xored, &opts);
        let found = extracted.iter().any(|s| s.value.contains("<<E"));

        assert!(
            found,
            "Heredoc pattern '{}' should NOT be filtered out",
            heredoc.escape_debug()
        );
    }
}

#[test]
fn test_stderr_redirection_patterns() {
    let key = b"KEY";
    let redirections = vec!["2>&1", "2>/dev/null", "command 2>&1", "script 2>/dev/null"];

    for redir in &redirections {
        let mut xored = Vec::new();
        for (i, &b) in redir.as_bytes().iter().enumerate() {
            xored.push(b ^ key[i % key.len()]);
        }

        let opts = ExtractOptions::new(4)
            .with_xor(Some(4))
            .with_xor_key(key.to_vec())
            .with_garbage_filter(true);

        let extracted = stng::extract_strings_with_options(&xored, &opts);
        let found = extracted.iter().any(|s| s.value.contains("2>"));

        assert!(
            found,
            "Redirection pattern '{}' should NOT be filtered out",
            redir
        );
    }
}
use stng::is_garbage;

#[test]
fn test_c2_url_not_garbage() {
    // The actual C2 URL from brew_agent malware
    let c2_url = "http://46.30.191.141n;uJ";

    println!("\nTesting: {:?}", c2_url);
    let result = is_garbage(c2_url);
    println!("is_garbage() returned: {}", result);

    assert!(!result, "C2 URL should NOT be marked as garbage");
}

#[test]
fn test_competing_garbage_string() {
    // The garbage string at offset -1 from C2
    let garbage = "fWWz^/21MU6.Tw";

    println!("\nTesting: {:?}", garbage);
    let result = is_garbage(garbage);
    println!("is_garbage() returned: {}", result);

    // This one might be garbage
    println!(
        "Garbage string result: {}",
        if result { "GARBAGE" } else { "NOT GARBAGE" }
    );
}
