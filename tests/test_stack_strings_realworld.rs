use stng::{ExtractOptions, StringKind};

#[test]
fn test_stack_strings_themeforestrat() {
    let sample_path = "testdata/malware/themeforestrat";
    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping - malware sample not found at {}", sample_path);
        return;
    }

    let data = std::fs::read(sample_path).expect("Failed to read malware sample");

    // We expect stack strings to be merged:
    // "https://" + "paxosfut" + "ure.com/" -> "https://paxosfuture.com/"
    // "option/b" + "ook.php" -> "option/book.php"
    // And "cmd.exe"
    let opts = ExtractOptions::new(4);
    let extracted = stng::extract_strings_with_options(&data, &opts);

    let stack_strings: Vec<&str> = extracted
        .iter()
        .filter(|s| s.kind == StringKind::StackString)
        .map(|s| s.value.as_str())
        .collect();

    println!("Found {} stack strings", stack_strings.len());
    for s in &stack_strings {
        println!("  - {}", s);
    }

    // Check for the main C2 URL parts
    // Note: They might be merged into one big string or split into two depending on the exact gap.
    // The previous run output showed:
    // - https://paxosfuture.com/
    // - option/book.php

    let full_url_present = stack_strings
        .iter()
        .any(|s| s.contains("https://paxosfuture.com/"));
    assert!(full_url_present, "Missing 'https://paxosfuture.com/'");

    let uri_present = stack_strings.iter().any(|s| s.contains("option/book.php"));
    assert!(uri_present, "Missing 'option/book.php'");

    assert!(stack_strings.contains(&"cmd.exe"), "Missing 'cmd.exe'");
}
