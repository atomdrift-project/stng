use stng::{ExtractOptions, StringKind};

#[test]
fn test_stack_strings_poolrat() {
    let sample_path = "testdata/malware/poolrat";
    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping - malware sample not found at {}", sample_path);
        return;
    }

    let data = std::fs::read(sample_path).expect("Failed to read malware sample");

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

    // Verify User-Agent extraction (byte-by-byte stack construction)
    // "Mozilla/5.0 (Windows NT 6.1; Trident/6.0)"
    // It might be fragmented due to code layout gaps.

    let fragments = ["Mozill", "Trident", "Window", "MSIE"];
    let mut found_count = 0;

    for frag in fragments {
        if stack_strings.iter().any(|s| s.contains(frag)) {
            found_count += 1;
        }
    }

    assert!(
        found_count >= 2,
        "Should find at least 2 parts of the User-Agent string. Found: {}",
        found_count
    );

    // Verify C2 URL (movabs)
    assert!(
        stack_strings.iter().any(|s| s.contains("paxosfuture.com")),
        "Missing C2 URL"
    );
}
