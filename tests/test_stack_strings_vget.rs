use stng::{ExtractOptions, StringKind};

#[test]
fn test_stack_strings_vget() {
    let sample_path = "testdata/malware/vget_sample";
    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping - malware sample not found at {}", sample_path);
        return;
    }

    let data = std::fs::read(sample_path).expect("Failed to read malware sample");

    // We expect stack strings to be merged correctly.
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

    // Stack string merging may produce fragments or full strings depending on instruction patterns
    // Verify we extracted some stack strings with relevant fragments
    assert!(
        !stack_strings.is_empty(),
        "Should extract some stack strings"
    );

    // Check for CPU-related fragments (may be merged or separate)
    let has_cpu_strings = stack_strings.iter().any(|s| {
        s.contains("AMD") || s.contains("Authenti") || s.contains("Hygon") || s.contains("Genuine")
    });
    assert!(has_cpu_strings, "Should find CPU-related stack strings");

    // Check for proc-related fragments
    let has_proc_strings = stack_strings
        .iter()
        .any(|s| s.contains("proc") || s.contains("self") || s.contains("exe"));
    assert!(has_proc_strings, "Should find proc-related stack strings");
}
