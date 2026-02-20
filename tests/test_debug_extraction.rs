use stng::ExtractOptions;

#[test]
fn debug_what_gets_extracted() {
    let content = b"line1\nVGhpcyBpcyBhIGxvbmdlciB0ZXN0IHN0cmluZw==\nline3\n";

    let opts = ExtractOptions::new(4);
    let strings = stng::extract_strings_with_options(content, &opts);

    println!("\nExtracted {} total strings:", strings.len());
    for (i, s) in strings.iter().enumerate() {
        println!(
            "  [{}] method={:?}, kind={:?}, offset={}, value='{}'",
            i, s.method, s.kind, s.data_offset, s.value
        );
    }

    // This test always passes - it's just for debugging
}
