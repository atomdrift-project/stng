use stng::{extract_strings_with_options, ExtractOptions, StringMethod};

/// Integration test against a real LD_PRELOAD Linux rootkit ELF.
///
/// The rootkit uses XOR 0xFE to encode sensitive strings in .rodata:
///   sym.x at VA 0x4064 decodes syscall names and path strings.
///
/// Known XOR 0xFE-encoded strings in .rodata (VA 0x4168-0x44b7):
///   - ld.so.preload   (offset 0x43b6) — LD_PRELOAD injection path
///   - /proc/net/tcp   (offset 0x441e) — network connection hiding
///   - /proc/net/tcp6  (offset 0x442c) — IPv6 connection hiding
#[test]
fn test_elf_rootkit_xor_detection() {
    let sample_path =
        "../../../data/bad/datasets/mbdl/rootkit/3b378846bc429fdf9bec08b9635885267d8d269f6d941ab1d6e526a03304331b.elf";

    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping - rootkit sample not found at {}", sample_path);
        return;
    }

    let data = std::fs::read(sample_path).expect("Failed to read rootkit sample");
    let opts = ExtractOptions::new(10).with_xor(None);
    let results = extract_strings_with_options(&data, &opts);

    let xor_results: Vec<&str> = results
        .iter()
        .filter(|r| r.method == StringMethod::XorDecode)
        .map(|r| r.value.as_str())
        .collect();

    assert!(
        xor_results.contains(&"ld.so.preload"),
        "Should detect XOR 0xFE-encoded 'ld.so.preload' (LD_PRELOAD rootkit injection). Found XOR strings: {:?}",
        xor_results
    );

    assert!(
        xor_results.contains(&"/proc/net/tcp"),
        "Should detect XOR 0xFE-encoded '/proc/net/tcp' (network connection hiding). Found XOR strings: {:?}",
        xor_results
    );

    assert!(
        xor_results.contains(&"/proc/net/tcp6"),
        "Should detect XOR 0xFE-encoded '/proc/net/tcp6' (IPv6 connection hiding). Found XOR strings: {:?}",
        xor_results
    );

    // Verify the method and key annotation
    let ld_so = results
        .iter()
        .find(|r| r.value == "ld.so.preload")
        .expect("ld.so.preload not found");
    assert_eq!(ld_so.method, StringMethod::XorDecode);
    assert!(
        ld_so
            .source
            .as_ref()
            .map(|s| s.contains("FE"))
            .unwrap_or(false),
        "ld.so.preload source should indicate 0xFE key, got: {:?}",
        ld_so.source
    );
}
