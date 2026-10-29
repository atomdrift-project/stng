use stng::{ExtractOptions, StringKind, StringMethod, extract_strings_with_options};

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

    let opts = ExtractOptions::new(8)
        .with_xor(stng::XorMode::Auto)
        .with_xor_min_length(10);
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

    let opts = ExtractOptions::new(8)
        .with_xor(stng::XorMode::Auto)
        .with_xor_min_length(8);
    let strings = extract_strings_with_options(&binary, &opts);

    let xor_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .filter(|s| s.kind == Some(StringKind::Ip) || s.kind == Some(StringKind::IpPort))
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

    let opts = ExtractOptions::new(8)
        .with_xor(stng::XorMode::Auto)
        .with_xor_min_length(10);
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
    // Test that Mozilla pattern detection works and extracts surrounding
    // context. The payload sits in a binary: text skips the XOR scanners.
    let plaintext = b"User-Agent: Mozilla/5.0 (Windows NT 10.0) Safari/537.36";
    let key: u8 = 0x42;
    let data = minimal_arm64_elf_with_xor(plaintext, key);

    let opts = ExtractOptions::new(10)
        .with_xor(stng::XorMode::Auto)
        .with_xor_min_length(10);
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

    let opts = ExtractOptions::new(8)
        .with_xor(stng::XorMode::Auto)
        .with_xor_min_length(10);
    let strings = extract_strings_with_options(&binary, &opts);

    let xor_strings: Vec<_> = strings
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .collect();

    assert!(
        !xor_strings.is_empty(),
        "Should decode strings with the 0x42 XOR key",
    );
}
