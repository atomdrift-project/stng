use super::*;

/// Lay down a realistic 16-byte `sockaddr_in` at `off`: the AF_INET marker,
/// a big-endian port, the big-endian IPv4 address, and a zeroed 8-byte
/// `sin_zero` tail — the layout `scan_sockaddr_in` now requires. `le_marker`
/// selects the marker byte order (`02 00` little-endian vs `00 02` big-endian).
fn put_sockaddr_in(data: &mut [u8], off: usize, le_marker: bool, port: u16, ip: [u8; 4]) {
    let marker = if le_marker {
        [0x02, 0x00]
    } else {
        [0x00, 0x02]
    };
    data[off..off + 2].copy_from_slice(&marker);
    data[off + 2..off + 4].copy_from_slice(&port.to_be_bytes());
    data[off + 4..off + 8].copy_from_slice(&ip);
    data[off + 8..off + 16].fill(0); // sin_zero
}

#[test]
fn test_sockaddr_in_little_endian() {
    // sockaddr_in with AF_INET (0x0002) in little-endian
    let mut data = vec![0xAA; 300]; // Larger buffer to bypass 256-byte skip
    put_sockaddr_in(&mut data, 270, true, 8080, [192, 168, 1, 50]);

    let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);

    // Should find our target
    let found = results.iter().find(|s| s.value == "192.168.1.50:8080");
    assert!(
        found.is_some(),
        "Should find 192.168.1.50:8080 in sockaddr_in"
    );
    assert_eq!(found.unwrap().data_offset, 270);
    assert_eq!(found.unwrap().kind, Some(StringKind::IpPort));
}

#[test]
fn test_sockaddr_in_big_endian() {
    // sockaddr_in with AF_INET (0x0200) in big-endian
    let mut data = vec![0xAA; 300]; // Larger buffer to bypass 256-byte skip
    put_sockaddr_in(&mut data, 270, false, 8080, [192, 168, 1, 50]);

    let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);

    let found = results.iter().find(|s| s.value == "192.168.1.50:8080");
    assert!(
        found.is_some(),
        "Should find 192.168.1.50:8080 with AF_INET BE"
    );
}

#[test]
fn test_sockaddr_in_min_length_filter() {
    // sockaddr_in but with min_length that's too high
    let mut data = vec![0xAA; 300]; // Larger buffer to bypass 256-byte skip
    put_sockaddr_in(&mut data, 270, true, 80, [198, 51, 100, 80]);

    // Request results with min_length = 100
    let results = scan_sockaddr_in(&data, 100, Endianness::Unknown);

    // Should not find it (198.51.100.80:80 is only 16 chars)
    assert!(results.is_empty(), "Should filter by min_length");
}

#[test]
fn test_sockaddr_in_no_false_positives_from_text() {
    // Data that looks like sockaddr_in but has text-like octets in the IP
    let mut data = vec![0xAA; 300]; // Larger buffer to bypass 256-byte skip
    // IP with 3+ ASCII chars (E=0x45, L=0x4C, F=0x46)
    put_sockaddr_in(&mut data, 270, true, 8080, [0x7F, 0x45, 0x4C, 0x46]);

    let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);

    // Should filter out because IP looks like "ELF" text
    assert!(
        results.is_empty(),
        "Should filter sockaddr_in with text-like IP"
    );
}

#[test]
fn test_multiple_sockaddr_in_structures() {
    let mut data = vec![0xAA; 100];

    // First sockaddr_in at offset 5
    put_sockaddr_in(&mut data, 5, true, 8080, [172, 16, 20, 50]);

    // Second sockaddr_in at offset 50 (well-separated to avoid overlaps)
    // IP 10.20.30.40 avoids accidental AF_INET patterns.
    put_sockaddr_in(&mut data, 50, false, 80, [10, 20, 30, 40]);

    let elf_arm = 40; // EM_ARM from ELF header
    let results = scan_binary_ips(&data, 4, elf_arm, None, None);

    // Should find at least the two main structures (deduplication may occur)
    assert!(results.len() >= 2);
    let ips: std::collections::HashSet<&str> = results.iter().map(|s| s.value.as_str()).collect();
    assert!(ips.contains("172.16.20.50:8080"));
    assert!(ips.contains("10.20.30.40:80"));
}

#[test]
fn test_sockaddr_in_rejects_invalid_ips() {
    // Test that invalid IPs are filtered out
    let mut data = vec![0xAA; 400];

    // Invalid: 5.20.30.65 (first octet 5 is too low, artifact pattern)
    data[270] = 0x02;
    data[271] = 0x00;
    data[272..274].copy_from_slice(&[0x1F, 0x90]); // Port 8080
    data[274..278].copy_from_slice(&[0x05, 0x14, 0x1E, 0x41]); // 5.20.30.65

    // Invalid: 103.214.143.0 (last octet is 0)
    data[280] = 0x02;
    data[281] = 0x00;
    data[282..284].copy_from_slice(&[0x1F, 0x91]); // Port 8081
    data[284..288].copy_from_slice(&[0x67, 0xD6, 0x8F, 0x00]); // 103.214.143.0

    // Invalid: 234.0.1.112 (multicast range >= 224 and has zero octet)
    data[290] = 0x02;
    data[291] = 0x00;
    data[292..294].copy_from_slice(&[0x1F, 0x92]); // Port 8082
    data[294..298].copy_from_slice(&[0xEA, 0x00, 0x01, 0x70]); // 234.0.1.112

    // Invalid: 51.0.100.80 (has zero octet in middle)
    data[300] = 0x02;
    data[301] = 0x00;
    data[302..304].copy_from_slice(&[0x1F, 0x93]); // Port 8083
    data[304..308].copy_from_slice(&[0x33, 0x00, 0x64, 0x50]); // 51.0.100.80

    // Invalid: 123.45.0.67 (has zero octet)
    data[310] = 0x02;
    data[311] = 0x00;
    data[312..314].copy_from_slice(&[0x1F, 0x94]); // Port 8084
    data[314..318].copy_from_slice(&[0x7B, 0x2D, 0x00, 0x43]); // 123.45.0.67

    // Valid: 103.214.143.214 (realistic struct with zeroed sin_zero)
    put_sockaddr_in(&mut data, 320, true, 8085, [103, 214, 143, 214]);

    let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);

    let ips: std::collections::HashSet<&str> = results.iter().map(|s| s.value.as_str()).collect();

    // Should NOT find the invalid IPs
    assert!(
        !ips.iter().any(|ip| ip.contains("5.20.30.65")),
        "Should reject 5.20.30.65 (low first octet)"
    );
    assert!(
        !ips.iter().any(|ip| ip.contains("103.214.143.0")),
        "Should reject 103.214.143.0 (zero octet)"
    );
    assert!(
        !ips.iter().any(|ip| ip.contains("234.0.1.112")),
        "Should reject 234.0.1.112 (multicast)"
    );
    assert!(
        !ips.iter().any(|ip| ip.contains("51.0.100.80")),
        "Should reject 51.0.100.80 (zero octet)"
    );
    assert!(
        !ips.iter().any(|ip| ip.contains("123.45.0.67")),
        "Should reject 123.45.0.67 (zero octet)"
    );

    // Should find the valid IP
    assert!(
        ips.contains("103.214.143.214:8085"),
        "Should find 103.214.143.214:8085"
    );
}

#[test]
fn test_sockaddr_in_rejects_linear_ip() {
    // Linear sequences like 0x0D 0x0E 0x0F 0x10 are common in data tables,
    // not real addresses (matches the tscfgwmi.dll false positive pattern).
    let mut data = vec![0xAA; 320];

    // 13.14.15.16 — perfectly sequential, should be rejected
    data[270] = 0x02;
    data[271] = 0x00;
    data[272..274].copy_from_slice(&[0x01, 0x02]); // Port 258
    data[274..278].copy_from_slice(&[0x0D, 0x0E, 0x0F, 0x10]); // 13.14.15.16

    // 21.22.23.24 — also linear
    data[280] = 0x02;
    data[281] = 0x00;
    data[282..284].copy_from_slice(&[0x1F, 0x90]); // Port 8080
    data[284..288].copy_from_slice(&[0x15, 0x16, 0x17, 0x18]); // 21.22.23.24

    // 192.168.1.50 — not linear, should be found
    put_sockaddr_in(&mut data, 290, true, 8081, [192, 168, 1, 50]);

    let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);
    let ips: std::collections::HashSet<&str> = results.iter().map(|s| s.value.as_str()).collect();

    assert!(
        !ips.contains("13.14.15.16:258"),
        "Should reject linear IP 13.14.15.16"
    );
    assert!(
        !ips.contains("21.22.23.24:8080"),
        "Should reject linear IP 21.22.23.24"
    );
    assert!(
        ips.contains("192.168.1.50:8081"),
        "Should find non-linear IP 192.168.1.50"
    );
}

#[test]
fn test_sockaddr_in_rejects_low_last_octet() {
    // Last octets 1–4 are gateway/infrastructure, not C2 hosts.
    // Mirrors the 128.92.202.4 false positive from tscfgwmi.dll.
    let mut data = vec![0xAA; 320];

    // 128.92.202.4 — last octet 4, should be rejected
    data[270] = 0x00;
    data[271] = 0x02;
    data[272..274].copy_from_slice(&[0x80, 0x02]); // Port 32770
    data[274..278].copy_from_slice(&[0x80, 0x5C, 0xCA, 0x04]); // 128.92.202.4

    // 12.2.120.2 — last octet 2, should be rejected
    data[280] = 0x00;
    data[281] = 0x02;
    data[282..284].copy_from_slice(&[0x1A, 0x04]); // Port 6660
    data[284..288].copy_from_slice(&[0x0C, 0x02, 0x78, 0x02]); // 12.2.120.2

    // 128.92.202.6 — last octet 6, should be found
    put_sockaddr_in(&mut data, 290, false, 32770, [128, 92, 202, 6]);

    let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);
    let ips: std::collections::HashSet<&str> = results.iter().map(|s| s.value.as_str()).collect();

    assert!(
        !ips.contains("128.92.202.4:32770"),
        "Should reject last octet 4"
    );
    assert!(
        !ips.contains("12.2.120.2:6660"),
        "Should reject last octet 2"
    );
    assert!(
        ips.contains("128.92.202.6:32770"),
        "Should find last octet 6"
    );
}

#[test]
fn test_sockaddr_in_rejects_repeated_low_octets() {
    // Repeated low-value octets are common in binary data tables, not real IPs.
    // Mirrors the 21.3.12.12 false positive from tscfgwmi.dll.
    let mut data = vec![0xAA; 340];

    // 21.3.12.12 — value 12 repeats and is < 16, should be rejected
    data[270] = 0x00;
    data[271] = 0x02;
    data[272..274].copy_from_slice(&[0x05, 0x5B]); // Port 1371
    data[274..278].copy_from_slice(&[0x15, 0x03, 0x0C, 0x0C]); // 21.3.12.12

    // 185.220.100.240 — no repeated low values, should be found
    put_sockaddr_in(&mut data, 290, false, 8080, [185, 220, 100, 240]);

    // 104.21.25.21 — 21 repeats but 21 >= 16, should be found
    put_sockaddr_in(&mut data, 310, false, 443, [104, 21, 25, 21]);

    let results = scan_sockaddr_in(&data, 4, Endianness::Unknown);
    let ips: std::collections::HashSet<&str> = results.iter().map(|s| s.value.as_str()).collect();

    assert!(
        !ips.contains("21.3.12.12:1371"),
        "Should reject repeated low octet 12"
    );
    assert!(
        ips.contains("185.220.100.240:8080"),
        "Should find IP with no repeated low octets"
    );
    assert!(
        ips.contains("104.21.25.21:443"),
        "Should find IP where repeated value >= 16"
    );
}

#[test]
fn test_m68000_skip() {
    // M68000 binaries should return empty results to avoid false positives
    // Their instruction stream naturally contains 0x0002 patterns
    let mut data = vec![0xAA; 300];

    // Create a valid sockaddr_in structure
    data[270] = 0x02;
    data[271] = 0x00;
    data[272..274].copy_from_slice(&[0x1F, 0x90]); // Port 8080
    data[274..278].copy_from_slice(&[0xC0, 0xA8, 0x01, 0x32]); // IP 192.168.1.50

    let elf_m68k = 4; // EM_68K from ELF header
    let results = scan_binary_ips(&data, 4, elf_m68k, None, None);

    // Should return empty for M68000 binaries
    assert!(
        results.is_empty(),
        "Should skip all results for M68000 binaries"
    );
}

#[test]
fn test_non_m68000_architectures_processed() {
    // Non-M68000 architectures should be processed normally
    let mut data = vec![0xAA; 300];

    // Create a valid sockaddr_in structure
    put_sockaddr_in(&mut data, 270, true, 8080, [192, 168, 1, 50]);

    // Test with various non-M68000 architectures
    let arch_samples = vec![
        (40, "ARM"),    // EM_ARM
        (183, "ARM64"), // EM_AARCH64
        (62, "x86_64"), // EM_X86_64
        (3, "x86"),     // EM_386
    ];

    for (e_machine, arch_name) in arch_samples {
        let results = scan_binary_ips(&data, 4, e_machine, None, None);
        assert!(
            !results.is_empty(),
            "Should process {arch_name} architecture"
        );
        assert!(
            results
                .iter()
                .any(|r| r.value.contains("192.168.1.50:8080")),
            "Should find IP for {arch_name} architecture"
        );
    }
}

#[test]
fn test_sockaddr_endianness_le_rejects_be_marker() {
    // On a little-endian binary, only `02 00` is a real sockaddr_in.
    // A `00 02 ...` sequence (e.g. middle of a COM GUID) must NOT match.
    let mut data = vec![0xAA; 300];
    // BE-marker bytes that decode to a plausible-looking 155.241.239.26:48379
    put_sockaddr_in(&mut data, 270, false, 48379, [155, 241, 239, 26]);

    let results = scan_sockaddr_in(&data, 4, Endianness::Little);
    assert!(
        results.is_empty(),
        "LE binary should not accept BE AF_INET marker; got {results:?}"
    );

    // Sanity: the same buffer with Unknown endianness *would* match.
    let results_unknown = scan_sockaddr_in(&data, 4, Endianness::Unknown);
    assert!(
        !results_unknown.is_empty(),
        "Unknown endianness should accept either marker"
    );
}

#[test]
fn test_sockaddr_endianness_be_rejects_le_marker() {
    // Inverse: on a big-endian binary, only `00 02` is real.
    let mut data = vec![0xAA; 300];
    data[270] = 0x02;
    data[271] = 0x00;
    data[272..274].copy_from_slice(&[0x1F, 0x90]); // Port 8080
    data[274..278].copy_from_slice(&[0xC0, 0xA8, 0x01, 0x32]); // 192.168.1.50

    let results = scan_sockaddr_in(&data, 4, Endianness::Big);
    assert!(
        results.is_empty(),
        "BE binary should not accept LE AF_INET marker; got {results:?}"
    );
}

#[test]
fn test_sockaddr_endianness_le_still_finds_native_marker() {
    // Regression guard: real LE sockaddr_in still extracts.
    let mut data = vec![0xAA; 300];
    put_sockaddr_in(&mut data, 270, true, 8080, [192, 168, 1, 50]);

    let results = scan_sockaddr_in(&data, 4, Endianness::Little);
    assert!(results.iter().any(|s| s.value == "192.168.1.50:8080"));
}

#[test]
fn test_non_go_binaries_still_processed() {
    // Create a C-style binary with sockaddr_in that should be detected
    let mut data = vec![0xAA; 300];

    put_sockaddr_in(&mut data, 270, true, 8080, [192, 168, 1, 50]);

    // Test with ARM architecture (not M68000, not Go)
    let elf_arm = 40; // EM_ARM
    let results = scan_binary_ips(&data, 4, elf_arm, None, None);

    // Should still find the sockaddr_in structure
    assert!(
        !results.is_empty(),
        "Non-Go binaries should still be scanned"
    );
    assert!(
        results
            .iter()
            .any(|r| r.value.contains("192.168.1.50:8080")),
        "Should find IP in non-Go binary"
    );
}

/// Verbatim 64-byte slice from CPython 3.10 `unicodedata.pyd` (Windows) at
/// file offset 0x4f80 — densely-packed UNWIND_CODE-style data that the
/// raw scanner previously surfaced as `19.1.2.170:5632` and `19.1.5.170:6912`.
/// `02 00 16 00 13 01 02 aa` sits at relative offset 26 of this slice.
const UWOP_FIXTURE: &[u8] = &[
    0x0a, 0x00, 0x05, 0x00, 0x1b, 0x00, 0x0b, 0x00, 0x05, 0x00, 0x1b, 0x00, 0x13, 0x01, 0x04, 0x88,
    0x1b, 0x00, 0x13, 0x01, 0x04, 0x0a, 0x1e, 0x00, 0x13, 0x00, 0x02, 0x00, 0x16, 0x00, 0x13, 0x01,
    0x02, 0xaa, 0x17, 0x00, 0x13, 0x01, 0x02, 0xaa, 0x1e, 0x00, 0x01, 0x00, 0x04, 0x88, 0x09, 0x00,
    0x13, 0x00, 0x04, 0x00, 0x1b, 0x00, 0x13, 0x00, 0x02, 0x00, 0x1b, 0x00, 0x13, 0x01, 0x05, 0xaa,
];

/// Verbatim 64-byte slices from the Inno Setup installer
/// `6fcd77d331dd9e9699a0f5ac623e2ac0.exe` at file offsets 0x1677f and
/// 0x16abd, centered on the AF_INET marker (relative offset 32). These are
/// Delphi/VCL packed metadata tables (`64 02 64 02`, `f0 02 f0 02`,
/// `XX 10 XX 10`) that the raw scanner surfaced as `11.16.15.16:3856` and
/// `19.89.9.89:784` — neither IP exists as ASCII anywhere in the file.
const PERIODIC_FIXTURE_A: &[u8] = &[
    0x0e, 0x10, 0x0b, 0x10, 0x0b, 0x10, 0x0b, 0x10, 0x0b, 0x10, 0x0b, 0x10, 0x0b, 0x0f, 0x0e, 0x10,
    0x0b, 0x10, 0x0b, 0xe0, 0x0e, 0x10, 0x0b, 0xf0, 0x0e, 0x64, 0x02, 0x64, 0x02, 0x64, 0x02, 0x64,
    0x02, 0x00, 0x0f, 0x10, 0x0b, 0x10, 0x0f, 0x10, 0x0b, 0x20, 0x0f, 0x30, 0x0f, 0x40, 0x0f, 0x50,
    0x0f, 0x59, 0x09, 0x60, 0x0f, 0x10, 0x0b, 0x70, 0x0f, 0x80, 0x0f, 0x34, 0x0e, 0x90, 0x0f, 0x34,
];
const PERIODIC_FIXTURE_B: &[u8] = &[
    0x12, 0x00, 0x13, 0x8d, 0x04, 0xf0, 0x02, 0x1b, 0x07, 0x56, 0x05, 0xfd, 0x02, 0xfd, 0x02, 0x64,
    0x02, 0x64, 0x02, 0xf0, 0x02, 0xf0, 0x02, 0xf0, 0x02, 0xf0, 0x02, 0xf0, 0x02, 0xf0, 0x02, 0xf0,
    0x02, 0x00, 0x03, 0x10, 0x13, 0x59, 0x09, 0x59, 0x09, 0x69, 0x09, 0xd0, 0x0d, 0xd0, 0x0d, 0xd0,
    0x0d, 0x20, 0x13, 0x30, 0x13, 0x64, 0x02, 0x64, 0x02, 0x64, 0x02, 0x64, 0x02, 0x64, 0x02, 0x64,
];

#[test]
fn test_sits_in_periodic_table_flags_real_false_positives() {
    // AF_INET marker sits at relative offset 32 in both fixtures.
    assert!(
        sits_in_periodic_table(PERIODIC_FIXTURE_A, 32),
        "11.16.15.16:3856 packed-table region must be flagged"
    );
    assert!(
        sits_in_periodic_table(PERIODIC_FIXTURE_B, 32),
        "19.89.9.89:784 packed-table region must be flagged"
    );
}

#[test]
fn test_sits_in_periodic_table_passes_real_layouts() {
    // Heterogeneous .data around a real sockaddr_in.
    let mut hetero: Vec<u8> = (0u8..128)
        .map(|i| i.wrapping_mul(37).wrapping_add(0x33))
        .collect();
    hetero[64..72].copy_from_slice(&[0x02, 0x00, 0x1f, 0x90, 192, 168, 1, 50]);
    assert!(
        !sits_in_periodic_table(&hetero, 64),
        "heterogeneous sockaddr_in must not be flagged"
    );

    // Zero-padded struct in a BSS-like region — zeros must not count as
    // periodicity.
    let mut zeroed = vec![0u8; 128];
    zeroed[64..72].copy_from_slice(&[0x02, 0x00, 0x1f, 0x90, 192, 168, 1, 50]);
    assert!(
        !sits_in_periodic_table(&zeroed, 64),
        "zero-padded sockaddr_in must not be flagged"
    );
}

#[test]
fn test_sin_zero_guard_rejects_periodic_fixture_at_raw_scan() {
    // The Delphi/VCL packed-table false positive (11.16.15.16:3856) is now
    // caught by the sin_zero guard directly in scan_sockaddr_in, without
    // needing a PE handle or the periodicity guard: the eight bytes after
    // the candidate IP are packed-table data, not a zeroed sin_zero tail.
    let mut data = vec![0u8; 2048];
    let embed = 1200;
    data[embed..embed + PERIODIC_FIXTURE_A.len()].copy_from_slice(PERIODIC_FIXTURE_A);
    let raw = scan_sockaddr_in(&data, 4, Endianness::Little);
    assert!(
        !raw.iter().any(|s| s.value == "11.16.15.16:3856"),
        "sin_zero guard must reject the packed-table false positive at raw scan; got {raw:?}"
    );
}

#[test]
fn test_looks_like_packed_u16_table_flags_unwind_code_region() {
    // Both AF_INET-marker offsets in the real fixture must be flagged.
    assert!(looks_like_packed_u16_table(UWOP_FIXTURE, 26));
    assert!(looks_like_packed_u16_table(UWOP_FIXTURE, 56));
}

#[test]
fn test_looks_like_packed_u16_table_passes_isolated_sockaddr() {
    // 192.168.1.50:8080 embedded among heterogeneous bytes (function
    // pointers, padding, unrelated constants) — what a real sockaddr_in
    // in `.data` looks like. Must NOT be flagged.
    // Pseudo-random spread covering the high byte space so u16 LE
    // values are >= 0x0200 most of the time. Length 128 fits in u8.
    let data_init: Vec<u8> = (0u8..128)
        .map(|i| i.wrapping_mul(37).wrapping_add(0x33))
        .collect();
    let mut data = data_init;
    let off = 64;
    data[off] = 0x02;
    data[off + 1] = 0x00;
    data[off + 2] = 0x1f;
    data[off + 3] = 0x90; // port 8080
    data[off + 4] = 192;
    data[off + 5] = 168;
    data[off + 6] = 1;
    data[off + 7] = 50;

    assert!(
        !looks_like_packed_u16_table(&data, off),
        "Isolated sockaddr_in in heterogeneous data must not be filtered"
    );
}

#[test]
fn test_sin_zero_guard_rejects_unwind_fixture_at_raw_scan() {
    // Embed the UWOP fixture deep enough to clear the 1024-byte header skip
    // used by scan_sockaddr_in.
    let mut data = vec![0u8; 2048];
    let embed = 1200;
    data[embed..embed + UWOP_FIXTURE.len()].copy_from_slice(UWOP_FIXTURE);

    // The UNWIND_CODE false positive (19.1.2.170:5632) is now rejected by
    // the sin_zero guard directly in scan_sockaddr_in: the bytes following
    // the candidate IP are further unwind data, not a zeroed sin_zero tail.
    // This catches the false positive without a PE handle, ahead of the
    // looks_like_packed_u16_table guard the PE retain path still applies.
    let raw = scan_sockaddr_in(&data, 4, Endianness::Little);
    assert!(
        !raw.iter().any(|s| s.value == "19.1.2.170:5632"),
        "sin_zero guard must reject the UNWIND_CODE false positive at raw scan; got {raw:?}"
    );
}
