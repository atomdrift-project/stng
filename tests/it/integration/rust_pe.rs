use stng::{ExtractOptions, extract_strings_with_options};

/// A parseable PE32+ (AMD64) with a single `.rdata` section holding `rdata`.
fn pe_with_rdata(rdata: &[u8]) -> Vec<u8> {
    const RAW: u32 = 0x200;
    let raw = RAW as usize;
    assert!(
        rdata.len() <= raw,
        "fixture .rdata is one file-aligned page"
    );
    let mut pe = vec![0u8; raw * 2];
    let put =
        |pe: &mut Vec<u8>, at: usize, bytes: &[u8]| pe[at..at + bytes.len()].copy_from_slice(bytes);

    put(&mut pe, 0, b"MZ");
    put(&mut pe, 0x3C, &0x80u32.to_le_bytes());
    put(&mut pe, 0x80, b"PE\0\0");
    // COFF header: AMD64, one section, PE32+ optional header, executable.
    put(&mut pe, 0x84, &0x8664u16.to_le_bytes());
    put(&mut pe, 0x86, &1u16.to_le_bytes());
    put(&mut pe, 0x94, &0xF0u16.to_le_bytes());
    put(&mut pe, 0x96, &0x0022u16.to_le_bytes());
    // Optional header.
    let opt = 0x98;
    put(&mut pe, opt, &0x20Bu16.to_le_bytes());
    put(&mut pe, opt + 16, &0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    put(&mut pe, opt + 24, &0x1_4000_0000u64.to_le_bytes()); // ImageBase
    put(&mut pe, opt + 32, &0x1000u32.to_le_bytes()); // SectionAlignment
    put(&mut pe, opt + 36, &RAW.to_le_bytes()); // FileAlignment
    put(&mut pe, opt + 48, &6u16.to_le_bytes()); // MajorSubsystemVersion
    put(&mut pe, opt + 56, &0x2000u32.to_le_bytes()); // SizeOfImage
    put(&mut pe, opt + 60, &RAW.to_le_bytes()); // SizeOfHeaders
    put(&mut pe, opt + 68, &3u16.to_le_bytes()); // Subsystem: console
    put(&mut pe, opt + 108, &16u32.to_le_bytes()); // NumberOfRvaAndSizes
    // Section table: .rdata, read-only initialized data.
    let sec = opt + 0xF0;
    put(&mut pe, sec, b".rdata\0\0");
    put(&mut pe, sec + 8, &RAW.to_le_bytes()); // VirtualSize
    put(&mut pe, sec + 12, &0x1000u32.to_le_bytes()); // VirtualAddress
    put(&mut pe, sec + 16, &RAW.to_le_bytes()); // SizeOfRawData
    put(&mut pe, sec + 20, &RAW.to_le_bytes()); // PointerToRawData
    put(&mut pe, sec + 36, &0x4000_0040u32.to_le_bytes()); // Characteristics
    put(&mut pe, raw, rdata);
    pe
}

/// Rust code names many `&str` literals straight from instructions (`lea`
/// plus a length immediate), so no `(ptr, len)` record in data reaches them.
/// JAVS's 2024 `fffmpeg.exe` backdoor kept its whole C2 vocabulary that way;
/// with `.rdata` excluded from the raw scan, none of it was extracted.
#[test]
fn rust_pe_keeps_rdata_literals_no_pointer_table_names() {
    let mut rdata =
        b"/rustc/79e9716c980570bfd1f666e3b16ac583f0168962/library/std/src/rt.rs".to_vec();
    rdata.extend_from_slice(b"gateway/registergateway/reportgateway/task");
    let pe = pe_with_rdata(&rdata);
    assert!(
        stng::is_rust_binary(&pe),
        "fixture must be detected as a Rust PE"
    );

    let strings = extract_strings_with_options(&pe, &ExtractOptions::new(4));
    assert!(
        strings.iter().any(|s| s.value.contains("gateway/register")),
        "code-referenced .rdata literal was dropped: {:?}",
        strings.iter().map(|s| &s.value).collect::<Vec<_>>()
    );
}
