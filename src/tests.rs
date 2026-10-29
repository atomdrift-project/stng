use super::*;

#[test]
fn fat_linkedit_walk_is_bounded_by_the_buffer() {
    // nfat_arch = u32::MAX over 1 KiB: a walk that trusts the count
    // visits about four billion entries.
    let mut data = vec![0xCA, 0xFE, 0xBA, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF];
    data.resize(1024, 0);
    let fat = goblin::mach::MultiArch::new(&data).expect("fat header parses");
    let object = Object::Mach(goblin::mach::Mach::Fat(fat));
    assert!(pipeline::macho::macho_linkedit_ranges(&object).is_empty());
}

#[test]
fn stack_string_spans_are_file_offsets() {
    // mov dword [rbp-0x10], "hell"; mov dword [rbp-0xc], "o wo";
    // mov dword [rbp-8], "rld\0"; ret — 4 KB into the file.
    let code = [
        0xC7, 0x45, 0xF0, b'h', b'e', b'l', b'l', 0xC7, 0x45, 0xF4, b'o', b' ', b'w', b'o', 0xC7,
        0x45, 0xF8, b'r', b'l', b'd', 0, 0xC3,
    ];
    let mut data = vec![0u8; 4096];
    data.extend_from_slice(&code);
    let found = extract_stack_strings_from_ranges(&data, 4, &[(4096, data.len())]);
    let s = found
        .iter()
        .find(|s| s.value.starts_with("hello"))
        .unwrap_or_else(|| panic!("no stack string in {found:?}"));
    assert!(s.fragments.is_some(), "{s:?}");
    for (offset, len) in s.source_spans() {
        assert!(
            offset >= 4096 && offset + len <= data.len() as u64,
            "span {offset}+{len} outside the code: {s:?}"
        );
    }
}

#[test]
fn instruction_referenced_text_preserves_layout_without_exempting_raw_noise() {
    let text = "a\nb\tc\rd";
    assert!(passes_garbage_filter(
        &at(text, 0, StringMethod::InstructionPattern),
        &[]
    ));
    assert!(!passes_garbage_filter(
        &at(text, 0, StringMethod::RawScan),
        &[]
    ));
    for control in ['\0', '\u{1}', '\u{1b}', '\u{7f}'] {
        let value = format!("a\nb{control}c");
        assert!(!passes_garbage_filter(
            &at(&value, 0, StringMethod::InstructionPattern),
            &[]
        ));
    }
    assert!(!passes_garbage_filter(
        &at(" \n\t\r ", 0, StringMethod::InstructionPattern),
        &[]
    ));
}

fn at(value: &str, offset: u64, method: StringMethod) -> ExtractedString {
    ExtractedString {
        value: value.to_string(),
        data_offset: offset,
        method,
        ..Default::default()
    }
}

#[test]
fn unclaimed_raw_strings_keeps_bytes_around_claimed_literals() {
    // rustc packs `src/main.rs` and an unreferenced URL back to back.
    let raw = vec![
        at(
            "src/main.rshttps://example.org/x.png",
            0x100,
            StringMethod::RawScan,
        ),
        at("untouched run", 0x200, StringMethod::RawScan),
        at("already known", 0x300, StringMethod::RawScan),
    ];
    let claimed = vec![
        at("src/main.rs", 0x100, StringMethod::Structure),
        at("already known", 0x400, StringMethod::Structure),
    ];

    let got: Vec<_> = unclaimed_raw_strings(raw, &claimed, 4)
        .into_iter()
        .map(|s| (s.value, s.data_offset))
        .collect();
    assert_eq!(
        got,
        [
            ("https://example.org/x.png".to_string(), 0x10b),
            ("untouched run".to_string(), 0x200),
        ]
    );
}

#[test]
fn unclaimed_raw_strings_drops_short_gaps_between_literals() {
    let raw = vec![at("alphaXYbravo", 0, StringMethod::RawScan)];
    let claimed = vec![
        at("alpha", 0, StringMethod::Structure),
        at("bravo", 7, StringMethod::Structure),
    ];
    assert!(unclaimed_raw_strings(raw, &claimed, 4).is_empty());
}
