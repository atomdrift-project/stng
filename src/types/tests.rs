use super::*;

#[test]
fn only_x86_and_x86_64_are_x86_family() {
    assert!(Arch::X86.is_x86_family());
    assert!(Arch::X86_64.is_x86_family());
    assert!(!Arch::Aarch64.is_x86_family());
    assert!(!Arch::Arm.is_x86_family());
    assert!(!Arch::Mips.is_x86_family());
    assert!(!Arch::Wasm.is_x86_family());
}

#[test]
fn source_spans_use_recorded_extent_then_fall_back_then_fragments() {
    // Recorded extent (e.g. a UTF-16LE string: source is 2× the value).
    let wide = ExtractedString {
        value: "Hi".into(),
        data_offset: 0x40,
        data_len: 4,
        method: StringMethod::WideString,
        ..Default::default()
    };
    assert_eq!(wide.source_spans().collect::<Vec<_>>(), vec![(0x40, 4)]);

    // No recorded extent → byte-identical fallback to the value length.
    let ascii = ExtractedString {
        value: "abcd".into(),
        data_offset: 0x10,
        method: StringMethod::RawScan,
        ..Default::default()
    };
    assert_eq!(ascii.source_spans().collect::<Vec<_>>(), vec![(0x10, 4)]);

    // Scattered stack string → the fragments, not the (bogus) single extent.
    let stack = ExtractedString {
        value: "STACK".into(),
        data_offset: 9999,
        data_len: 0,
        method: StringMethod::StackString,
        fragments: Some(Box::new(vec![
            StringFragment {
                offset: 0x100,
                length: 4,
            },
            StringFragment {
                offset: 0x200,
                length: 1,
            },
        ])),
        ..Default::default()
    };
    assert_eq!(
        stack.source_spans().collect::<Vec<_>>(),
        vec![(0x100, 4), (0x200, 1)]
    );
}

#[test]
fn elf_64bit_le_has_8_byte_pointers() {
    let info = BinaryInfo::from_elf(true, true);
    assert!(info.is_64bit);
    assert!(info.is_little_endian);
    assert_eq!(info.ptr_size, 8);
}

#[test]
fn elf_32bit_le_has_4_byte_pointers() {
    let info = BinaryInfo::from_elf(false, true);
    assert!(!info.is_64bit);
    assert!(info.is_little_endian);
    assert_eq!(info.ptr_size, 4);
}

#[test]
fn elf_64bit_be_has_8_byte_pointers() {
    let info = BinaryInfo::from_elf(true, false);
    assert!(info.is_64bit);
    assert!(!info.is_little_endian);
    assert_eq!(info.ptr_size, 8);
}

#[test]
fn elf_32bit_be_has_4_byte_pointers() {
    let info = BinaryInfo::from_elf(false, false);
    assert!(!info.is_64bit);
    assert!(!info.is_little_endian);
    assert_eq!(info.ptr_size, 4);
}

#[test]
fn elf_info_follows_class_and_endianness() {
    let info64 = BinaryInfo::from_elf(true, true);
    assert!(info64.is_64bit);
    assert!(info64.is_little_endian);
    assert_eq!(info64.ptr_size, 8);

    let info32 = BinaryInfo::from_elf(false, false);
    assert!(!info32.is_64bit);
    assert!(!info32.is_little_endian);
    assert_eq!(info32.ptr_size, 4);
}

#[test]
fn macho_info_is_always_little_endian() {
    let info64 = BinaryInfo::from_macho(true);
    assert!(info64.is_64bit);
    assert!(info64.is_little_endian); // Mach-O always LE
    assert_eq!(info64.ptr_size, 8);

    let info32 = BinaryInfo::from_macho(false);
    assert!(!info32.is_64bit);
    assert!(info32.is_little_endian);
    assert_eq!(info32.ptr_size, 4);
}

#[test]
fn pe_info_is_always_little_endian() {
    let info64 = BinaryInfo::from_pe(true);
    assert!(info64.is_64bit);
    assert!(info64.is_little_endian); // PE always LE
    assert_eq!(info64.ptr_size, 8);

    let info32 = BinaryInfo::from_pe(false);
    assert!(!info32.is_64bit);
    assert!(info32.is_little_endian);
    assert_eq!(info32.ptr_size, 4);
}

// ===== OverlayInfo Tests =====

#[test]
fn overlay_info_keeps_fields() {
    let overlay = OverlayInfo {
        start_offset: 0x10000,
        size: 0x5000,
    };

    assert_eq!(overlay.start_offset, 0x10000);
    assert_eq!(overlay.size, 0x5000);
}

#[test]
fn overlay_info_copies() {
    let overlay = OverlayInfo {
        start_offset: 0x20000,
        size: 0x8000,
    };

    let cloned = overlay;
    assert_eq!(overlay.start_offset, cloned.start_offset);
    assert_eq!(overlay.size, cloned.size);
}

#[test]
fn overlay_info_equal_by_fields() {
    let overlay1 = OverlayInfo {
        start_offset: 1000,
        size: 500,
    };

    let overlay2 = OverlayInfo {
        start_offset: 1000,
        size: 500,
    };

    assert_eq!(overlay1, overlay2);
}

// ===== StringStruct Tests =====

#[test]
fn string_struct_keeps_fields() {
    let s = StringStruct {
        struct_offset: 0x1000,
        ptr: 0x2000,
        len: 42,
    };

    assert_eq!(s.struct_offset, 0x1000);
    assert_eq!(s.ptr, 0x2000);
    assert_eq!(s.len, 42);
}

#[test]
fn string_struct_equal_by_fields() {
    let s1 = StringStruct {
        struct_offset: 100,
        ptr: 200,
        len: 10,
    };

    let s2 = StringStruct {
        struct_offset: 100,
        ptr: 200,
        len: 10,
    };

    assert_eq!(s1, s2);
}

#[test]
fn string_struct_hashes_by_fields() {
    use std::collections::HashSet;

    let s1 = StringStruct {
        struct_offset: 100,
        ptr: 200,
        len: 10,
    };

    let s2 = StringStruct {
        struct_offset: 100,
        ptr: 200,
        len: 10,
    };

    let mut set = HashSet::new();
    set.insert(s1);
    assert!(set.contains(&s2)); // Should find duplicate
}

// ===== ExtractedString with Fragments Tests =====
