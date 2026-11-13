//! UTF-16 strings built one character at a time through a pointer reloaded
//! from a global, as Dofoil's crypter stub builds a COM interface key:
//!
//! ```text
//! mov dword [ebp-4],0
//! ; per character c at displacement d:
//! mov eax,[ebp-4]; add eax,c; mov ecx,[global]; mov word [ecx+d],ax
//! ```
//!
//! The fixtures are synthetic PEs assembled here; no sample bytes.

use stng::{ExtractOptions, ExtractedString, StringKind, StringMethod, extract_strings_with_options};

/// File alignment, and the size of the headers and of `.data`.
const RAW: u32 = 0x200;
/// `.text` spans two file-aligned pages.
const TEXT_SIZE: u32 = 2 * RAW;
const TEXT_RVA: u32 = 0x1000;
const DATA_RVA: u32 = 0x2000;
const BASE32: u32 = 0x40_0000;
const BASE64: u64 = 0x1_4000_0000;

/// A COM interface key (the HTMLDocument IID): what the stub assembles.
const KEY: &str = "interface\\{3050F557-98B5-11CF-BB82-00AA00BDCE0B}";

/// A parseable PE (PE32+ for AMD64 when `amd64`, else PE32 for i386) with
/// `.text` holding `code` and `.data` holding the global pointer.
fn pe(code: &[u8], amd64: bool) -> Vec<u8> {
    let raw = RAW as usize;
    let text_size = TEXT_SIZE as usize;
    let data_at = raw + text_size;
    assert!(code.len() <= text_size, "fixture code fits .text");
    let mut pe = vec![0u8; data_at + raw];
    let put =
        |pe: &mut Vec<u8>, at: usize, bytes: &[u8]| pe[at..at + bytes.len()].copy_from_slice(bytes);

    put(&mut pe, 0, b"MZ");
    put(&mut pe, 0x3C, &0x80u32.to_le_bytes());
    put(&mut pe, 0x80, b"PE\0\0");
    let (machine, opt_size, characteristics) = if amd64 {
        (0x8664u16, 0xF0u16, 0x0022u16)
    } else {
        (0x014C, 0xE0, 0x0102)
    };
    put(&mut pe, 0x84, &machine.to_le_bytes());
    put(&mut pe, 0x86, &2u16.to_le_bytes()); // NumberOfSections
    put(&mut pe, 0x94, &opt_size.to_le_bytes());
    put(&mut pe, 0x96, &characteristics.to_le_bytes());
    let opt = 0x98;
    put(&mut pe, opt + 16, &TEXT_RVA.to_le_bytes()); // AddressOfEntryPoint
    put(&mut pe, opt + 20, &TEXT_RVA.to_le_bytes()); // BaseOfCode
    if amd64 {
        put(&mut pe, opt, &0x20Bu16.to_le_bytes());
        put(&mut pe, opt + 24, &BASE64.to_le_bytes());
        put(&mut pe, opt + 108, &16u32.to_le_bytes()); // NumberOfRvaAndSizes
    } else {
        put(&mut pe, opt, &0x10Bu16.to_le_bytes());
        put(&mut pe, opt + 24, &DATA_RVA.to_le_bytes()); // BaseOfData
        put(&mut pe, opt + 28, &BASE32.to_le_bytes());
        put(&mut pe, opt + 92, &16u32.to_le_bytes()); // NumberOfRvaAndSizes
    }
    put(&mut pe, opt + 32, &0x1000u32.to_le_bytes()); // SectionAlignment
    put(&mut pe, opt + 36, &RAW.to_le_bytes()); // FileAlignment
    put(&mut pe, opt + 48, &6u16.to_le_bytes()); // MajorSubsystemVersion
    put(&mut pe, opt + 56, &0x3000u32.to_le_bytes()); // SizeOfImage
    put(&mut pe, opt + 60, &RAW.to_le_bytes()); // SizeOfHeaders
    put(&mut pe, opt + 68, &2u16.to_le_bytes()); // Subsystem: GUI

    // (name, RVA, size, file offset, characteristics)
    let sections: [(&[u8; 8], u32, u32, u32, u32); 2] = [
        // Code: execute, read.
        (b".text\0\0\0", TEXT_RVA, TEXT_SIZE, RAW, 0x6000_0020),
        // Initialized data: read, write.
        (b".data\0\0\0", DATA_RVA, RAW, RAW + TEXT_SIZE, 0xC000_0040),
    ];
    let mut sec = opt + usize::from(opt_size);
    for (name, rva, size, file_at, flags) in sections {
        put(&mut pe, sec, name);
        put(&mut pe, sec + 8, &size.to_le_bytes()); // VirtualSize
        put(&mut pe, sec + 12, &rva.to_le_bytes()); // VirtualAddress
        put(&mut pe, sec + 16, &size.to_le_bytes()); // SizeOfRawData
        put(&mut pe, sec + 20, &file_at.to_le_bytes()); // PointerToRawData
        put(&mut pe, sec + 36, &flags.to_le_bytes()); // Characteristics
        sec += 40;
    }
    put(&mut pe, raw, code);
    // The global at the start of .data points at the buffer just past it.
    if amd64 {
        put(&mut pe, data_at, &(BASE64 + u64::from(DATA_RVA) + 16).to_le_bytes());
    } else {
        put(&mut pe, data_at, &(BASE32 + DATA_RVA + 16).to_le_bytes());
    }
    pe
}

/// The i386 stub: `push ebp; mov ebp,esp; push ecx; mov dword [ebp-4],0`,
/// then per character `mov eax,[ebp-4]; add eax,c; mov ecx,[global];
/// mov word [ecx+d],ax`, displacements advancing by `stride`.
fn i386_stub(text: &[u8], stride: u8) -> Vec<u8> {
    let global = (BASE32 + DATA_RVA).to_le_bytes();
    let mut code = vec![0x55, 0x89, 0xe5, 0x51, 0xc7, 0x45, 0xfc, 0, 0, 0, 0];
    let mut disp = 0u8;
    for &c in text {
        code.extend([0x8b, 0x45, 0xfc, 0x83, 0xc0, c, 0x8b, 0x0d]);
        code.extend(global);
        code.extend([0x66, 0x89, 0x41, disp]);
        disp = disp.wrapping_add(stride);
    }
    code.extend([0x89, 0xec, 0x5d, 0xc3]); // mov esp,ebp; pop ebp; ret
    code
}

/// The same stub for AMD64, the pointer loaded RIP-relative:
/// `mov eax,[rbp-4]; add eax,c; mov rcx,[rip+X]; mov word [rcx+d],ax`.
fn amd64_stub(text: &[u8], stride: u8) -> Vec<u8> {
    let global = i64::from(DATA_RVA);
    let mut code = vec![0x55, 0x48, 0x89, 0xe5, 0xc7, 0x45, 0xfc, 0, 0, 0, 0];
    let mut disp = 0u8;
    for &c in text {
        code.extend([0x8b, 0x45, 0xfc, 0x83, 0xc0, c, 0x48, 0x8b, 0x0d]);
        // RIP-relative to the end of the load: four displacement bytes on.
        let next = i64::from(TEXT_RVA) + i64::try_from(code.len() + 4).unwrap_or(i64::MAX);
        code.extend(i32::try_from(global - next).unwrap_or(0).to_le_bytes());
        code.extend([0x66, 0x89, 0x41, disp]);
        disp = disp.wrapping_add(stride);
    }
    code.extend([0x5d, 0xc3]); // pop rbp; ret
    code
}

fn stack_strings(pe: &[u8]) -> Vec<ExtractedString> {
    extract_strings_with_options(pe, &ExtractOptions::new(4))
        .into_iter()
        .filter(|s| s.method == StringMethod::StackString)
        .collect()
}

fn assert_recovers_key(pe: &[u8]) {
    let strings = stack_strings(pe);
    assert!(
        strings
            .iter()
            .any(|s| s.value == KEY && s.kind == Some(StringKind::StackString)),
        "{strings:?}"
    );
}

#[test]
fn i386_pe_recovers_wide_string_built_through_global_pointer() {
    assert_recovers_key(&pe(&i386_stub(KEY.as_bytes(), 2), false));
}

#[test]
fn amd64_pe_recovers_wide_string_built_through_global_pointer() {
    assert_recovers_key(&pe(&amd64_stub(KEY.as_bytes(), 2), true));
}

/// Word stores four bytes apart fill adjacent integer slots; not text.
#[test]
fn pe_word_stores_with_gaps_yield_no_stack_string() {
    for pe in [
        pe(&i386_stub(KEY.as_bytes(), 4), false),
        pe(&amd64_stub(KEY.as_bytes(), 4), true),
    ] {
        let strings = stack_strings(&pe);
        assert!(strings.is_empty(), "{strings:?}");
    }
}

#[test]
fn pe_non_printable_values_yield_no_stack_string() {
    let values: Vec<u8> = (1..=16).collect();
    for pe in [
        pe(&i386_stub(&values, 2), false),
        pe(&amd64_stub(&values, 2), true),
    ] {
        let strings = stack_strings(&pe);
        assert!(strings.is_empty(), "{strings:?}");
    }
}
