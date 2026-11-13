use super::{extract_stack_strings, extract_stack_strings_with_context};

/// `lea rax,[rbp-0x90]; add rax,rdx; mov dword [rax-1],'AAAA'; ret`, then
/// padding. The store's negative displacement once wrapped the bounds check
/// and panicked on the slice.
#[test]
fn strcat_store_with_negative_displacement_is_ignored() {
    let mut code = vec![
        0x48, 0x8d, 0x85, 0x70, 0xff, 0xff, 0xff, // lea rax,[rbp-0x90]
        0x48, 0x01, 0xd0, // add rax,rdx
        0xc7, 0x40, 0xff, 0x41, 0x41, 0x41, 0x41, // mov dword [rax-1],0x41414141
        0xc3, // ret
    ];
    code.extend([b'A'; 160]);
    let strings = extract_stack_strings(&code, 4, 64);
    assert!(
        strings.iter().all(|s| !s.value.starts_with("AAAA\0")),
        "a store before the buffer must not be assembled: {strings:?}"
    );
}

/// Two adjacent RIP-relative stores whose absolute targets sit at the top of
/// the signed range: assembling them once overflowed `disp + len`.
#[test]
fn stack_writes_near_i64_max_do_not_overflow() {
    // mov dword [rip+4],'ABCD'; mov dword [rip+0],'EFGH'
    let code = [
        0xc7, 0x05, 0x04, 0x00, 0x00, 0x00, b'A', b'B', b'C', b'D', //
        0xc7, 0x05, 0x00, 0x00, 0x00, 0x00, b'E', b'F', b'G', b'H',
    ];
    let vma = 0x7fff_ffff_ffff_fff0;
    let strings = extract_stack_strings_with_context(&code, 4, &code, vma, 0, 64);
    assert!(
        strings.iter().any(|s| s.value.contains("ABCD")),
        "the stores are still reported: {strings:?}"
    );
}

/// The i386 pointer every [`i386_global_wide`] store goes through.
const GLOBAL: [u8; 4] = 0x0040_90a4_u32.to_le_bytes();

/// Dofoil's crypter stub (i386), one UTF-16 character at a time:
///
/// ```text
/// push ebp; mov ebp,esp; push ecx
/// mov dword [ebp-4],0              ; only when `zero_local`
/// ; per character, displacements advancing by `stride`:
/// mov eax,[ebp-4]; add eax,c; mov ecx,[0x4090a4]; mov word [ecx+d],ax
/// mov esp,ebp; pop ebp; ret
/// ```
fn i386_global_wide(text: &[u8], stride: u8, zero_local: bool) -> Vec<u8> {
    let mut code = vec![0x55, 0x89, 0xe5, 0x51];
    if zero_local {
        code.extend([0xc7, 0x45, 0xfc, 0, 0, 0, 0]);
    }
    let mut disp = 0u8;
    for &c in text {
        push_global_wide_char(&mut code, c, disp);
        disp = disp.wrapping_add(stride);
    }
    code.extend([0x89, 0xec, 0x5d, 0xc3]);
    code
}

/// `mov eax,[ebp-4]; add eax,c; mov ecx,[0x4090a4]; mov word [ecx+disp],ax`
fn push_global_wide_char(code: &mut Vec<u8>, c: u8, disp: u8) {
    code.extend([0x8b, 0x45, 0xfc, 0x83, 0xc0, c, 0x8b, 0x0d]);
    code.extend(GLOBAL);
    code.extend([0x66, 0x89, 0x41, disp]);
}

/// Whether `strings` holds `value` as a stack string.
fn has_stack_string(strings: &[crate::ExtractedString], value: &str) -> bool {
    strings
        .iter()
        .any(|s| s.value == value && s.method == crate::StringMethod::StackString)
}

#[test]
fn i386_wide_chars_through_global_pointer() {
    let code = i386_global_wide(b"interface\\{3050F557}", 2, true);
    let strings = extract_stack_strings(&code, 4, 32);
    assert!(
        has_stack_string(&strings, "interface\\{3050F557}"),
        "{strings:?}"
    );
}

#[test]
fn non_printable_chars_through_global_pointer_are_ignored() {
    let code = i386_global_wide(&[1, 2, 3, 4, 5, 6, 7, 8], 2, true);
    let strings = extract_stack_strings(&code, 4, 32);
    assert!(strings.is_empty(), "{strings:?}");
}

/// Word stores four bytes apart are integers in adjacent slots, not text.
#[test]
fn wide_chars_with_gaps_are_not_joined() {
    let code = i386_global_wide(b"interface", 4, true);
    let strings = extract_stack_strings(&code, 4, 32);
    assert!(strings.is_empty(), "{strings:?}");
}

/// Without `mov dword [ebp-4],0` the local, and so every character, is
/// unknown.
#[test]
fn chars_from_an_unknown_local_are_ignored() {
    let code = i386_global_wide(b"interface", 2, false);
    let strings = extract_stack_strings(&code, 4, 32);
    assert!(strings.is_empty(), "{strings:?}");
}

/// `mov [0x4090a4],edx` replaces the pointer halfway: the two halves land
/// in different buffers and must not be joined.
#[test]
fn replacing_the_global_pointer_splits_the_buffer() {
    let build = |replace: bool| {
        let mut code = vec![0x55, 0x89, 0xe5, 0x51, 0xc7, 0x45, 0xfc, 0, 0, 0, 0];
        for (disp, c) in (0u8..).step_by(2).zip(*b"abcdef") {
            if replace && c == b'd' {
                code.extend([0x89, 0x15]); // mov [0x4090a4],edx
                code.extend(GLOBAL);
            }
            push_global_wide_char(&mut code, c, disp);
        }
        code.extend([0x89, 0xec, 0x5d, 0xc3]);
        code
    };
    let strings = extract_stack_strings(&build(false), 4, 32);
    assert!(has_stack_string(&strings, "abcdef"), "{strings:?}");
    let strings = extract_stack_strings(&build(true), 4, 32);
    assert!(strings.is_empty(), "{strings:?}");
}

/// x86-64, the pointer reloaded RIP-relative from the global at 0x1000:
/// `mov eax,c; mov rcx,[rip+X]; mov word [rcx+d],ax` per character.
fn amd64_global(text: &[u8], store: &[u8]) -> Vec<u8> {
    let mut code = Vec::new();
    let mut disp = 0u8;
    for &c in text {
        code.extend([0xb8, c, 0, 0, 0, 0x48, 0x8b, 0x0d]);
        // The displacement is relative to the end of the 7-byte load.
        let next = i64::try_from(code.len() + 4).unwrap_or(i64::MAX);
        let rel = i32::try_from(0x1000 - next).unwrap_or(0);
        code.extend(rel.to_le_bytes());
        code.extend(store);
        code.push(disp);
        disp = disp.wrapping_add(u8::try_from(store.len() - 1).unwrap_or(1));
    }
    code.push(0xc3);
    code
}

#[test]
fn amd64_wide_chars_through_rip_relative_global() {
    // mov word [rcx+d],ax
    let code = amd64_global(b"kernel32", &[0x66, 0x89, 0x41]);
    let strings = extract_stack_strings(&code, 4, 64);
    assert!(has_stack_string(&strings, "kernel32"), "{strings:?}");
}

#[test]
fn amd64_bytes_through_rip_relative_global() {
    // mov byte [rcx+d],al
    let code = amd64_global(b"ws2_32.dll", &[0x88, 0x41]);
    let strings = extract_stack_strings(&code, 4, 64);
    assert!(has_stack_string(&strings, "ws2_32.dll"), "{strings:?}");
}

/// i386, a pointer argument reloaded from `[ebp+8]` each time, characters
/// folded with `xor`/`add`/`sub`/`inc`: `xor edx,edx; add edx,c+1; dec`…
/// `mov esi,[ebp+8]; mov byte [esi+d],dl`.
#[test]
fn i386_bytes_through_frame_slot_pointer() {
    let mut code = vec![0x55, 0x89, 0xe5];
    for (d, &c) in (0u8..).zip(b"cmd.exe") {
        code.extend([0x31, 0xd2]); // xor edx,edx
        code.extend([0x83, 0xc2, c.wrapping_add(2)]); // add edx,c+2
        code.extend([0x83, 0xea, 0x01]); // sub edx,1
        code.extend([0x4a]); // dec edx
        code.extend([0x8b, 0x75, 0x08]); // mov esi,[ebp+8]
        code.extend([0x88, 0x56, d]); // mov byte [esi+d],dl
    }
    code.extend([0x5d, 0xc3]);
    let strings = extract_stack_strings(&code, 4, 32);
    assert!(has_stack_string(&strings, "cmd.exe"), "{strings:?}");
}

/// x86-64, a register base of unknown origin (`rdi`, the first argument):
/// `mov eax,c; mov byte [rdi+d],al`.
#[test]
fn amd64_bytes_through_register_base() {
    let mut code = Vec::new();
    for (d, &c) in (0u8..).zip(b"/bin/sh") {
        code.extend([0xb8, c, 0, 0, 0, 0x88, 0x47, d]);
    }
    code.push(0xc3);
    let strings = extract_stack_strings(&code, 4, 64);
    assert!(has_stack_string(&strings, "/bin/sh"), "{strings:?}");
}

/// An instruction the tracker does not model (`imul`) makes the register
/// unknown, so the characters after it are not stored text.
#[test]
fn unmodelled_instruction_forgets_register_values() {
    let mut code = Vec::new();
    for (d, &c) in (0u8..).zip(b"/bin/sh") {
        code.extend([0xb8, c, 0, 0, 0]); // mov eax,c
        code.extend([0x6b, 0xc0, 0x01]); // imul eax,eax,1
        code.extend([0x88, 0x47, d]); // mov byte [rdi+d],al
    }
    code.push(0xc3);
    let strings = extract_stack_strings(&code, 4, 64);
    assert!(strings.is_empty(), "{strings:?}");
}

/// MSVC's UTF-16 frame strings: `mov dword [ebp-0x10],0x0065006b` (L"ke")
/// … and a word store for the last character.
#[test]
fn i386_wide_immediates_on_the_frame() {
    let code = [
        0xc7, 0x45, 0xf0, b'k', 0, b'e', 0, // mov dword [ebp-0x10],L"ke"
        0xc7, 0x45, 0xf4, b'r', 0, b'n', 0, // mov dword [ebp-0xc],L"rn"
        0xc7, 0x45, 0xf8, b'e', 0, b'l', 0, // mov dword [ebp-8],L"el"
        0x66, 0xc7, 0x45, 0xfc, b'3', 0, // mov word [ebp-4],L"3"
        0x66, 0xc7, 0x45, 0xfe, b'2', 0, // mov word [ebp-2],L"2"
        0xc3,
    ];
    let strings = extract_stack_strings(&code, 4, 32);
    assert!(has_stack_string(&strings, "kernel32"), "{strings:?}");
}
