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
