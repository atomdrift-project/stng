use super::{entry, extract};
use crate::StringMethod;
use goblin::{Object, mach::Mach};

const BASE: u64 = 0x100020000;
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn types() -> Vec<u8> {
    let mut b = vec![0; 512];
    b[23] = 22; // pointer type -> struct at +64
    put64(&mut b, 48, BASE + 64);
    b[64 + 23] = 25;
    put64(&mut b, 64 + 56, BASE + 160);
    put64(&mut b, 64 + 64, 1);
    put64(&mut b, 160, BASE + 192);
    b[192] = 2; // Name has a tag
    b[193] = 4;
    b[194..198].copy_from_slice(b"Blob");
    b[198] = 9;
    b[199..208].copy_from_slice(b"json:\"iv\"");
    b
}
// Minimal valid Mach-O with explicit reflection sections. These fixtures
// isolate metadata validation without relying on strings found elsewhere.
fn image(types: &[u8], links: &[i32], magic: u32) -> Vec<u8> {
    let links: Vec<u8> = links.iter().flat_map(|n| n.to_le_bytes()).collect();
    let magic = magic.to_le_bytes();
    let sections = [
        ("__rodata", types),
        ("__typelink", links.as_slice()),
        ("__gopclntab", magic.as_slice()),
    ];
    let size: usize = sections.iter().map(|(_, b)| b.len()).sum();
    let mut b = vec![0; 512 + size];
    for (at, v) in [
        (0, 0xfeedfacf),
        (4, 0x100000c),
        (12, 2),
        (16, 1),
        (20, 312),
        (32, 0x19),
        (36, 312),
    ] {
        put32(&mut b, at, v);
    }
    b[40..52].copy_from_slice(b"__DATA_CONST");
    put64(&mut b, 56, BASE);
    put64(&mut b, 64, size as u64);
    put64(&mut b, 72, 512);
    put64(&mut b, 80, size as u64);
    put32(&mut b, 88, 7);
    put32(&mut b, 92, 3);
    put32(&mut b, 96, 3);
    let mut off = 512;
    for (i, (name, data)) in sections.into_iter().enumerate() {
        let h = 104 + i * 80;
        b[h..h + name.len()].copy_from_slice(name.as_bytes());
        b[h + 16..h + 28].copy_from_slice(b"__DATA_CONST");
        put64(&mut b, h + 32, BASE + (off - 512) as u64);
        put64(&mut b, h + 40, data.len() as u64);
        put32(&mut b, h + 48, off as u32);
        b[off..off + data.len()].copy_from_slice(data);
        off += data.len();
    }
    b
}
fn tags(types: &[u8], links: &[i32], magic: u32, min: usize) -> Vec<crate::ExtractedString> {
    let b = image(types, links, magic);
    let Object::Mach(Mach::Binary(m)) = Object::parse(&b).unwrap() else {
        panic!("Mach-O")
    };
    extract(&m, min)
}
#[test]
fn pointer_and_direct_type_links_deduplicate_by_tag_location() {
    let found = tags(&types(), &[0, 64, 0, 64], 0xfffffff1, 4);
    assert_eq!(found.len(), 1);
    let t = &found[0];
    assert_eq!(t.value, "json:\"iv\"");
    assert_eq!(t.data_offset, BASE + 199);
    assert_eq!(t.data_len, 9);
    assert_eq!(t.method, StringMethod::Structure);
}
#[test]
fn modern_versions_and_minimum_length() {
    for magic in [0xfffffff0, 0xfffffff1] {
        assert_eq!(tags(&types(), &[0], magic, 9).len(), 1);
    }
    for magic in [0, 0xfffffffa, 0xfffffffb] {
        assert!(tags(&types(), &[0], magic, 4).is_empty());
    }
    assert!(tags(&types(), &[0], 0xfffffff1, 10).is_empty());
}
#[test]
fn invalid_type_offsets_and_pointer_cycles_do_not_recurse() {
    assert!(tags(&types(), &[-1, i32::MAX, 512], 0xfffffff1, 4).is_empty());
    for pointer in [BASE, BASE - 1, u64::MAX] {
        let mut t = types();
        put64(&mut t, 48, pointer);
        assert!(tags(&t, &[0], 0xfffffff1, 4).is_empty());
    }
}
#[test]
fn field_and_name_ranges_are_checked() {
    for (at, value) in [
        (120, BASE - 1),
        (120, BASE + 500),
        (120, u64::MAX),
        (160, BASE + 512),
        (160, u64::MAX),
    ] {
        let mut t = types();
        put64(&mut t, at, value);
        assert!(tags(&t, &[0], 0xfffffff1, 4).is_empty(), "{at}: {value:x}");
    }
}
#[test]
fn oversized_or_truncated_field_lists_are_rejected() {
    for count in [0, 4097, u64::MAX, 16] {
        let mut t = types();
        put64(&mut t, 128, count);
        assert!(tags(&t, &[0], 0xfffffff1, 4).is_empty());
    }
}
#[test]
fn malformed_name_flags_lengths_and_text_are_rejected() {
    for (at, value) in [
        (192, 0),
        (192, 0x82),
        (193, 0),
        (193, 0xff),
        (198, 0xff),
        (199, 0xff),
        (199, 0),
    ] {
        let mut t = types();
        t[at] = value;
        assert!(tags(&t, &[0], 0xfffffff1, 4).is_empty(), "{at}: {value:x}");
    }
}
#[test]
fn unsupported_word_size_and_endianness_are_rejected() {
    let b = image(&types(), &[0], 0xfffffff1);
    let Object::Mach(Mach::Binary(mut m)) = Object::parse(&b).unwrap() else {
        panic!("Mach-O")
    };
    m.is_64 = false;
    assert!(extract(&m, 4).is_empty());
    m.is_64 = true;
    m.little_endian = false;
    assert!(extract(&m, 4).is_empty());
}
#[test]
fn name_varints_check_exact_boundaries_and_truncation() {
    assert_eq!(entry(&[3, b'a', b'b', b'c'], 0), Some((1, 3)));
    assert_eq!(entry(&[0], 0), Some((1, 0)));
    for bytes in [&[][..], &[0x80], &[0x80, 0x80], &[3, b'a', b'b']] {
        assert!(entry(bytes, 0).is_none());
    }
    let mut bytes = vec![0x80, 0x20];
    bytes.resize(4098, b'a');
    assert_eq!(entry(&bytes, 0), Some((2, 4096)));
    bytes[0] = 0x81;
    bytes.push(b'a');
    assert!(entry(&bytes, 0).is_none());
    assert!(entry(&bytes, usize::MAX).is_none());
}
