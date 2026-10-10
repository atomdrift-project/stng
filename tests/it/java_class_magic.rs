//! Regression coverage for the CAFEBABE JVM/Mach-O magic collision.
#![allow(clippy::panic)]

use stng::{ExtractOptions, extract_strings_with_options};

fn minimal_java_class_with_utf8(value: &[u8]) -> Vec<u8> {
    let mut class = vec![
        0xCA, 0xFE, 0xBA, 0xBE, // magic
        0x00, 0x00, // minor version
        0x00, 0x3D, // major version 61 (Java 17)
        0x00, 0x02, // constant_pool_count
        0x01, // CONSTANT_Utf8
    ];
    let Ok(value_len) = u16::try_from(value.len()) else {
        return Vec::new();
    };
    class.extend_from_slice(&value_len.to_be_bytes());
    class.extend_from_slice(value);
    class
}

#[test]
fn java_class_magic_extracts_constant_pool_text() {
    let data = minimal_java_class_with_utf8(b"com/sun/jna/Pointer");
    let strings = extract_strings_with_options(&data, &ExtractOptions::new(4));

    assert!(
        strings.iter().any(|s| s.value == "com/sun/jna/Pointer"),
        "JVM constant-pool text must survive the CAFEBABE magic collision: {strings:?}"
    );
}

#[test]
fn fat_macho_header_is_not_mistaken_for_java() {
    let fat_header = [
        0xCA, 0xFE, 0xBA, 0xBE, // shared magic
        0x00, 0x00, 0x00, 0x02, // two Mach-O architectures, not a JVM version
        0x00, 0x00,
    ];

    // This assertion is behavioral: extraction may return nothing for the
    // deliberately truncated header, but it must remain safe and must not
    // manufacture the Java-only marker used by the positive fixture.
    let strings = extract_strings_with_options(&fat_header, &ExtractOptions::new(4));
    assert!(strings.iter().all(|s| s.value != "com/sun/jna/Pointer"));
}

#[test]
fn malformed_cafebabe_does_not_enter_fat_macho_parser() {
    let malformed = [
        0xCA, 0xFE, 0xBA, 0xBE, 0x4D, 0x11, 0xAB, 0xD4, 0x00, 0x02, 0x01,
    ];
    assert!(extract_strings_with_options(&malformed, &ExtractOptions::new(4)).is_empty());
}

#[test]
fn java_class_preserves_constant_pool_boundaries() {
    // The low byte of this entry's u2 length is printable. A raw byte scan
    // would merge it into the value; the constant-pool walk must not.
    let value = b"java/lang/String;exact-boundary-marker";
    assert!(u8::try_from(value.len()).is_ok_and(|len| len.is_ascii_graphic()));
    let data = minimal_java_class_with_utf8(value);
    let strings = extract_strings_with_options(&data, &ExtractOptions::new(4));

    assert!(
        strings
            .iter()
            .any(|s| s.value == String::from_utf8_lossy(value)),
        "{strings:?}"
    );
    assert!(strings.iter().all(|s| !s.value.starts_with('&')));
}

#[test]
fn fat_macho_with_many_slices_still_yields_strings() {
    // More than 16 architectures sends CAFEBABE down the class path, where the
    // first slice's CPU type reads as an empty constant pool. XNU runs such a
    // file, so its strings must not disappear with the pool.
    let mut data = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x11];
    for _ in 0..17 {
        data.extend_from_slice(&[
            0, 0, 0, 0x12, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0x40, 0, 0, 0, 0x0C,
        ]);
    }
    data.extend_from_slice(b"\0\0https://fat-macho-hidden-c2.ru/beacon\0");
    let strings = extract_strings_with_options(&data, &ExtractOptions::new(4));
    let hit = strings
        .iter()
        .find(|s| s.value == "https://fat-macho-hidden-c2.ru/beacon");
    let at = hit.and_then(|s| usize::try_from(s.data_offset).ok());
    assert!(
        at.and_then(|at| data.get(at..))
            .is_some_and(|rest| rest.starts_with(b"https://")),
        "{strings:?}"
    );
}
