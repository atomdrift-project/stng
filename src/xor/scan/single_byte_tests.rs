use super::*;

#[test]
fn single_byte_keys_merge_hints_and_honor_exclusions() {
    let key = 0x5a;
    let mut data = vec![0u8; 600];
    for (at, text) in [
        (100, &b"http://evil.example.com/payload.sh"[..]),
        (300, &b"C:\\Windows\\System32\\cmd.exe /c whoami"[..]),
    ] {
        for (i, &b) in text.iter().enumerate() {
            data[at + i] = b ^ key;
        }
    }
    let hint = ExtractedString {
        value: "rizin-found".to_owned(),
        data_offset: 500,
        method: StringMethod::XorDecode,
        ..Default::default()
    };
    let found = extract_custom_xor_strings_filtered_with_exclusions(
        &data,
        &[key],
        8,
        true,
        &[(300, 340)],
        vec![hint],
        false,
    );
    let values: Vec<&str> = found.iter().map(|s| s.value.as_str()).collect();
    assert!(
        values.contains(&"http://evil.example.com/payload.sh"),
        "{values:?}"
    );
    assert!(values.contains(&"rizin-found"), "hint dropped: {values:?}");
    assert!(
        !values.iter().any(|v| v.contains("cmd.exe")),
        "excluded: {values:?}"
    );
}
