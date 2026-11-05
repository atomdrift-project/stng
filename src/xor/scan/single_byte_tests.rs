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
        value: "pre-decoded".to_owned(),
        data_offset: 500,
        method: StringMethod::XorDecode,
        ..Default::default()
    };
    let found = extract_custom_xor_strings_filtered_with_exclusions(
        &data,
        &[key],
        8,
        true,
        std::slice::from_ref(&(300..340)),
        vec![hint],
        false,
    );
    let values: Vec<&str> = found.iter().map(|s| s.value.as_str()).collect();
    assert!(
        values.contains(&"http://evil.example.com/payload.sh"),
        "{values:?}"
    );
    assert!(values.contains(&"pre-decoded"), "hint dropped: {values:?}");
    assert!(
        !values.iter().any(|v| v.contains("cmd.exe")),
        "excluded: {values:?}"
    );
}

#[test]
fn key_showing_through_at_any_phase_is_an_artifact() {
    let key = b"k3yPhrase";
    // Zeros XOR'd from phase 3: the key rotated by three, repeated.
    let rotated: String = (0..20)
        .map(|i| char::from(key[(i + 3) % key.len()]))
        .collect();
    assert!(super::is_xor_key_artifact(&rotated, key), "{rotated}");
    assert!(!super::is_xor_key_artifact(
        "http://c2.example/gate.php",
        key
    ));
}
