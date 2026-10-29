use super::*;

/// Helper to create a minimal PE with embedded ASCII strings
fn minimal_pe_with_strings(strings: &[&str]) -> Vec<u8> {
    let mut data = vec![0u8; 1024];

    // DOS header magic
    data[0..2].copy_from_slice(&[0x4D, 0x5A]); // MZ

    // PE offset at 0x3C
    data[0x3C..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);

    // PE signature at 0x80
    data[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE\0\0

    // Embed strings starting at 0x200
    let mut offset = 0x200;
    for s in strings {
        let bytes = s.as_bytes();
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
        data[offset + bytes.len()] = 0; // null terminator
        offset += bytes.len() + 1;
    }

    data
}

#[test]
fn test_dotnet_generic_not_shell_command() {
    // .NET generics with backticks should NOT be shell commands
    let data = minimal_pe_with_strings(&["IEnumerable`1"]);

    let strings = extract_strings(&data, 4);
    let generic_string = strings.iter().find(|s| s.value == "IEnumerable`1");

    if let Some(s) = generic_string {
        assert_ne!(
            s.kind,
            Some(StringKind::ShellCmd),
            "IEnumerable`1 should NOT be classified as shell command"
        );
    }
}

#[test]
fn test_dictionary_generic_not_shell_command() {
    let data = minimal_pe_with_strings(&["Dictionary`2"]);

    let strings = extract_strings(&data, 4);
    let generic_string = strings.iter().find(|s| s.value == "Dictionary`2");

    if let Some(s) = generic_string {
        assert_ne!(
            s.kind,
            Some(StringKind::ShellCmd),
            "Dictionary`2 should NOT be classified as shell command"
        );
    }
}

#[test]
fn test_real_shell_command_detected() {
    // Real shell commands should be detected
    let data = minimal_pe_with_strings(&["curl http://example.com"]);

    let strings = extract_strings(&data, 4);
    let cmd_string = strings
        .iter()
        .find(|s| s.value == "curl http://example.com");

    assert!(cmd_string.is_some(), "Shell command should be extracted");
    assert_eq!(
        cmd_string.unwrap().kind,
        Some(StringKind::ShellCmd),
        "curl command should be classified as shell command"
    );
}

#[test]
fn test_pipe_command_detected() {
    let data = minimal_pe_with_strings(&["cat file | grep pattern"]);

    let strings = extract_strings(&data, 4);
    let cmd_string = strings
        .iter()
        .find(|s| s.value == "cat file | grep pattern");

    if let Some(s) = cmd_string {
        assert_eq!(
            s.kind,
            Some(StringKind::ShellCmd),
            "Pipe command should be classified as shell command"
        );
    }
}

#[test]
fn test_shell_command_has_high_severity() {
    use stng::Severity;

    assert_eq!(
        StringKind::ShellCmd.severity(),
        Severity::High,
        "Shell commands should have High severity"
    );
}
