use super::*;

#[test]
fn ienumerable_generic_is_not_shell() {
    // .NET generics with backticks should NOT be shell commands
    let data = minimal_pe_with_strings(&["IEnumerable`1"]);

    let strings = extract_strings(&data, 4);
    let generic = strings
        .iter()
        .find(|s| s.value == "IEnumerable`1")
        .expect("IEnumerable`1 is extracted");
    assert_ne!(
        generic.kind,
        Some(StringKind::ShellCmd),
        "IEnumerable`1 should NOT be classified as shell command"
    );
}

#[test]
fn dictionary_generic_is_not_shell() {
    let data = minimal_pe_with_strings(&["Dictionary`2"]);

    let strings = extract_strings(&data, 4);
    let generic = strings
        .iter()
        .find(|s| s.value == "Dictionary`2")
        .expect("Dictionary`2 is extracted");
    assert_ne!(
        generic.kind,
        Some(StringKind::ShellCmd),
        "Dictionary`2 should NOT be classified as shell command"
    );
}

#[test]
fn classifies_curl_as_shell() {
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
fn classifies_pipeline_as_shell() {
    let data = minimal_pe_with_strings(&["cat file | grep pattern"]);

    let strings = extract_strings(&data, 4);
    let cmd = strings
        .iter()
        .find(|s| s.value == "cat file | grep pattern")
        .expect("the pipeline is extracted");
    assert_eq!(
        cmd.kind,
        Some(StringKind::ShellCmd),
        "Pipe command should be classified as shell command"
    );
}

#[test]
fn rates_shell_high() {
    use stng::Severity;

    assert_eq!(
        StringKind::ShellCmd.severity(),
        Severity::High,
        "Shell commands should have High severity"
    );
}
