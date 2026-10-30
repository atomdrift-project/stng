use super::*;

#[test]
#[cfg(unix)]
fn deadline_still_applies_after_stdout_closes() {
    use std::os::unix::fs::PermissionsExt;
    let input = TempInput::write(b"#!/bin/sh\nexec 1>&-\nexec /bin/sleep 30\n").unwrap();
    std::fs::set_permissions(input.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let started = std::time::Instant::now();
    assert!(
        run_tool_with_timeout(
            input.path(),
            Path::new("ignored"),
            "aaa",
            Duration::from_millis(200)
        )
        .is_none()
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
#[cfg(unix)]
fn exited_leader_cannot_leave_a_pipe_holding_descendant() {
    use std::os::unix::fs::PermissionsExt;
    let input = TempInput::write(b"#!/bin/sh\n/bin/sleep 30 &\necho '[]'\nexit 0\n").unwrap();
    std::fs::set_permissions(input.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let started = std::time::Instant::now();
    let out = run_tool_with_timeout(
        input.path(),
        Path::new("ignored"),
        "aaa",
        Duration::from_secs(3),
    );
    assert_eq!(out.as_deref(), Some("[]\n"));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn scrubbed_tool_environment_omits_secrets() {
    let mut command = Command::new("rizin");
    command.env("AWS_SECRET_ACCESS_KEY", "secret");
    scrub_env(&mut command);
    assert!(
        command
            .get_envs()
            .all(|(key, _)| key != "AWS_SECRET_ACCESS_KEY")
    );
}

#[test]
fn temp_input_is_a_private_snapshot() {
    let input = TempInput::write(b"original").unwrap();
    assert_eq!(std::fs::read(input.path()).unwrap(), b"original");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(input.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let path = input.path().to_path_buf();
    drop(input);
    assert!(!path.exists());
}

#[test]
fn extract_stack_off_multibyte_does_not_panic() {
    // Lines from r2 visual output can contain box-drawing chars like '│'
    // whose first byte spans multiple bytes — slicing &s[0..2] would
    // panic at a non-char boundary.
    assert_eq!(extract_stack_off("  │││  something"), None);
    assert_eq!(extract_stack_off("x │││││││ y"), None);
}

#[test]
fn extract_stack_off_hex_prefix() {
    // 8+ char ASCII token in second column parses as hex u8 from first 2 chars.
    assert_eq!(extract_stack_off("op 0412abcd rest"), Some(0x04));
}

#[test]
fn extract_stack_off_sp_offset() {
    assert_eq!(extract_stack_off("str w8, [sp, #0x4]"), Some(4));
}

/// A stand-in for rizin that prints `json` for any command.
#[cfg(unix)]
fn fake_tool(json: &str) -> TempInput {
    use std::os::unix::fs::PermissionsExt;
    let script = format!("#!/bin/sh\necho '{json}'\n");
    let tool = TempInput::write(script.as_bytes()).unwrap();
    std::fs::set_permissions(tool.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    tool
}

#[test]
#[cfg(unix)]
fn large_inputs_get_symbols_but_no_string_scan() {
    let tool = fake_tool(r#"[{"paddr":0,"string":"hello world","length":11,"name":"main_func"}]"#);
    let small = vec![0u8; 64];
    let session = Session::new(tool.path(), &small, false).unwrap();
    let methods: Vec<_> = extract_strings(&session, 4)
        .iter()
        .map(|s| s.method)
        .collect();
    assert_eq!(
        methods,
        [StringMethod::RizinString, StringMethod::RizinSymbol]
    );
    assert_eq!(extract_string_boundaries(&session).len(), 1);

    let large = vec![0u8; MAX_ANALYSIS_SIZE + 1];
    let session = Session::new(tool.path(), &large, false).unwrap();
    let methods: Vec<_> = extract_strings(&session, 4)
        .iter()
        .map(|s| s.method)
        .collect();
    assert_eq!(methods, [StringMethod::RizinSymbol]);
    assert!(extract_string_boundaries(&session).is_empty());
}

#[test]
#[cfg(unix)]
fn a_command_runs_once_per_session() {
    use std::os::unix::fs::PermissionsExt;
    // Each run appends a line to the log; the second request must not.
    let log = TempInput::write(b"").unwrap();
    let script = format!(
        "#!/bin/sh\necho run >> '{}'\necho '[]'\n",
        log.path().display()
    );
    let tool = TempInput::write(script.as_bytes()).unwrap();
    std::fs::set_permissions(tool.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let session = Session::new(tool.path(), b"data", false).unwrap();
    assert_eq!(
        session.run("izzj").as_deref().map(String::as_str),
        Some("[]\n")
    );
    assert_eq!(
        session.run("izzj").as_deref().map(String::as_str),
        Some("[]\n")
    );
    assert_eq!(std::fs::read_to_string(log.path()).unwrap(), "run\n");
}

#[test]
fn a_missing_tool_yields_nothing() {
    let session = Session::new(Path::new("/nonexistent/rizin"), b"data", false).unwrap();
    assert!(extract_strings(&session, 4).is_empty());
    assert!(extract_string_boundaries(&session).is_empty());
    assert!(xor_key_offsets(&session).is_empty());
    assert!(extract_connect_addrs(&session).is_empty());
}
