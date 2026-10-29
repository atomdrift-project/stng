#[test]
fn test_goodboy_loader_detection() -> Result<(), Box<dyn std::error::Error>> {
    let output = crate::stng()
        .arg(crate::common::path("testdata/malware/goodboy-stage-01.exe"))
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("basic_loader.pdb"));
    assert!(stdout.contains("user32"));

    Ok(())
}
