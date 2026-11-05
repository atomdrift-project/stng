#[test]
fn shows_loader_pdb_path_and_user32() -> Result<(), Box<dyn std::error::Error>> {
    let output = crate::stng()
        .arg(crate::common::path("testdata/malware/goodboy-stage-01.exe"))
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("basic_loader.pdb"));
    assert!(stdout.contains("user32"));

    Ok(())
}
