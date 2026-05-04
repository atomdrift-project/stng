use std::process::Command;

#[test]
fn test_goodboy_loader_detection() -> Result<(), Box<dyn std::error::Error>> {
    let stng_path = env!("CARGO_BIN_EXE_stng");

    let output = Command::new(stng_path)
        .arg("testdata/malware/goodboy-stage-01.exe")
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("basic_loader.pdb"));
    assert!(stdout.contains("user32"));

    Ok(())
}
