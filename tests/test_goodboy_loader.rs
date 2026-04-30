use std::process::Command;

#[test]
fn test_goodboy_loader_detection() {
    let stng_path = "./out/stng";
    
    // Test for the specific XOR payload strings we expect
    let output = Command::new(stng_path)
        .arg("testdata/malware/goodboy-stage-01.exe")
        .output()
        .expect("failed to execute stng");

    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // With the new high-performance XOR detection, these SHOULD be found
    assert!(stdout.contains("GoodBoy"), "Should contain 'GoodBoy' after new XOR detection implementation");
    assert!(stdout.contains("user32.dll"), "Should contain 'user32.dll' after new XOR detection implementation");
}
