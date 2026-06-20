#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use stng::{ExtractOptions, StringKind, StringMethod};

#[test]
fn test_dynamichub_arm64_stack_xor_system_arg() {
    let sample_path = "testdata/malware/dynamichub/DynamicHub";
    if !std::path::Path::new(sample_path).exists() {
        eprintln!("Skipping - DynamicHub sample not found at {sample_path}");
        return;
    }

    let data = std::fs::read(sample_path).expect("failed to read DynamicHub sample");
    let opts = ExtractOptions::new(4);
    let results = stng::extract_strings_with_options(&data, &opts);

    let decoded = results
        .iter()
        .find(|s| s.value == "killall Terminal")
        .expect("missing ARM64 stack-XOR decoded system() argument");

    assert_eq!(decoded.method, StringMethod::XorStackPair);

    let xor_key = results
        .iter()
        .find(|s| s.kind == Some(StringKind::XorKey))
        .expect("missing recovered ARM64 stack-XOR key entry");

    assert_eq!(
        xor_key.value,
        "0xff19765d94e37e6e85ec4f5b1a3ad577734d3269b8c8ab49b9e771fc8e769ee4"
    );
    assert_eq!(xor_key.method, StringMethod::XorStackPair);

    for expected in [
        "dscl . -auth",
        "Library/Keychains/login.keychain",
        "BraveSoftware/Brave-Browser",
        "Cookies",
        "Login Data",
        ".electrum/wallets",
        "Exodus",
        "Atomic",
        "Monero/wallets",
        "wallet.dat",
        "Ledger Live",
        "ledger-wallet",
        "osascript -e 'display dialog \"",
    ] {
        assert!(
            results
                .iter()
                .any(|s| s.value == expected && s.method == StringMethod::XorStackPair),
            "missing broadened ARM64 stack-XOR decoded string: {expected}"
        );
    }
}
