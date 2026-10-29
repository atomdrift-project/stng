/// Test XOR extraction of cryptocurrency wallet paths from real malware
use stng::{ExtractOptions, StringMethod};

#[test]
fn test_crypto_wallet_paths_from_brew_agent() {
    let data = crate::common::bytes("testdata/malware/brew_agent");
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    let opts = ExtractOptions::new(10)
        .with_xor(stng::XorMode::Key(key.to_vec()))
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<&str> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value.as_str())
        .collect();

    // Key wallet indicators found in DPRK malware
    // Note: Some short variants (e.g., "Wallets/Electrum" alone) may be filtered
    // as they appear with heavy trailing garbage, but their longer paths are found
    let expected_wallets = [
        ("Wallets/Guarda", "Guarda wallet"),
        ("Wallets/MyMonero", "MyMonero wallet"),
        ("Wallets/Coinomi", "Coinomi wallet"),
        ("Exodus/exodus.wallet", "Exodus wallet file"),
        ("Exodus/exodus.conf", "Exodus config"),
        (".electrum/wallets", "Electrum directory"),
        (".electron-cash/wallets", "Electron Cash directory"),
        (".sparrow/wallets", "Sparrow directory"),
        ("Monero/wallets", "Monero wallet directory"),
        (".walletwasabi", "Wasabi wallet directory"),
        ("Neon/storage/userWallet", "Neon NEO wallet"),
        ("Daedalus Mainnet/wallets", "Daedalus mainnet"),
        ("com.bitpay.wallet", "BitPay app identifier"),
        ("wallet.dat", "Generic wallet.dat file"),
    ];

    let mut found_count = 0;
    let mut missing = Vec::new();

    for (wallet_path, description) in &expected_wallets {
        let found = xor_strings.iter().any(|s| s.contains(wallet_path));

        if found {
            found_count += 1;
        } else {
            missing.push((wallet_path, description));
        }
    }

    // Print summary

    // We should find at least 75% of the expected wallet paths
    let success_rate = (found_count * 100) / expected_wallets.len();
    assert!(
        success_rate >= 75,
        "Should find at least 75% of wallet paths, found {}% ({}/{})",
        success_rate,
        found_count,
        expected_wallets.len()
    );
}

#[test]
fn test_wallet_keyword_detection() {
    // Verify that strings containing "wallet" are properly detected
    // even without exact path matches
    let data = crate::common::bytes("testdata/malware/brew_agent");
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    let opts = ExtractOptions::new(10)
        .with_xor(stng::XorMode::Key(key.to_vec()))
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let wallet_strings: Vec<&str> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .filter(|s| s.value.to_lowercase().contains("wallet"))
        .map(|s| s.value.as_str())
        .collect();

    // Should find at least 10 wallet-related strings
    assert!(
        wallet_strings.len() >= 10,
        "Should find at least 10 wallet strings, found {}",
        wallet_strings.len()
    );
}

#[test]
fn test_crypto_terms_detection() {
    // Test detection of other cryptocurrency-related terms
    let data = crate::common::bytes("testdata/malware/brew_agent");
    let key = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

    let opts = ExtractOptions::new(10)
        .with_xor(stng::XorMode::Key(key.to_vec()))
        .with_garbage_filter(true);

    let extracted = stng::extract_strings_with_options(&data, &opts);

    let xor_strings: Vec<&str> = extracted
        .iter()
        .filter(|s| s.method == StringMethod::XorDecode)
        .map(|s| s.value.as_str())
        .collect();

    // Check for various crypto-related terms that actually exist in this malware
    let crypto_terms = ["ethereum", "exodus", "electrum", "monero"];

    for term in &crypto_terms {
        let found = xor_strings.iter().any(|s| s.to_lowercase().contains(term));

        assert!(
            found,
            "Should find at least one string containing '{}' (found {} total XOR strings)",
            term,
            xor_strings.len()
        );
    }
}
