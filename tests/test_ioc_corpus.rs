#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use stng::{
    ExtractOptions, Ioc, IocKind, KeyAlgorithm, KeyMetadata, StringMethod, extract_iocs,
    extract_strings_with_options,
};

const BREW_AGENT_KEY: &[u8] = b"fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf";

#[derive(Debug)]
struct ExpectedIoc {
    kind: IocKind,
    value: &'static str,
    ports: Vec<u16>,
    count: u32,
    methods: Vec<StringMethod>,
    xor_key_bytes: Option<u32>,
}

fn expected(
    kind: IocKind,
    value: &'static str,
    ports: &[u16],
    count: u32,
    methods: &[StringMethod],
) -> ExpectedIoc {
    ExpectedIoc {
        kind,
        value,
        ports: ports.to_vec(),
        count,
        methods: methods.to_vec(),
        xor_key_bytes: None,
    }
}

fn xor_key(value: &'static str, bytes: u32, method: StringMethod) -> ExpectedIoc {
    ExpectedIoc {
        kind: IocKind::Key,
        value,
        ports: Vec::new(),
        count: 1,
        methods: vec![method],
        xor_key_bytes: Some(bytes),
    }
}

fn extract(path: &str, options: &ExtractOptions) -> Vec<Ioc> {
    let data = std::fs::read(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    let strings = extract_strings_with_options(&data, options);
    extract_iocs(&strings)
}

fn assert_exact(label: &str, path: &str, options: &ExtractOptions, expected_iocs: &[ExpectedIoc]) {
    let actual = extract(path, options);
    assert_eq!(
        actual.len(),
        expected_iocs.len(),
        "{label} IOC inventory changed:\n{actual:#?}"
    );

    for (actual, expected) in actual.iter().zip(expected_iocs) {
        assert_eq!(actual.kind, expected.kind, "{label}: {actual:#?}");
        assert_eq!(actual.value, expected.value, "{label}: {actual:#?}");
        assert_eq!(actual.ports, expected.ports, "{label}: {actual:#?}");
        assert_eq!(actual.count, expected.count, "{label}: {actual:#?}");
        assert_eq!(
            actual
                .occurrences
                .iter()
                .map(|occurrence| occurrence.method)
                .collect::<Vec<_>>(),
            expected.methods,
            "{label}: {actual:#?}"
        );

        let expected_key = expected.xor_key_bytes.map(|bytes| KeyMetadata {
            algorithms: vec![KeyAlgorithm::Xor],
            bytes,
        });
        assert_eq!(actual.key, expected_key, "{label}: {actual:#?}");

        for occurrence in &actual.occurrences {
            assert!(
                !occurrence.source_spans.is_empty()
                    && occurrence.source_spans.iter().all(|span| span[1] > 0),
                "{label}: IOC lost source provenance: {actual:#?}"
            );
            assert!(
                occurrence.value_span[1] > 0,
                "{label}: IOC has an empty decoded-value span: {actual:#?}"
            );
        }
    }
}

fn assert_empty(label: &str, path: &str, options: &ExtractOptions) {
    let actual = extract(path, options);
    assert!(
        actual.is_empty(),
        "{label} produced false-positive IOCs:\n{actual:#?}"
    );
}

/// Exact manifests are intentional here. A contains-only assertion would prove
/// recall while silently allowing new false positives into a corpus-wide index.
#[test]
fn existing_testdata_ioc_manifest_is_exact() {
    let brew = [
        expected(
            IocKind::Ip,
            "46.30.191.141",
            &[],
            2,
            &[StringMethod::XorDecode, StringMethod::XorDecode],
        ),
        xor_key(
            "base64url:Zll6dFpPUkw1Vk5TN25DVUgxa3RuNVVvSjhWU2dhZg",
            31,
            StringMethod::RawScan,
        ),
    ];
    let brew_options = || {
        ExtractOptions::new(10)
            .with_xor_key(BREW_AGENT_KEY.to_vec())
            .with_garbage_filter(true)
    };
    assert_exact(
        "sanitized Brew XOR region",
        "tests/fixtures/brew_agent_xor_region.bin",
        &brew_options(),
        &brew,
    );
    assert_exact(
        "Brew full sample",
        "testdata/malware/brew_agent",
        &brew_options(),
        &brew,
    );
    assert_exact(
        "Brew XOR sample",
        "testdata/xor/brew_agent_xor_sample",
        &brew_options(),
        &brew,
    );

    assert_exact(
        "DynamicHub ARM64 stack XOR",
        "testdata/malware/dynamichub/DynamicHub",
        &ExtractOptions::new(4),
        &[
            xor_key(
                "base64url:_xl2XZTjfm6F7E9bGjrVd3NNMmm4yKtJuedx_I52nuQ",
                32,
                StringMethod::XorStackPair,
            ),
            xor_key(
                "base64url:jRl2XZTjfm6F7E9bGjrVdw",
                16,
                StringMethod::XorStackPair,
            ),
            xor_key(
                "base64url:lHAaMfWPEk7RiT02c1S0G3NNMmm4yKtJuedx_I52nuQ",
                32,
                StringMethod::XorStackPair,
            ),
            xor_key(
                "base64url:t3nY0KxbAcWddGFykmTfqetnAjQQ80TzUZzbIObxRo8",
                32,
                StringMethod::XorStackPair,
            ),
        ],
    );

    assert_exact(
        "PoolRat",
        "testdata/malware/poolrat",
        &ExtractOptions::new(4),
        &[
            expected(
                IocKind::Hostname,
                "paxosfuture.com",
                &[],
                1,
                &[StringMethod::StackString],
            ),
            expected(
                IocKind::Path,
                "/tmp/xweb_log.md",
                &[],
                1,
                &[StringMethod::RawScan],
            ),
        ],
    );
    assert_exact(
        "ThemeForest RAT",
        "testdata/malware/themeforestrat",
        &ExtractOptions::new(4),
        &[expected(
            IocKind::Hostname,
            "paxosfuture.com",
            &[],
            1,
            &[StringMethod::StackString],
        )],
    );

    assert_exact(
        "WizardNet/QQ downloader",
        "testdata/malware/wizardnet_downloader.dll",
        &ExtractOptions::new(10),
        &[
            expected(
                IocKind::Hostname,
                "1.com",
                &[],
                1,
                &[StringMethod::WideString],
            ),
            expected(
                IocKind::Hostname,
                "c.pc.qq.com",
                &[],
                1,
                &[StringMethod::WideString],
            ),
            expected(
                IocKind::Hostname,
                "qbwupacc.imtt.qq.com",
                &[8080],
                1,
                &[StringMethod::WideString],
            ),
            expected(
                IocKind::Hostname,
                "s.pc.qq.com",
                &[],
                1,
                &[StringMethod::WideString],
            ),
            expected(
                IocKind::Hostname,
                "sc.qq.com",
                &[],
                1,
                &[StringMethod::WideString],
            ),
            expected(
                IocKind::Hostname,
                "wup.browser.qq.com",
                &[443],
                1,
                &[StringMethod::WideString],
            ),
            expected(
                IocKind::Hostname,
                "www.weiyun.com",
                &[],
                1,
                &[StringMethod::WideString],
            ),
        ],
    );

    assert_exact(
        "Kimwolf sockaddr C2",
        "testdata/malware/kimwolf_installer",
        &ExtractOptions::new(4)
            .with_r2("testdata/malware/kimwolf_installer")
            .with_garbage_filter(true),
        &[expected(
            IocKind::Ip,
            "45.139.197.87",
            &[],
            1,
            &[StringMethod::InstructionPattern],
        )],
    );
    assert_exact(
        "vget",
        "testdata/malware/vget_sample",
        &ExtractOptions::new(4),
        &[expected(
            IocKind::Hostname,
            "fixupcount.s3.dualstack.ap-northeast-1.amazonaws.com",
            &[],
            1,
            &[StringMethod::RawScan],
        )],
    );
    assert_exact(
        "wallet report",
        "testdata/macho/wallet_report_objc",
        &ExtractOptions::new(4),
        &[expected(
            IocKind::Hostname,
            "api.telegram.org",
            &[],
            1,
            &[StringMethod::RawScan],
        )],
    );
    assert_exact(
        "BrickStorm",
        "tests/testdata/brickstorm_linux_amd64",
        &ExtractOptions::new(4),
        &[
            expected(
                IocKind::Ip,
                "1.1.1.1",
                &[],
                1,
                &[StringMethod::XorStackPair],
            ),
            expected(
                IocKind::Ip,
                "149.112.112.11",
                &[],
                1,
                &[StringMethod::XorStackPair],
            ),
            expected(
                IocKind::Ip,
                "149.112.112.112",
                &[],
                1,
                &[StringMethod::XorStackPair],
            ),
            expected(
                IocKind::Ip,
                "8.8.4.4",
                &[],
                1,
                &[StringMethod::XorStackPair],
            ),
            expected(
                IocKind::Ip,
                "8.8.8.8",
                &[],
                1,
                &[StringMethod::XorStackPair],
            ),
            expected(
                IocKind::Ip,
                "9.9.9.11",
                &[],
                1,
                &[StringMethod::XorStackPair],
            ),
            expected(
                IocKind::Ip,
                "9.9.9.9",
                &[],
                1,
                &[StringMethod::XorStackPair],
            ),
            expected(
                IocKind::Hostname,
                "service.systemsvcs.com",
                &[],
                1,
                &[StringMethod::XorStackPair],
            ),
        ],
    );

    // These fixtures contain versions, code-signature hosts, compiler/runtime
    // metadata, common system paths, malformed URLs, or bare filenames, but no
    // high-confidence IOC under the conservative contract.
    for (label, path, options) in [
        (
            "clean Linux",
            "tests/testdata/hello_linux_amd64",
            ExtractOptions::new(10),
        ),
        (
            "clean Windows",
            "tests/testdata/does-nothing-windows-amd64.exe",
            ExtractOptions::new(10).with_xor(Some(10)),
        ),
        (
            "hello Windows",
            "tests/testdata/hello_windows.exe",
            ExtractOptions::new(4),
        ),
        (
            "goodboy certificate metadata",
            "testdata/malware/goodboy-stage-01.exe",
            ExtractOptions::new(4),
        ),
        (
            "sample stealer runtime paths",
            "testdata/malware/sample-stealer",
            ExtractOptions::new(4),
        ),
        (
            "sorry ransomware",
            "testdata/malware/sorry_ransomware.exe",
            ExtractOptions::new(4),
        ),
        (
            "ZyraVPN runtime paths",
            "testdata/malware/zyravpn_tun2socks.exe",
            ExtractOptions::new(4),
        ),
        (
            "KWorker malformed URL",
            "testdata/kworker_samples/kworker_obfuscated_1",
            ExtractOptions::new(4),
        ),
        (
            "ThreadRacer version and certificate metadata",
            "tests/testdata/malware/threadracer.exe",
            ExtractOptions::new(4),
        ),
        (
            "RTC clean DLL",
            "tests/testdata/rtc.dll",
            ExtractOptions::new(4),
        ),
        (
            "Go PE compiler metadata",
            "testdata/pe/gobump_windows_amd64.exe",
            ExtractOptions::new(4),
        ),
    ] {
        assert_empty(label, path, &options);
    }

    for entry in std::fs::read_dir("testdata/garble").expect("read garble corpus") {
        let entry = entry.expect("read garble entry");
        let path = entry.path();
        if !path.is_file()
            || matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("go" | "txt")
            )
        {
            continue;
        }
        let path = path.to_str().expect("UTF-8 fixture path");
        assert_empty(path, path, &ExtractOptions::new(4));
    }
}

/// Developer aid for reviewing all exact expectations when a fixture changes.
#[test]
#[ignore = "prints the complete IOC inventory for manual review"]
fn print_ioc_corpus_inventory() {
    for (name, path, options) in [
        (
            "brew-region",
            "tests/fixtures/brew_agent_xor_region.bin",
            ExtractOptions::new(10)
                .with_xor_key(BREW_AGENT_KEY.to_vec())
                .with_garbage_filter(true),
        ),
        (
            "dynamichub",
            "testdata/malware/dynamichub/DynamicHub",
            ExtractOptions::new(4),
        ),
        (
            "poolrat",
            "testdata/malware/poolrat",
            ExtractOptions::new(4),
        ),
        (
            "wizardnet",
            "testdata/malware/wizardnet_downloader.dll",
            ExtractOptions::new(10),
        ),
        (
            "brickstorm",
            "tests/testdata/brickstorm_linux_amd64",
            ExtractOptions::new(4),
        ),
    ] {
        let iocs = extract(path, &options);
        eprintln!("\n=== {name}: {} IOCs ===", iocs.len());
        for ioc in iocs {
            eprintln!("{ioc:#?}");
        }
    }
}
