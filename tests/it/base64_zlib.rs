#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Regressions through the public decoder, library extraction and CLI paths.
use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::{Compression, write::ZlibEncoder};
use std::{
    fs,
    io::Write,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};
use stng::{ExtractOptions, ExtractedString, StringMethod};

fn encode(text: &str) -> String {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(text.as_bytes()).unwrap();
    STANDARD.encode(encoder.finish().unwrap())
}

fn options(filtered: bool) -> ExtractOptions {
    ExtractOptions::new(4)
        .with_garbage_filter(filtered)
        .with_caller_provides_symbols(true)
}

fn cli_strings(source: &str) -> Vec<ExtractedString> {
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "stng-base64-zlib-{}-{}.txt",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&path, source).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_stng"))
        .args([
            "--json",
            "--unfiltered",
            "--no-xor",
            "--no-r2",
            "--no-cache",
        ])
        .arg(&path)
        .output();
    fs::remove_file(&path).unwrap();
    let output = output.unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn base64_zlib_aliased_python_wrapper_yields_whole_module() {
    // Same wrapper shape as all 16 ameva_cluster modules. Do not execute it.
    let payload = "import os\n\ndef main():\n    print('decoded module')\n\nif __name__ == '__main__':\n    main()\n";
    let encoded = encode(payload);
    let prefix = "# café\nimport zlib as _z, base64 as _b\nexec(_z.decompress(_b.b64decode('";
    let src = format!("{prefix}{encoded}')).decode('utf-8'), globals())\n");
    for filtered in [false, true] {
        let strings = stng::extract_strings_with_options(src.as_bytes(), &options(filtered));
        let decoded = strings
            .iter()
            .find(|s| s.method == StringMethod::Base64Decode && s.value == payload.trim())
            .unwrap();
        assert_eq!(decoded.data_offset, prefix.len() as u64);
        assert_eq!(decoded.data_len as usize, encoded.len());
        assert_eq!(
            &src[usize::try_from(decoded.data_offset).unwrap()..][..decoded.data_len as usize],
            encoded
        );
    }
}

#[test]
fn base64_zlib_is_filetype_agnostic() {
    let payload = "print('not tied to Python syntax')\n";
    let encoded = encode(payload);
    for source in [
        encoded.clone(),
        format!("{{\"payload\":\"{encoded}\"}}"),
        format!("const payload = '{encoded}';"),
        format!("payload='{encoded}'\n"),
    ] {
        let strings = stng::extract_strings_with_options(source.as_bytes(), &options(true));
        assert!(strings.iter().any(|s| s.method == StringMethod::Base64Decode && s.value.trim() == payload.trim()));
    }
    let mut binary = b"\0\xff\x01binary\0".to_vec();
    let offset = binary.len();
    binary.extend(encoded.as_bytes());
    binary.extend(b"\0\xff\0");
    let strings = stng::extract_strings_with_options(&binary, &options(true));
    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode && s.value.trim() == payload.trim())
        .unwrap();
    assert_eq!(decoded.data_offset, offset as u64);
    assert_eq!(decoded.data_len as usize, encoded.len());
}

#[test]
fn base64_zlib_public_decoder_recovers_unicode_source_exactly() {
    let payload = "# 日本語 🦀\nprint('café')\n";
    let encoded = encode(payload);
    let source = ExtractedString {
        value: encoded.clone(),
        data_offset: 4096,
        data_len: u32::try_from(encoded.len()).unwrap(),
        ..Default::default()
    };
    let strings = stng::decode_encoded_strings(&[source]);
    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode && s.value == payload)
        .unwrap();
    assert_eq!(
        decoded.source_spans().collect::<Vec<_>>(),
        vec![(4096, encoded.len() as u64)]
    );
}

#[test]
fn base64_zlib_cli_text_path_emits_decoded_payload_and_provenance() {
    let payload = "print('CLI zlib regression')\n";
    let encoded = encode(payload);
    let strings = cli_strings(&format!("blob='{encoded}'\n"));
    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode && s.value.trim() == payload.trim())
        .unwrap();
    assert_eq!(decoded.data_offset, 6);
    assert_eq!(decoded.data_len as usize, encoded.len());
}

#[test]
fn base64_zlib_cli_spans_account_for_crlf_and_leading_whitespace() {
    let payload = "print('correct byte spans')\n";
    let encoded = encode(payload);
    for prefix in ["# café\n   blob='", "# café\r\n \tblob='"] {
        let source = format!("{prefix}{encoded}'\r\n");
        let strings = cli_strings(&source);
        let decoded = strings
            .iter()
            .find(|s| s.method == StringMethod::Base64Decode && s.value.trim() == payload.trim())
            .unwrap();
        assert_eq!(decoded.data_offset, prefix.len() as u64);
        assert_eq!(
            &source.as_bytes()[usize::try_from(decoded.data_offset).unwrap()..]
                [..decoded.data_len as usize],
            encoded.as_bytes()
        );
    }
}

#[test]
fn base64_zlib_real_ameva_main_wrapper_regression() {
    // Exact compressed literal from ameva_cluster 1.0.1 __main__.py. The
    // surrounding import aliases and globals() defeated the old script path.
    const ENCODED: &str = "eNoljEEKwCAQxO6+Ym/qxQcUfMsgorDgalFb2t9XaY4hhOVsfdJ4h8q9CQVJd0As15ipu1iY+C8kcFWcCairAch70sDWgD4ULdbFpYen2dZY+wEzFh/b";
    let payload = "import sys\nfrom ameva_cluster.cli import main\nif __name__ == '__main__':\n    sys.exit(main())";
    let prefix = "import zlib as _z, base64 as _b\r\nexec(_z.decompress(_b.b64decode('";
    let wrapper = format!("{prefix}{ENCODED}')).decode('utf-8'), globals())\r\n");
    let strings = stng::extract_strings_with_options(wrapper.as_bytes(), &options(true));
    let decoded = strings
        .iter()
        .find(|s| s.method == StringMethod::Base64Decode && s.value == payload)
        .unwrap();
    assert_eq!(decoded.data_offset, prefix.len() as u64);
    assert_eq!(decoded.data_len as usize, ENCODED.len());
}
