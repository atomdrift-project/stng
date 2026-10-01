//! Short base64 through the full extraction path.
//!
//! `decoders::tests` cover the unit behavior; these exercise the public
//! `extract_strings_with_options` that filefacts/cleave drive, with the same
//! options a source file gets there (`garbage_filter`, `caller_provides_symbols`).
//! The motivating sample is gentoo-systemd's obfuscated `configure`, which hides
//! a root/home wipe behind `base64 -d <<< L2Jpbi9ybQo=` (→ `/bin/rm`).

use stng::{ExtractOptions, StringMethod, extract_strings_with_options};

/// Options matching filefacts' source-file string extraction.
fn source_opts() -> ExtractOptions {
    ExtractOptions::new(4)
        .with_garbage_filter(true)
        .with_caller_provides_symbols(true)
}

fn decoded_values(bytes: &[u8]) -> Vec<String> {
    extract_strings_with_options(bytes, &source_opts())
        .into_iter()
        .filter(|s| s.method == StringMethod::Base64Decode)
        .map(|s| s.value.trim().to_string())
        .collect()
}

#[test]
fn gentoo_configure_decodes_bin_rm() {
    // The exact line from the sample, in a plausible script context.
    let script = b"#!/bin/bash -e\n\
        meson=${meson:-`base64 -d <<< L2Jpbi9ybQo=`}\n\
        exec ${meson} -rf build \"${args[@]}\" $HOME ~/\n";
    let decoded = decoded_values(script);
    assert!(
        decoded.iter().any(|v| v == "/bin/rm"),
        "expected decoded /bin/rm, got {decoded:?}"
    );
}

#[test]
fn short_padded_and_commanded_payloads_decode() {
    // Padding alone (no command) is enough; a decode command carries the
    // unpadded case. Each payload is too short for the old fixed embedded floor.
    for (bytes, plain) in [
        (&b"cfg=dW5hbWUgLWE="[..], "uname -a"), // padded, no command
        (&b"x := \"L2Jpbi9ybQ==\""[..], "/bin/rm"), // padded, no command
        (&b"base64 -d <<< cmVib290"[..], "reboot"), // unpadded, command vouches
    ] {
        let decoded = decoded_values(bytes);
        assert!(
            decoded.iter().any(|v| v == plain),
            "expected decoded {plain:?} from {:?}, got {decoded:?}",
            String::from_utf8_lossy(bytes)
        );
    }
}
