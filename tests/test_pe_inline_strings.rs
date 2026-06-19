//! Regression test for inline-string recovery from Windows PE Go binaries.
//!
//! `testdata/pe/gobump_windows_amd64.exe` is a Go (GOOS=windows, GOARCH=amd64)
//! build whose `.rdata` packs string literals back-to-back without separators.
//! Several are referenced only by `LEA reg, [rip+disp]` + an immediate length
//! in `.text`, not by `{ptr,len}` data structures. Before the PE path learned
//! to follow those instruction patterns (as the ELF and Mach-O paths already
//! did), such strings surfaced only as substrings buried inside rizin's merged
//! megastrings — so the MBR-wipe command `dd if=/dev/zero of=%s bs=446 count=1`
//! was never extracted as its own string nor classified as a shell command.
//!
//! This binary requires no radare2/rizin: the boundaries come entirely from
//! stng's own instruction-pattern analysis.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use stng::{ExtractOptions, StringKind, extract_strings_with_options};

const SAMPLE: &str = "testdata/pe/gobump_windows_amd64.exe";

fn load_strings() -> Vec<stng::ExtractedString> {
    let data = std::fs::read(SAMPLE).expect("Failed to read gobump PE sample");
    // Disable r2 so the assertions exercise stng's own extraction, not rizin.
    let opts = ExtractOptions {
        min_length: 4,
        use_r2: false,
        ..Default::default()
    };
    extract_strings_with_options(&data, &opts)
}

#[test]
fn pe_inline_shell_command_recovered_without_r2() {
    if !std::path::Path::new(SAMPLE).exists() {
        eprintln!("skipping — sample missing at {SAMPLE}");
        return;
    }
    let strings = load_strings();

    // Each MBR-wipe variant must appear as its own bounded string (not merely
    // as a substring of a packed-rodata megastring) and be classified as a
    // shell command.
    let wipe_commands = [
        "dd if=/dev/zero of=%s bs=446 count=1",
        "dd if=/dev/zero of=%s bs=512 count=1",
    ];

    for &want in &wipe_commands {
        let hit = strings.iter().find(|s| s.value == want).unwrap_or_else(|| {
            panic!("inline string not recovered as its own value: {want:?}");
        });
        assert_eq!(
            hit.kind,
            Some(StringKind::ShellCmd),
            "expected {want:?} to classify as ShellCmd, got {:?}",
            hit.kind
        );
    }
}
