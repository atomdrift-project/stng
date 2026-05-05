//! Integration tests covering five extractor regressions surfaced by
//! `testdata/malware/zyravpn_tun2socks.exe` (bundled with the ZyraPrivateVPN
//! dropper). The sample is the OSS Go project github.com/xjasonlyu/tun2socks
//! built with go1.20.11, GOOS=windows, GOARCH=amd64.
//!
//! 1. Buildinfo varint length-prefix bleeds into module-path strings.
//! 2. Win32 API names assembled via `mov r, imm64` + `mov [rsp+N], r` are
//!    not reassembled into the full API name.
//! 3. Garbage 4–6 char fragments from x86 instruction bytes leak through
//!    the `.text` filter.
//! 4. 16-byte windows of `.text` matched as `{ptr,len}` structures emit
//!    mid-string fragments of strings whose full versions are already in
//!    the funcnametab.
//! 5. Tightly packed Go string pools surface as one concatenated megastring
//!    when individual `{ptr,len}` boundaries are missed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use stng::{extract_strings, ExtractedString};

const SAMPLE: &str = "testdata/malware/zyravpn_tun2socks.exe";

fn load_strings() -> Vec<ExtractedString> {
    let data = std::fs::read(SAMPLE).expect("Failed to read tun2socks sample");
    extract_strings(&data, 4)
}

fn values(strings: &[ExtractedString]) -> Vec<&str> {
    strings.iter().map(|s| s.value.as_str()).collect()
}

// --------------------------------------------------------------------------
// Issue 1: buildinfo varint length-prefix bleeds in
// --------------------------------------------------------------------------

#[test]
fn issue1_buildinfo_no_varint_prefix() {
    if !std::path::Path::new(SAMPLE).exists() {
        eprintln!("skipping — sample missing at {SAMPLE}");
        return;
    }
    let strings = load_strings();
    let vals = values(&strings);

    // The Go pkgnamestab packs paths with a single-byte varint length
    // prefix. The clean string MUST appear; the prefixed form must NOT.
    let cases: &[&str] = &[
        "go.uber.org/automaxprocs/maxprocs",  // 33 chars, prefix 0x21 '!'
        "gvisor.dev/gvisor/pkg/atomicbitops", // 34 chars, prefix 0x22 '"'
        "vendor/golang.org/x/net/http2/hpack", // 35 chars, prefix 0x23 '#'
        "golang.org/x/crypto/chacha20poly1305", // 36 chars, prefix 0x24 '$'
        "github.com/xjasonlyu/tun2socks/v2/log", // 37 chars, prefix 0x25 '%'
        "github.com/xjasonlyu/tun2socks/v2/core", // 38 chars, prefix 0x26 '&'
        "github.com/xjasonlyu/tun2socks/v2/proxy", // 39 chars, prefix 0x27 '\''
        "github.com/xjasonlyu/tun2socks/v2/dialer", // 40 chars, prefix 0x28 '('
        "github.com/Dreamacro/go-shadowsocks2/core", // 41 chars, prefix 0x29 ')'
    ];

    for &want in cases {
        assert!(
            vals.contains(&want),
            "missing clean buildinfo string: {want:?}"
        );
        let prefix = char::from(u8::try_from(want.len()).unwrap());
        let prefixed = format!("{prefix}{want}");
        assert!(
            !vals.iter().any(|v| *v == prefixed),
            "found prefixed form (varint byte not stripped): {prefixed:?}"
        );
    }
}

// --------------------------------------------------------------------------
// Issue 2: stack-constructed Win32 API names not reassembled
// --------------------------------------------------------------------------

#[test]
fn issue2_stack_strings_assemble_win32_apis() {
    if !std::path::Path::new(SAMPLE).exists() {
        eprintln!("skipping — sample missing at {SAMPLE}");
        return;
    }
    let strings = load_strings();
    let vals = values(&strings);

    // Each of these is built with several `mov rdx, imm64; mov [rsp+N], rdx`
    // instructions whose 8-byte immediates are contiguous/overlapping ASCII.
    // The full API name should appear somewhere in the extracted set.
    let expected = [
        "AddDllDirectory",
        "AddVectoredContinueHandler",
        "AddVectoredExceptionHandler",
        "RegisterSuspendResumeNotification",
        "QueryPerformanceCounter",
        "QueryPerformanceFrequency",
        "timeBeginPeriod",
        "timeEndPeriod",
        "GetSystemTimeAsFileTime",
    ];
    for &want in &expected {
        assert!(
            vals.iter().any(|v| v.contains(want)),
            "missing stack-assembled Win32 API name: {want:?}"
        );
    }
}

// --------------------------------------------------------------------------
// Issue 3: x86 register-encoding fragments leaking through filter
// --------------------------------------------------------------------------

#[test]
fn issue3_no_x86_register_garbage() {
    if !std::path::Path::new(SAMPLE).exists() {
        eprintln!("skipping — sample missing at {SAMPLE}");
        return;
    }
    let strings = load_strings();
    let vals = values(&strings);

    // These are bytes from `cmp r/m64, r64` (0x48 0x39 = 'H' '9'),
    // `pop rcx` (0x59 = 'Y'), REX-prefixed encodings, etc. They leaked
    // through despite the d02546a register-save filter.
    let garbage = [
        "KYKZ", "CYEF", "CYBS", "IYGT", "IYNW", "QXA9", "CYMT", "IYRX", "KYXS", "KYUQ", "KZV3",
        "KYFG", "FH9Y", "ZPH9", "PPH9", "R0H9", "N0H9", "S8H9", "V0H9", "K0M9", "L9N0", "X0H9",
        "Q0H9", "Q8H9", "H9A8", "A8I9", "H9QP", "9H9Z", "R8L9", "Q0H9Q", "KYP5", "I9F0", "Q0H9",
        "5PDA", "D9BX", "H9B8", "H9H8", "ZFM9", "YO09", "3YEV", "u7z5", "YDU7", "YNK7", "YSF9",
        "YRB9", "YQZ6", "FH9Y",
    ];
    for &g in &garbage {
        assert!(!vals.contains(&g), "x86 register garbage leaked: {g:?}");
    }
}

// --------------------------------------------------------------------------
// Issue 4: mid-string fragments from cmp-imm structure false positives
// --------------------------------------------------------------------------

#[test]
fn issue4_no_mid_string_funcname_fragments() {
    if !std::path::Path::new(SAMPLE).exists() {
        eprintln!("skipping — sample missing at {SAMPLE}");
        return;
    }
    let strings = load_strings();
    let vals = values(&strings);

    // The Go runtime has dispatch code that compares the first 4/8 bytes
    // of a function name against an immediate. Stng's structure scanner
    // matches 16-byte windows in `.text` and emits these truncated fragments.
    // The clean strings exist elsewhere and should be the only versions.
    let fragments = [
        "debugCal", "l128", "l256f", "l512", "l102u", "l204", "l409u", "l819uq", "l163u", "l327u",
        "l655u",
    ];
    for &f in &fragments {
        assert!(
            !vals.contains(&f),
            "mid-string funcname fragment leaked: {f:?}"
        );
    }

    // Sanity: the full versions ARE present (Go funcnametab stores
    // `debugCallNNN` bare and `runtime.debugCallV2` qualified).
    for full in [
        "debugCall128",
        "debugCall256",
        "debugCall512",
        "debugCall1024",
        "debugCall65536",
        "runtime.debugCallV2",
    ] {
        assert!(
            vals.contains(&full),
            "expected full funcname missing: {full:?}"
        );
    }
}

// --------------------------------------------------------------------------
// Issue 5: concatenated megastrings when string-pool boundaries are missed
// --------------------------------------------------------------------------

#[test]
fn issue5_no_concatenated_megastrings() {
    if !std::path::Path::new(SAMPLE).exists() {
        eprintln!("skipping — sample missing at {SAMPLE}");
        return;
    }
    let strings = load_strings();
    let vals = values(&strings);

    // These signature substrings are pairs of unrelated strings concatenated
    // because the pclntab funcnametab/strtab boundaries weren't recovered.
    // Each should appear as two separate strings, never as one blob.
    let bad_concats = [
        "AddDllDirectoryCLSIDFromString",
        "Accept-EncodingAccept-Language",
        "ASCII_Hex_DigitAccept-Encoding",
        "QueryValueExWRemoveDirectory",
        "RtlGetCurrentPebSETTINGS",
        "GetCurrentDirectoryWGetFileAttributes",
        "CreateMutexWECDSA-SHA256",
        "ECDSA-SHA256ECDSA-SHA384",
    ];
    for &substr in &bad_concats {
        assert!(
            !vals.iter().any(|v| v.contains(substr)),
            "concatenated megastring leaked, contained {substr:?}"
        );
    }

    // Sanity: each individual constituent should still surface separately.
    // (Some packed-pool strings like `RemoveDirectoryW` are only reachable
    // via the offset table inside pclntab — out of scope for this test.)
    for indiv in [
        "AddDllDirectory",
        "Accept-Encoding",
        "Accept-Language",
        "ECDSA-SHA256",
        "ECDSA-SHA384",
        "ECDSA-SHA512",
    ] {
        assert!(
            vals.contains(&indiv),
            "individual string missing: {indiv:?}"
        );
    }
}
