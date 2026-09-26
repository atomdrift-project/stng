//! Whole-file repeating-XOR PE recovery (`stng::recover_repeating_xor_pe`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use stng::recover_repeating_xor_pe;

/// MSVC console PE32+ (AMD64), 10 KiB.
const PE: &[u8] = include_bytes!("testdata/pe_small/msvc_console_amd64.exe");
/// Unsigned .NET PE32 DLL (i386), 3 KiB.
const DOTNET_DLL: &[u8] = include_bytes!("testdata/pe_small/dotnet_unsigned_x86.dll");

fn xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .zip(key.iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect()
}

/// Deterministic pseudo-random bytes (xorshift64*), no RNG dependency.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut s = seed.max(1);
    (0..len)
        .map(|_| {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s.wrapping_mul(0x2545_f491_4f6c_dd1d).to_be_bytes()[0]
        })
        .collect()
}

fn key_of_len(len: usize, seed: u64) -> Vec<u8> {
    // A zero byte in a short key is legal but makes the "all zero" case too
    // easy to hit by accident in the length-1 test.
    noise(seed, len)
        .into_iter()
        .map(|k| if k == 0 { 0x5a } else { k })
        .collect()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn recovers_keys_of_every_tested_length() {
    for (len, seed) in [(1, 11), (4, 12), (16, 13), (32, 14), (33, 15), (64, 16)] {
        let key = key_of_len(len, seed);
        let enc = xor(PE, &key);
        let found =
            recover_repeating_xor_pe(&enc).unwrap_or_else(|| panic!("len {len} not detected"));
        assert_eq!(found.bytes(), key.as_slice(), "len {len}");
        assert_eq!(found.period(), len, "len {len}");
        assert_eq!(found.decode(&enc), PE, "len {len}");
    }
}

/// The 32-byte key of the `hvnc.enc` payload shipped inside a malicious jar.
#[test]
fn recovers_the_hvnc_sample_key() {
    let key = hex("5564ee586f83b8022fcd6064d450a4c0981ffb2d8dedf7ffad4560962406e943");
    let enc = xor(PE, &key);
    let found = recover_repeating_xor_pe(&enc).unwrap();
    assert_eq!(found.bytes(), key.as_slice());
    assert_eq!(found.period(), 32);
    assert_eq!(found.decode(&enc), PE);
}

#[test]
fn recovers_a_dword_key_with_zero_bytes() {
    // `0x000000ab` stored little-endian: its period-1 vote is all zero.
    let key = [0xab, 0x00, 0x00, 0x00];
    let found = recover_repeating_xor_pe(&xor(PE, &key)).unwrap();
    assert_eq!(found.bytes(), key.as_slice());
}

#[test]
fn reports_the_smallest_period() {
    // A 4-byte key repeated to 16 is the same encoding at period 4.
    let key = key_of_len(4, 21).repeat(4);
    let found = recover_repeating_xor_pe(&xor(PE, &key)).unwrap();
    assert_eq!(found.period(), 4);
    assert_eq!(found.bytes(), &key[..4]);
}

#[test]
fn recovers_a_dotnet_image() {
    let key = key_of_len(8, 31);
    let found = recover_repeating_xor_pe(&xor(DOTNET_DLL, &key)).unwrap();
    assert_eq!(found.bytes(), key.as_slice());
}

#[test]
fn recovers_a_borland_header_through_the_reserved_zeros() {
    // Delphi/Borland write different e_cblp/e_cp/e_ovno values and a "must be
    // run under Win32" stub; the reserved zeros still carry every residue of a
    // 32-byte key.
    let mut pe = PE.to_vec();
    pe[2..0x1c].copy_from_slice(&[
        0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0f, 0x00, 0xff, 0xff, 0x00, 0x00, 0xb8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x1a, 0x00,
    ]);
    let stub = b"\xba\x10\x00\x0e\x1f\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21\x90\x90This program must be run under Win32\r\n$7";
    pe[0x40..0x40 + stub.len()].copy_from_slice(stub);
    let key = key_of_len(32, 41);
    let found = recover_repeating_xor_pe(&xor(&pe, &key)).unwrap();
    assert_eq!(found.bytes(), key.as_slice());
}

#[test]
fn plaintext_pe_is_not_an_encoding() {
    assert_eq!(recover_repeating_xor_pe(PE), None);
    assert_eq!(recover_repeating_xor_pe(DOTNET_DLL), None);
}

#[test]
fn random_data_never_validates() {
    for seed in 1..=2000 {
        let blob = noise(seed, 4096);
        assert_eq!(recover_repeating_xor_pe(&blob), None, "seed {seed}");
    }
}

#[test]
fn zip_is_not_an_encoded_pe() {
    // Local file header, a stored member, central directory, EOCD.
    let mut zip = Vec::new();
    zip.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00\x00\x00");
    zip.extend_from_slice(&[0; 16]);
    zip.extend_from_slice(b"\x05\x00\x00\x00a.txt");
    zip.extend_from_slice(&noise(7, 512));
    zip.extend_from_slice(b"PK\x01\x02");
    zip.extend_from_slice(&[0; 42]);
    zip.extend_from_slice(b"PK\x05\x06");
    zip.extend_from_slice(&[0; 18]);
    assert_eq!(recover_repeating_xor_pe(&zip), None);
}

#[test]
fn truncated_or_tiny_input_is_rejected() {
    let key = key_of_len(4, 51);
    let enc = xor(PE, &key);
    assert_eq!(recover_repeating_xor_pe(&enc[..0x7f]), None);
    // e_lfanew points past a truncated file.
    let lfanew = u32::from_le_bytes(PE[0x3c..0x40].try_into().unwrap());
    let lfanew = usize::try_from(lfanew).unwrap();
    assert_eq!(recover_repeating_xor_pe(&enc[..lfanew + 2]), None);
    assert_eq!(recover_repeating_xor_pe(&[]), None);
}

#[test]
fn decode_round_trips() {
    let key = key_of_len(33, 61);
    let found = recover_repeating_xor_pe(&xor(PE, &key)).unwrap();
    assert_eq!(found.decode(&found.decode(PE)), PE);
    assert!(found.decode(&[]).is_empty());
}

/// Degenerate inputs never panic and never validate.
#[test]
fn degenerate_inputs_are_rejected() {
    for fill in [0x00, 0xff, b'M', 0x5a] {
        for len in [0, 1, 0x7f, 0x80, 0x81, 4096] {
            assert_eq!(
                recover_repeating_xor_pe(&vec![fill; len]),
                None,
                "{fill:#x}x{len}"
            );
        }
    }
}

/// `e_lfanew` past the end, at the edge, or at `u32::MAX` never panics.
#[test]
fn hostile_e_lfanew_is_rejected() {
    let key = key_of_len(7, 71);
    let lfanew = u32::from_le_bytes(PE[0x3c..0x40].try_into().unwrap());
    for bad in [
        0,
        0x3f,
        lfanew + 1,
        u32::try_from(PE.len()).unwrap() - 3,
        u32::MAX,
    ] {
        let mut pe = PE.to_vec();
        pe[0x3c..0x40].copy_from_slice(&bad.to_le_bytes());
        assert_eq!(recover_repeating_xor_pe(&xor(&pe, &key)), None, "{bad:#x}");
    }
}

#[test]
fn recovers_odd_periods() {
    for (len, seed) in [(3, 81), (7, 82), (13, 83), (63, 84)] {
        let key = key_of_len(len, seed);
        let found = recover_repeating_xor_pe(&xor(DOTNET_DLL, &key)).unwrap();
        assert_eq!(found.bytes(), key.as_slice(), "len {len}");
    }
}

/// The XOR scan surfaces the key the way it surfaces any detected key, and
/// the IOC pass records its bytes, not its `0x<hex>` rendering.
#[test]
fn xor_scan_surfaces_the_key() {
    let key = hex("5564ee586f83b8022fcd6064d450a4c0981ffb2d8dedf7ffad4560962406e943");
    let enc = xor(PE, &key);
    let opts = stng::ExtractOptions::new(4).with_xor(None);
    let strings = stng::extract_strings_with_options(&enc, &opts);
    let found: Vec<_> = strings
        .iter()
        .filter(|s| s.kind == Some(stng::StringKind::XorKey))
        .collect();
    assert_eq!(found.len(), 1, "{found:?}");
    let s = found[0];
    assert_eq!(
        s.value,
        format!(
            "0x{}",
            "5564ee586f83b8022fcd6064d450a4c0981ffb2d8dedf7ffad4560962406e943"
        )
    );
    assert_eq!((s.data_offset, s.data_len), (0, 0x80));
    assert_eq!(s.method, stng::StringMethod::XorRepeatingKey);

    let iocs = stng::extract_iocs(&strings);
    let keys: Vec<_> = iocs
        .iter()
        .filter(|i| i.kind == stng::IocKind::Key)
        .collect();
    assert_eq!(keys.len(), 1, "{keys:?}");
    assert_eq!(keys[0].value, stng::encode_key_material(&key));

    // Without the XOR scan nothing is surfaced.
    let plain = stng::extract_strings_with_options(&enc, &stng::ExtractOptions::new(4));
    assert!(
        !plain
            .iter()
            .any(|s| s.kind == Some(stng::StringKind::XorKey))
    );
}

/// Recovery cost is fixed: a large non-PE input takes as long as a small one.
#[test]
fn cost_is_independent_of_size() {
    let big = noise(91, 64 << 20);
    let start = std::time::Instant::now();
    for _ in 0..100 {
        assert_eq!(recover_repeating_xor_pe(std::hint::black_box(&big)), None);
    }
    let per_call = start.elapsed() / 100;
    eprintln!("recover_repeating_xor_pe on 64 MiB of noise: {per_call:?}/call");
    assert!(
        per_call < std::time::Duration::from_millis(5),
        "{per_call:?}"
    );
}

/// The straightforward algorithm the library evaluates lazily: vote every
/// key byte of a period, then validate. Kept here as the specification.
fn reference(data: &[u8]) -> Option<Vec<u8>> {
    const HEADER: &[u8; 0x1c] = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00";
    const STUB: &[u8] =
        b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$";
    let template: Vec<(u8, u32)> = (0..0x80)
        .map(|i| match i {
            0 | 1 => (HEADER[i], 8),
            0x02..0x1c => (HEADER[i], 1),
            0x1c..0x3c => (0, 4),
            0x3c..0x40 => (0, 0),
            0x40..0x79 => (STUB[i - 0x40], 1),
            _ => (0, 1),
        })
        .collect();
    let validates = |key: &[u8]| {
        let dec = |off: usize, n: usize| -> Option<Vec<u8>> {
            let src = data.get(off..off.checked_add(n)?)?;
            Some(
                src.iter()
                    .enumerate()
                    .map(|(i, b)| b ^ key[(off + i) % key.len()])
                    .collect(),
            )
        };
        let Some(lf) = dec(0x3c, 4) else { return false };
        let lf = u32::from_le_bytes(lf.try_into().unwrap()) as usize;
        let word = |off: usize| dec(off, 2).map(|w| u16::from_le_bytes([w[0], w[1]]));
        dec(0, 2).as_deref() == Some(b"MZ")
            && lf >= 0x40
            && dec(lf, 4).as_deref() == Some(b"PE\0\0")
            && word(lf + 4)
                .is_some_and(|m| [0x014c, 0x8664, 0xaa64, 0x01c4, 0x01c0, 0x0200].contains(&m))
            && word(lf + 24).is_some_and(|m| m == 0x010b || m == 0x020b)
    };
    if data.len() < 0x80 || validates(&[0]) {
        return None;
    }
    for period in 1..=64 {
        let key: Vec<u8> = (0..period)
            .map(|r| {
                let mut tally: Vec<(u8, u32)> = Vec::new();
                for pos in (r..0x80).step_by(period) {
                    let (plain, w) = template[pos];
                    if w == 0 {
                        continue;
                    }
                    let c = data[pos] ^ plain;
                    match tally.iter_mut().find(|(k, _)| *k == c) {
                        Some(e) => e.1 += w,
                        None => tally.push((c, w)),
                    }
                }
                let mut best = (0, 0);
                for &(k, w) in &tally {
                    if w > best.1 {
                        best = (k, w);
                    }
                }
                best.0
            })
            .collect();
        if key.iter().any(|&k| k != 0) && validates(&key) {
            return Some(key);
        }
    }
    None
}

/// The lazy evaluation accepts exactly what the reference accepts, on inputs
/// built to sit near the acceptance boundary: encoded images with scrambled
/// header bytes, a few random low-entropy keys, and noise.
#[test]
fn lazy_recovery_matches_the_reference() {
    let mut accepted = 0;
    for seed in 1..=3000u64 {
        let r = noise(seed, 8);
        let base = if r[0] & 1 == 0 { PE } else { DOTNET_DLL };
        let len = 1 + usize::from(r[1]) % 64;
        // Low-entropy keys make ties and zero bytes common.
        let key: Vec<u8> = noise(seed ^ 0x55, len).iter().map(|k| k & r[2]).collect();
        let mut plain = base.to_vec();
        let lfanew = u32::from_le_bytes(base[0x3c..0x40].try_into().unwrap()) as usize;
        for (i, &b) in noise(seed ^ 0xaa, usize::from(r[3] % 8)).iter().enumerate() {
            let at = match i % 3 {
                0 => usize::from(b) % 0x80,
                1 => lfanew + usize::from(b) % 26,
                _ => usize::from(b) % 0x40 + 0x1c,
            };
            plain[at] = noise(seed + i as u64, 1)[0];
        }
        let enc = xor(&plain, &key);
        let got = recover_repeating_xor_pe(&enc).map(|k| k.bytes().to_vec());
        assert_eq!(got, reference(&enc), "seed {seed}");
        accepted += usize::from(got.is_some());
        let blob = noise(seed, 512);
        assert_eq!(
            recover_repeating_xor_pe(&blob).map(|k| k.bytes().to_vec()),
            reference(&blob)
        );
    }
    // The corpus must exercise both outcomes.
    assert!((500..3000).contains(&accepted), "{accepted}");
}
