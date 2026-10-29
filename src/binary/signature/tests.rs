use super::*;

const CA: &[u8] = b"Microsoft Windows Production PCA 2011";

fn put(data: &mut [u8], at: usize, bytes: &[u8]) {
    data[at..at + bytes.len()].copy_from_slice(bytes);
}

/// A PE32+ header whose certificate table covers `[0x300, 0x400)`.
fn pe() -> Vec<u8> {
    let mut data = vec![0u8; 0x400];
    put(&mut data, 0, b"MZ");
    put(&mut data, 0x3c, &0x80u32.to_le_bytes());
    put(&mut data, 0x80, b"PE\0\0");
    let optional = 0x80 + 24;
    put(&mut data, optional, &0x20bu16.to_le_bytes());
    put(&mut data, optional + 108, &16u32.to_le_bytes());
    put(&mut data, optional + 112 + 32, &0x300u32.to_le_bytes());
    put(&mut data, optional + 112 + 36, &0x100u32.to_le_bytes());
    data
}

/// A 64-bit Mach-O whose LC_CODE_SIGNATURE covers `[0x200, 0x300)`.
fn macho() -> Vec<u8> {
    let mut data = vec![0u8; 0x300];
    put(&mut data, 0, &0xfeed_facfu32.to_le_bytes());
    put(&mut data, 16, &1u32.to_le_bytes());
    for (i, word) in [0x1du32, 16, 0x200, 0x100].iter().enumerate() {
        put(&mut data, 32 + 4 * i, &word.to_le_bytes());
    }
    data
}

#[test]
fn platform_ca_counts_only_inside_the_signature() {
    let mut signed = pe();
    put(&mut signed, 0x320, CA);
    assert!(is_platform_signed(&signed));
    let mut planted = pe();
    put(&mut planted, 0x200, CA);
    assert!(
        !is_platform_signed(&planted),
        "CA name outside the certificate table"
    );

    let mut signed = macho();
    put(&mut signed, 0x210, CA);
    assert!(is_platform_signed(&signed));
    let mut planted = macho();
    put(&mut planted, 0x100, CA);
    assert!(
        !is_platform_signed(&planted),
        "CA name outside LC_CODE_SIGNATURE"
    );

    // Universal binary: one slice at 0x1000, its blob relative to the slice.
    let mut fat = vec![0u8; 0x1000];
    put(&mut fat, 0, &0xcafe_babeu32.to_be_bytes());
    put(&mut fat, 4, &1u32.to_be_bytes());
    put(&mut fat, 8 + 8, &0x1000u32.to_be_bytes());
    put(&mut fat, 8 + 12, &0x300u32.to_be_bytes());
    fat.extend(signed);
    assert!(is_platform_signed(&fat));
    assert!(!is_platform_signed(CA));
}

#[test]
fn third_party_chains_are_not_platform() {
    let signed_with = |names: &[&[u8]]| {
        let mut data = macho();
        let mut at = 0x200;
        for name in names {
            put(&mut data, at, name);
            at += name.len() + 1;
        }
        is_platform_signed(&data)
    };
    let platform: &[&[u8]] = &[
        b"Software Signing",
        b"Apple Code Signing Certification Authority",
        b"Apple Root CA",
    ];
    assert!(signed_with(platform));
    // 3CX's trojanized libffmpeg: a Developer ID chain to the same root.
    assert!(!signed_with(&[
        b"Developer ID Application: 3CX (33CF4654HL)",
        b"Developer ID Certification Authority",
        b"Apple Root CA",
    ]));

    let authenticode_with = |names: &[&[u8]]| {
        let mut data = pe();
        let mut at = 0x300;
        for name in names {
            put(&mut data, at, name);
            at += name.len() + 1;
        }
        is_platform_signed(&data)
    };
    // A vendor signature with a Microsoft timestamp countersignature.
    assert!(!authenticode_with(&[
        b"Microsoft Time-Stamp PCA 2010",
        b"Microsoft Root Certificate Authority 2010",
    ]));
    // A WHQL-attested third-party driver.
    assert!(!authenticode_with(&[
        b"Microsoft Windows Hardware Compatibility Publisher",
        b"Microsoft Windows Third Party Component CA 2014",
    ]));
}

#[test]
fn signature_walk_survives_hostile_headers() {
    let mut data = macho();
    put(&mut data, 16, &u32::MAX.to_le_bytes()); // ncmds
    put(&mut data, 32 + 4, &0u32.to_le_bytes()); // cmdsize 0
    put(&mut data, 32, &0x19u32.to_le_bytes());
    assert!(!is_platform_signed(&data));
    let mut data = pe();
    put(&mut data, 0x3c, &u32::MAX.to_le_bytes());
    assert!(!is_platform_signed(&data));
    let mut fat = vec![0u8; 64];
    put(&mut fat, 0, &0xcafe_babfu32.to_be_bytes());
    put(&mut fat, 4, &u32::MAX.to_be_bytes());
    put(&mut fat, 8 + 8, &u64::MAX.to_be_bytes());
    assert!(!is_platform_signed(&fat));
}
