//! Code-signature checks: whether a binary carries a platform vendor's
//! signature (Apple's or Microsoft's own, not third-party developer IDs).

/// Heuristic: is this binary signed by a platform vendor (Apple, Microsoft)?
///
/// Only *platform* signatures — the chains that sign the OS itself — are
/// treated as trustworthy-enough to skip expensive pattern scans. Third-party
/// signatures (including malware that managed to get signed) are NOT matched:
///
/// - Apple: the "Software Signing" leaf issued by Apple's platform CA. Every
///   Apple chain, Developer ID included, ends in "Apple Root CA", so that name
///   proves nothing (3CX's trojanized libffmpeg carries it).
/// - Microsoft: the Windows Production PCA, which issues only Windows
///   components. Microsoft's timestamp countersignatures (rooted in "Microsoft
///   Root Certificate Authority") and WHQL-attested third-party drivers
///   ("Microsoft Windows Hardware Compatibility Publisher") do not chain to it.
///
/// Names are looked for only inside the embedded signature
/// (`signature_blobs`); anywhere else they are just bytes a sample can carry
/// to opt out of scanning. Signatures are not verified, so a binary carrying a
/// copied platform signature blob still passes.
#[must_use]
pub(crate) fn is_platform_signed(data: &[u8]) -> bool {
    signature_blobs(data).iter().any(|blob| {
        let has = |name: &[u8]| memchr::memmem::find(blob, name).is_some();
        let apple = has(b"Apple Code Signing Certification Authority")
            && has(b"Software Signing")
            && !has(b"Developer ID");
        let microsoft = has(b"Microsoft Windows Production PCA");
        apple || microsoft
    })
}

/// The code-signature data embedded in a binary: a PE's Authenticode
/// certificate table, or the `LC_CODE_SIGNATURE` blob of a Mach-O (of each
/// slice, for a universal binary). Headers are read with bounds checks, so a
/// malformed one yields fewer blobs, never a panic.
pub(super) fn signature_blobs(data: &[u8]) -> Vec<&[u8]> {
    let span = |start: u64, len: u64| {
        let start = usize::try_from(start).ok()?;
        data.get(start..start.checked_add(usize::try_from(len).ok()?)?)
    };
    let bytes = |at: usize, n: usize| data.get(at..at.checked_add(n)?);
    let u16_le = |at| Some(u16::from_le_bytes(bytes(at, 2)?.try_into().ok()?));
    let u32_le = |at| Some(u32::from_le_bytes(bytes(at, 4)?.try_into().ok()?));
    let u32_be = |at| Some(u32::from_be_bytes(bytes(at, 4)?.try_into().ok()?));
    let u64_be = |at| Some(u64::from_be_bytes(bytes(at, 8)?.try_into().ok()?));

    // LC_CODE_SIGNATURE of the thin Mach-O at `base`.
    let macho = |base: usize| -> Option<&[u8]> {
        const LC_CODE_SIGNATURE: u32 = 0x1d;
        // Inside the file, so the small offsets added below cannot overflow.
        data.get(base..)?;
        let header_len = match u32_le(base)? {
            0xfeed_face => 28,
            0xfeed_facf => 32,
            _ => return None,
        };
        let ncmds = u32_le(base + 16)?;
        let mut at = base.checked_add(header_len)?;
        for _ in 0..ncmds.min(4096) {
            let (cmd, size) = (u32_le(at)?, u32_le(at + 4)?);
            if cmd == LC_CODE_SIGNATURE {
                let (offset, len) = (u32_le(at + 8)?, u32_le(at + 12)?);
                return span(base as u64 + u64::from(offset), u64::from(len));
            }
            if size < 8 {
                return None;
            }
            at = at.checked_add(usize::try_from(size).ok()?)?;
        }
        None
    };

    match data.get(..4) {
        Some([b'M', b'Z', ..]) => {
            // Authenticode: data directory 4, whose "address" is a file offset.
            let pe = usize::try_from(u32_le(0x3c).unwrap_or(0)).unwrap_or(0);
            let optional = pe + 24;
            let directories = match (data.get(pe..pe + 4), u16_le(optional)) {
                (Some(b"PE\0\0"), Some(0x10b)) => optional + 96,
                (Some(b"PE\0\0"), Some(0x20b)) => optional + 112,
                _ => return Vec::new(),
            };
            let count = u32_le(directories - 4).unwrap_or(0);
            let entry = directories + 4 * 8;
            if count <= 4 {
                return Vec::new();
            }
            match (u32_le(entry), u32_le(entry + 4)) {
                (Some(offset), Some(len)) => span(u64::from(offset), u64::from(len))
                    .into_iter()
                    .collect(),
                _ => Vec::new(),
            }
        }
        Some([0xca, 0xfe, 0xba, 0xbe | 0xbf]) => {
            // Universal binary: big-endian slice table (64-bit offsets for 0xcafebabf).
            let wide = data[3] == 0xbf;
            let entry_len = if wide { 32 } else { 20 };
            let slices = u32_be(4).unwrap_or(0).min(64) as usize;
            (0..slices)
                .filter_map(|i| {
                    let entry = 8 + i * entry_len;
                    let offset = if wide {
                        u64_be(entry + 8)?
                    } else {
                        u64::from(u32_be(entry + 8)?)
                    };
                    macho(usize::try_from(offset).ok()?)
                })
                .collect()
        }
        _ => macho(0).into_iter().collect(),
    }
}

#[cfg(test)]
mod tests;
