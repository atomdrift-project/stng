//! Detection and extraction of overlay/appended data after binary boundaries.

use crate::binary::RangeSet;
use crate::classifier::classify_string;
use crate::raw::{PrintableRunContext, extract_printable_runs, extract_wide_strings};
use crate::types::{ExtractedString, OverlayInfo, StringKind};
use std::collections::HashSet;

/// Detect overlay/appended data after an ELF binary.
///
/// Malware often appends encrypted payloads or configuration after the ELF structure.
/// This function identifies data beyond the normal ELF boundaries.
#[must_use]
pub fn detect_elf_overlay(data: &[u8]) -> Option<OverlayInfo> {
    let elf = goblin::elf::Elf::parse(data).ok()?;
    elf_overlay(&elf, data)
}

/// The data appended after the image of a parsed ELF or PE: none for other
/// formats, or when nothing follows the image.
#[must_use]
pub fn detect_overlay(object: &goblin::Object<'_>, data: &[u8]) -> Option<OverlayInfo> {
    match object {
        goblin::Object::Elf(elf) => elf_overlay(elf, data),
        goblin::Object::PE(pe) => pe_overlay(pe, data),
        _ => None,
    }
}

/// The bytes after an ELF's last segment, section and header table.
/// `.bss` and other NOBITS sections occupy no file bytes, so they do not
/// extend the image.
pub(crate) fn elf_overlay(elf: &goblin::elf::Elf<'_>, data: &[u8]) -> Option<OverlayInfo> {
    let header_size = if elf.is_64 { 64u64 } else { 52 };
    let segments = elf
        .program_headers
        .iter()
        .map(|ph| ph.p_offset.saturating_add(ph.p_filesz));
    let sections = elf
        .section_headers
        .iter()
        .filter(|sh| sh.sh_type != goblin::elf::section_header::SHT_NOBITS)
        .map(|sh| sh.sh_offset.saturating_add(sh.sh_size));
    let section_table = (elf.header.e_shoff > 0).then(|| {
        elf.header.e_shoff.saturating_add(
            u64::from(elf.header.e_shnum).saturating_mul(u64::from(elf.header.e_shentsize)),
        )
    });
    let end = segments
        .chain(sections)
        .chain(section_table)
        .fold(header_size, u64::max);
    overlay_after(end, data.len() as u64)
}

/// The bytes after a PE's headers and last section's raw data. An
/// Authenticode certificate table there is signature, not overlay: data
/// after it is the overlay.
pub(crate) fn pe_overlay(pe: &goblin::pe::PE<'_>, data: &[u8]) -> Option<OverlayInfo> {
    let headers = pe
        .header
        .optional_header
        .map_or(0, |o| u64::from(o.windows_fields.size_of_headers));
    // Without section data there is no image for anything to follow.
    let mut end = pe
        .sections
        .iter()
        .filter(|s| s.size_of_raw_data > 0)
        .map(|s| u64::from(s.pointer_to_raw_data).saturating_add(u64::from(s.size_of_raw_data)))
        .max()?
        .max(headers);
    // The certificate table's "address" is a file offset. Entries are
    // 8-byte aligned, so a table that starts within that padding follows
    // the image directly.
    if let Some(cert) = pe
        .header
        .optional_header
        .and_then(|o| o.data_directories.get_certificate_table().copied())
    {
        let start = u64::from(cert.virtual_address);
        if start >= end && start <= end.next_multiple_of(8) && cert.size > 0 {
            end = start.saturating_add(u64::from(cert.size));
        }
    }
    overlay_after(end, data.len() as u64)
}

/// The overlay from `end` to the end of a `len`-byte file, if it holds at
/// least 16 bytes: less is alignment padding.
fn overlay_after(end: u64, len: u64) -> Option<OverlayInfo> {
    let size = len.checked_sub(end)?;
    (size >= 16).then_some(OverlayInfo {
        start_offset: end,
        size,
    })
}

/// Extract strings from overlay/appended data after binary boundaries.
///
/// Malware often hides encrypted payloads or configuration in overlay data.
/// This function extracts both ASCII and wide (UTF-16LE) strings from overlay regions.
#[must_use]
pub fn extract_overlay_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let overlay = match goblin::Object::parse(data) {
        Ok(goblin::Object::Elf(elf)) => elf_overlay(&elf, data),
        Ok(goblin::Object::PE(pe)) => pe_overlay(&pe, data),
        _ => None,
    };
    overlay.map_or_else(Vec::new, |overlay| {
        overlay_strings(data, &overlay, min_length)
    })
}

/// The ASCII and UTF-16LE strings in `overlay`, at file offsets and typed
/// as overlay data unless the classifier has more specific evidence.
pub(crate) fn overlay_strings(
    data: &[u8],
    overlay: &OverlayInfo,
    min_length: usize,
) -> Vec<ExtractedString> {
    let Some(bytes) = crate::binary::file_range_clamped(data, overlay.start_offset, overlay.size)
    else {
        return Vec::new();
    };
    let mut strings = Vec::new();
    extract_printable_runs(
        bytes,
        PrintableRunContext {
            min_length,
            segment_names_set: &HashSet::new(),
            skip_ranges: &RangeSet::default(),
        },
        &mut strings,
        &mut HashSet::new(),
    );
    for s in &mut strings {
        s.kind = Some(overlay_kind(&s.value, StringKind::Overlay));
    }
    strings.extend(
        extract_wide_strings(bytes, min_length, &[], &[])
            .into_iter()
            .map(|mut s| {
                s.kind = Some(overlay_kind(&s.value, StringKind::OverlayWide));
                s
            }),
    );
    for s in &mut strings {
        s.rebase(overlay.start_offset);
    }
    strings
}

/// The kind of a string found in an overlay: the classifier's kind when it
/// is specific evidence (encoded data, crypto, network indicators, commands),
/// `otherwise` for anything else.
fn overlay_kind(value: &str, otherwise: StringKind) -> StringKind {
    match classify_string(value) {
        Some(
            kind @ (StringKind::Base32
            | StringKind::Base58
            | StringKind::Base64
            | StringKind::Base85
            | StringKind::CryptoWallet
            | StringKind::MiningPool
            | StringKind::Ip
            | StringKind::IpPort
            | StringKind::Hostname
            | StringKind::Url
            | StringKind::Email
            | StringKind::TorAddress
            | StringKind::ShellCmd
            | StringKind::SuspiciousPath
            | StringKind::XorKey
            | StringKind::HexEncoded
            | StringKind::ApiKey
            | StringKind::Jwt
            | StringKind::CtfFlag),
        ) => kind,
        _ => otherwise,
    }
}
