//! Detection and extraction of overlay/appended data after binary boundaries.

use crate::go::classifier::classify_string;
use crate::raw::{extract_printable_runs, extract_wide_strings};
use crate::types::{ExtractedString, OverlayInfo, StringKind};
use std::collections::HashSet;

/// Detect overlay/appended data after an ELF binary.
///
/// Malware often appends encrypted payloads or configuration after the ELF structure.
/// This function identifies data beyond the normal ELF boundaries.
pub fn detect_elf_overlay(data: &[u8]) -> Option<OverlayInfo> {
    let Ok(elf) = goblin::elf::Elf::parse(data) else {
        return None;
    };

    // Find the highest file offset used by any program or section header
    // Start with the ELF header size as minimum (64 bytes for 64-bit, 52 for 32-bit)
    let header_size = if elf.is_64 { 64u64 } else { 52u64 };
    let mut max_offset: u64 = header_size;

    // Check program headers (segments)
    for ph in &elf.program_headers {
        let end = ph.p_offset + ph.p_filesz;
        if end > max_offset {
            max_offset = end;
        }
    }

    // Check section headers
    for sh in &elf.section_headers {
        let end = sh.sh_offset + sh.sh_size;
        if end > max_offset {
            max_offset = end;
        }
    }

    // Also check for section header table position (often at the end of the file)
    if elf.header.e_shoff > 0 {
        let sh_table_end =
            elf.header.e_shoff + u64::from(elf.header.e_shnum) * u64::from(elf.header.e_shentsize);
        if sh_table_end > max_offset {
            max_offset = sh_table_end;
        }
    }

    // If there's data after the highest offset, it's overlay/appended data
    // Require at least 16 bytes to avoid false positives from padding
    let overlay_start = max_offset as usize;
    let overlay_size = data.len().saturating_sub(overlay_start);
    if overlay_size >= 16 {
        Some(OverlayInfo {
            start_offset: max_offset,
            size: overlay_size as u64,
        })
    } else {
        None
    }
}

/// Extract strings from overlay/appended data after binary boundaries.
///
/// Malware often hides encrypted payloads or configuration in overlay data.
/// This function extracts both ASCII and wide (UTF-16LE) strings from overlay regions.
pub fn extract_overlay_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();

    // Try ELF overlay detection
    if let Some(overlay_info) = detect_elf_overlay(data) {
        let start = usize::try_from(overlay_info.start_offset)
            .unwrap_or(data.len())
            .min(data.len());
        if start < data.len() {
            let overlay_data = &data[start..];

            // Extract ASCII strings
            let section = Some("overlay".to_string());
            let mut seen = HashSet::new();
            let initial_count = strings.len();
            extract_printable_runs(
                overlay_data,
                min_length,
                section.as_ref(),
                &HashSet::new(),
                &std::collections::HashMap::new(),
                &mut strings,
                &mut seen,
            );

            // Classify overlay strings and adjust offsets
            for s in &mut strings[initial_count..] {
                // Classify the string - if it's something highly specific and interesting
                // (encoded data, crypto, network indicators), keep that classification.
                // Otherwise mark as generic Overlay.
                let classified_kind = classify_string(&s.value);
                s.kind = match classified_kind {
                    // Keep highly specific/interesting classifications
                    StringKind::Base32
                    | StringKind::Base58
                    | StringKind::Base64
                    | StringKind::Base85
                    | StringKind::CryptoWallet
                    | StringKind::MiningPool
                    | StringKind::IP
                    | StringKind::IPPort
                    | StringKind::Hostname
                    | StringKind::Url
                    | StringKind::Email
                    | StringKind::TorAddress
                    | StringKind::ShellCmd
                    | StringKind::SuspiciousPath
                    | StringKind::XorKey
                    | StringKind::HexEncoded
                    | StringKind::APIKey
                    | StringKind::JWT
                    | StringKind::CTFFlag => classified_kind,
                    // Everything else stays as Overlay
                    _ => StringKind::Overlay,
                };
                s.data_offset += start as u64;
            }

            // Extract wide strings
            let wide_strings = extract_wide_strings(
                overlay_data,
                min_length,
                Some("overlay".to_string()),
                &[],
                &std::collections::HashMap::new(),
            );
            for mut s in wide_strings {
                // Classify wide overlay strings - keep highly specific classifications
                let classified_kind = classify_string(&s.value);
                s.kind = match classified_kind {
                    // Keep highly specific/interesting classifications
                    StringKind::Base32
                    | StringKind::Base58
                    | StringKind::Base64
                    | StringKind::Base85
                    | StringKind::CryptoWallet
                    | StringKind::MiningPool
                    | StringKind::IP
                    | StringKind::IPPort
                    | StringKind::Hostname
                    | StringKind::Url
                    | StringKind::Email
                    | StringKind::TorAddress
                    | StringKind::ShellCmd
                    | StringKind::SuspiciousPath
                    | StringKind::XorKey
                    | StringKind::HexEncoded
                    | StringKind::APIKey
                    | StringKind::JWT
                    | StringKind::CTFFlag => classified_kind,
                    // Everything else stays as OverlayWide
                    _ => StringKind::OverlayWide,
                };
                s.data_offset += start as u64;
                strings.push(s);
            }
        }
    }

    strings
}
