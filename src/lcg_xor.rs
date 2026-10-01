//! Bounded extraction for native cipher loaders.
//!
//! Some native loaders evolve a small state with `state = state * a % m`
//! and XOR each payload byte with the low state byte and a fixed mask. The
//! parameters and source range can come from explicit analyst input. Automatic
//! Mach-O passes require identified loader structures or instruction patterns
//! before decoding, and validate the recovered bytes before emitting strings.

use crate::{ExtractedString, StringMethod, classify_string};
use goblin::Object;
use goblin::mach::MachO;

/// Decode one explicitly identified LCG-XOR byte range into a string fact.
///
/// `offset` and `length` refer to the encoded bytes in the original file.
/// The state is updated after each byte, matching the common native loop form
/// `plain[i] = encoded[i] ^ (state as u8) ^ mask; state = state * a % m`.
#[must_use]
pub fn decode_lcg_xor(
    data: &[u8],
    offset: usize,
    length: usize,
    seed: u64,
    multiplier: u64,
    modulus: u64,
    mask: u8,
) -> Option<ExtractedString> {
    if length == 0 || modulus == 0 || multiplier == 0 {
        return None;
    }
    let end = offset.checked_add(length)?;
    let encoded = data.get(offset..end)?;
    let mut state = seed;
    let mut decoded = Vec::with_capacity(length);
    for &byte in encoded {
        let state_byte = u8::try_from(state & 0xff).unwrap_or(0);
        decoded.push(byte ^ state_byte ^ mask);
        state = state.wrapping_mul(multiplier) % modulus;
    }

    // Explicit decoding is useful only when it yields readable material. A
    // lossy conversion keeps ASCII scripts with a trailing NUL intact while
    // rejecting ciphertext that merely happens to produce replacement text.
    let value = String::from_utf8_lossy(&decoded)
        .trim_end_matches('\0')
        .to_owned();
    if value.is_empty() {
        return None;
    }
    let readable = value
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .count();
    if readable * 5 < value.chars().count() * 4 {
        return None;
    }

    Some(ExtractedString {
        kind: classify_string(&value),
        value,
        data_offset: offset as u64,
        data_len: u32::try_from(length).ok()?,
        method: StringMethod::XorDecode,
        ..Default::default()
    })
}

/// Recover a high-confidence LCG-XOR payload stored in a Mach-O `__const`
/// section. This targets the common loader shape where the section begins
/// with a 16-bit seed in a 32-bit little-endian word, the same seed and LCG
/// constants occur in `__text`, and the decoded command begins with a known
/// script or shell interpreter marker.
///
/// The conservative prefix and entropy checks keep this automatic pass from
/// turning arbitrary constant tables into decoded strings. The analyst-driven
/// [`decode_lcg_xor`] API remains available for other parameterizations.
#[must_use]
pub fn extract_macho_lcg_xor(
    macho: &MachO<'_>,
    data: &[u8],
    slice_base: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    let clock_lcg = extract_macho_clock_lcg_xor(macho, data, slice_base, min_length);
    if !clock_lcg.is_empty() {
        return clock_lcg;
    }
    if macho.header.cputype != goblin::mach::constants::cputype::CPU_TYPE_X86_64 {
        return Vec::new();
    }
    const MAX_SECTION_SIZE: usize = 8 * 1024 * 1024;
    const MIN_ENTROPY: f64 = 6.5;
    const PREVIEW_SIZE: usize = 96;

    // The last section of each name, which is what a name-keyed lookup
    // returned: `__DATA_CONST,__const` over `__TEXT,__const` when both exist.
    let sections = crate::binary::collect_macho_section_info(macho);
    let last = |name: &str| sections.iter().rev().find(|s| s.name == name);
    let Some(constant) = last("__const") else {
        return Vec::new();
    };
    let Some(text) = last("__text") else {
        return Vec::new();
    };
    let Ok(constant_start) = usize::try_from(slice_base.saturating_add(constant.file_offset))
    else {
        return Vec::new();
    };
    let Ok(constant_size) = usize::try_from(constant.size) else {
        return Vec::new();
    };
    let Ok(text_start) = usize::try_from(slice_base.saturating_add(text.file_offset)) else {
        return Vec::new();
    };
    let Ok(text_size) = usize::try_from(text.size) else {
        return Vec::new();
    };
    if constant_size <= 4 || constant_size > MAX_SECTION_SIZE {
        return Vec::new();
    }
    let Some(constant_end) = constant_start.checked_add(constant_size) else {
        return Vec::new();
    };
    let Some(text_end) = text_start.checked_add(text_size) else {
        return Vec::new();
    };
    let Some(constant_bytes) = data.get(constant_start..constant_end) else {
        return Vec::new();
    };
    let Some(code_bytes) = data.get(text_start..text_end) else {
        return Vec::new();
    };

    let seed_word = u32::from_le_bytes(constant_bytes[..4].try_into().unwrap_or([0; 4]));
    if !(0x1000..=0xffff).contains(&seed_word) || !code_contains_u32(code_bytes, seed_word) {
        return Vec::new();
    }
    let encoded = &constant_bytes[4..];
    if entropy(encoded) < MIN_ENTROPY {
        return Vec::new();
    }

    // The recurrence constants are immediates in the decoder's code. Scanning
    // overlapping little-endian words is intentionally bounded to `__text`.
    let mut multipliers = Vec::new();
    let mut moduli = Vec::new();
    for word in code_bytes.windows(4) {
        let value = u32::from_le_bytes(word.try_into().unwrap_or([0; 4]));
        if value & 1 == 0 {
            continue;
        }
        if (0x1_0000..=0x10_0000).contains(&value) {
            multipliers.push(u64::from(value));
        } else if (0x1000..0x1_0000).contains(&value) {
            moduli.push(u64::from(value));
        }
    }
    multipliers.sort_unstable();
    multipliers.dedup();
    moduli.sort_unstable();
    moduli.dedup();
    if multipliers.is_empty() || moduli.is_empty() || multipliers.len() > 64 || moduli.len() > 64 {
        return Vec::new();
    }

    let preview_len = encoded.len().min(PREVIEW_SIZE);
    for &multiplier in &multipliers {
        for &modulus in &moduli {
            if multiplier == modulus {
                continue;
            }
            for mask in 0..=u8::MAX {
                let preview = decode_preview(
                    &encoded[..preview_len],
                    u64::from(seed_word),
                    multiplier,
                    modulus,
                    mask,
                );
                if !looks_like_script_or_command(&preview) {
                    continue;
                }
                let Some(offset) = slice_base
                    .checked_add(constant.file_offset)
                    .and_then(|offset| offset.checked_add(4))
                    .and_then(|offset| usize::try_from(offset).ok())
                else {
                    return Vec::new();
                };
                return decode_lcg_xor(
                    data,
                    offset,
                    encoded.len(),
                    u64::from(seed_word),
                    multiplier,
                    modulus,
                    mask,
                )
                .filter(|s| s.value.len() >= min_length)
                .into_iter()
                .collect();
            }
        }
    }
    Vec::new()
}

/// Recover the small native-loader variant that derives its LCG modulus from
/// an embedded `HH:MM:SS` string. The seed and multiplier must also appear in
/// the architecture's code, and the decoded preview must identify a command
/// or script before the payload is fully decoded.
fn extract_macho_clock_lcg_xor(
    macho: &MachO<'_>,
    data: &[u8],
    slice_base: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    use goblin::mach::constants::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};

    const MAX_CODE: usize = 1024 * 1024;
    const MAX_PAYLOAD: usize = 8 * 1024 * 1024;
    const MULTIPLIER: u32 = 0x3785;

    let cpu = macho.header.cputype;
    if !matches!(cpu, CPU_TYPE_ARM64 | CPU_TYPE_X86_64) {
        return Vec::new();
    }

    let mut text = None;
    let mut constants = None;
    let mut cstrings = None;
    for segment in &macho.segments {
        if segment.name().ok() != Some("__TEXT") {
            continue;
        }
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, _) in sections {
            let Ok(name) = section.name() else {
                continue;
            };
            let target = match name {
                "__text" => &mut text,
                "__const" => &mut constants,
                "__cstring" => &mut cstrings,
                _ => continue,
            };
            *target = Some((u64::from(section.offset), section.size));
        }
    }
    let (
        Some((text_offset, text_size)),
        Some((const_offset, const_size)),
        Some((str_offset, str_size)),
    ) = (text, constants, cstrings)
    else {
        return Vec::new();
    };
    if text_size == 0
        || text_size > MAX_CODE as u64
        || !(5..=MAX_PAYLOAD as u64 + 4).contains(&const_size)
        || str_size == 0
    {
        return Vec::new();
    }
    let section = |offset: u64, size: u64| -> Option<&[u8]> {
        let start = usize::try_from(slice_base.checked_add(offset)?).ok()?;
        let end = start.checked_add(usize::try_from(size).ok()?)?;
        data.get(start..end)
    };
    let (Some(code), Some(constant), Some(cstrings)) = (
        section(text_offset, text_size),
        section(const_offset, const_size),
        section(str_offset, str_size),
    ) else {
        return Vec::new();
    };

    let seed = u32::from_le_bytes(constant[..4].try_into().unwrap_or([0; 4]));
    if !(0x1_0000..=0x1_ffff).contains(&seed) {
        return Vec::new();
    }
    let modulus = cstrings.windows(8).find_map(|value| {
        if value[2] != b':'
            || value[5] != b':'
            || !value
                .iter()
                .enumerate()
                .all(|(i, b)| matches!(i, 2 | 5) || b.is_ascii_digit())
        {
            return None;
        }
        let pair = |i| u64::from(value[i] - b'0') * 10 + u64::from(value[i + 1] - b'0');
        let (hours, minutes, seconds) = (pair(0), pair(3), pair(6));
        (hours < 24 && minutes < 60 && seconds < 60)
            .then_some(hours * 3600 + minutes * 60 + seconds)
            .filter(|&seconds| (0x1000..=0xffff).contains(&seconds))
    });
    let Some(modulus) = modulus else {
        return Vec::new();
    };

    let has_multiplier = if cpu == CPU_TYPE_X86_64 {
        code_contains_u32(code, MULTIPLIER)
    } else {
        code.as_chunks::<4>().0.iter().any(|word| {
            let word = u32::from_le_bytes(*word);
            word & 0x7f80_001f == 0x5280_0009
                && (word >> 5) & 0xffff == MULTIPLIER
                && (word >> 21) & 3 == 0
        })
    };
    let has_seed = if cpu == CPU_TYPE_X86_64 {
        code_contains_u32(code, seed)
    } else {
        let words = code.as_chunks::<4>().0;
        words.iter().zip(words.iter().skip(1)).any(|(movz, movk)| {
            let movz = u32::from_le_bytes(*movz);
            let movk = u32::from_le_bytes(*movk);
            movz & 0x7f80_001f == 0x5280_0001
                && (movz >> 5) & 0xffff == seed & 0xffff
                && movk & 0x7f80_001f == 0x7280_0001
                && (movk >> 5) & 0xffff == seed >> 16
                && (movk >> 21) & 3 == 1
        })
    };
    if !has_multiplier || !has_seed {
        return Vec::new();
    }

    let max_len = constant.len().saturating_sub(4).min(MAX_PAYLOAD);
    let min_bound = max_len.saturating_sub(15).max(min_length);
    let payload_len = if min_bound > max_len {
        None
    } else if cpu == CPU_TYPE_X86_64 {
        code.windows(4).find_map(|word| {
            let length = u32::from_le_bytes(word.try_into().unwrap_or([0; 4])) as usize;
            (min_bound..=max_len).contains(&length).then_some(length)
        })
    } else {
        code.as_chunks::<4>().0.iter().find_map(|word| {
            let word = u32::from_le_bytes(*word);
            if word & 0xff80_001f != 0xd280_0009 {
                return None;
            }
            let length = usize::try_from((word >> 5) & 0xffff).ok()?;
            ((word >> 21) & 3 == 0 && (min_bound..=max_len).contains(&length)).then_some(length)
        })
    };
    let Some(payload_len) = payload_len else {
        return Vec::new();
    };
    let Some(encoded) = constant.get(4..4 + payload_len) else {
        return Vec::new();
    };
    if encoded.len() < min_length || entropy(encoded) < 6.5 {
        return Vec::new();
    }
    let preview_len = encoded.len().min(96);
    let preview = decode_preview(
        &encoded[..preview_len],
        u64::from(seed),
        u64::from(MULTIPLIER),
        modulus,
        0,
    );
    if !looks_like_script_or_command(&preview) {
        return Vec::new();
    }
    let Some(offset) = slice_base
        .checked_add(const_offset)
        .and_then(|offset| offset.checked_add(4))
    else {
        return Vec::new();
    };
    let Ok(offset) = usize::try_from(offset) else {
        return Vec::new();
    };
    decode_lcg_xor(
        data,
        offset,
        encoded.len(),
        u64::from(seed),
        u64::from(MULTIPLIER),
        modulus,
        0,
    )
    .filter(|s| s.value.len() >= min_length)
    .into_iter()
    .collect()
}

/// Extract printable strings from a validated single-byte-XOR Mach-O payload
/// embedded in a Mach-O `__const` section. This only accepts blobs whose
/// decoded bytes form a structurally valid universal Mach-O with valid slices;
/// it does not emit strings from arbitrary one-byte-XOR guesses.
#[must_use]
pub fn extract_macho_xor_macho_strings(
    macho: &MachO<'_>,
    data: &[u8],
    slice_base: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    const MAX_SECTION_SIZE: usize = 32 * 1024 * 1024;
    const MAX_PAYLOADS: usize = 8;
    const FAT_MAGICS: [[u8; 4]; 4] = [
        [0xca, 0xfe, 0xba, 0xbe], // FAT_MAGIC
        [0xbe, 0xba, 0xfe, 0xca], // FAT_CIGAM
        [0xca, 0xfe, 0xba, 0xbf], // FAT_MAGIC_64
        [0xbf, 0xba, 0xfe, 0xca], // FAT_CIGAM_64
    ];

    let mut out = Vec::new();
    let mut payload_count = 0;
    for segment in &macho.segments {
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, _) in sections {
            if !section.name().is_ok_and(|name| name == "__const") {
                continue;
            }
            let Ok(start) = usize::try_from(slice_base.saturating_add(u64::from(section.offset)))
            else {
                continue;
            };
            let Ok(size) = usize::try_from(section.size) else {
                continue;
            };
            if !(4096..=MAX_SECTION_SIZE).contains(&size) {
                continue;
            }
            let Some(end) = start.checked_add(size) else {
                continue;
            };
            let Some(encoded_section) = data.get(start..end) else {
                continue;
            };

            let mut cursor = 0usize;
            while cursor
                .checked_add(8)
                .is_some_and(|n| n <= encoded_section.len())
                && payload_count < MAX_PAYLOADS
            {
                let mut found = None;
                for magic in FAT_MAGICS {
                    let key = encoded_section[cursor] ^ magic[0];
                    if encoded_section[cursor..cursor + 4]
                        .iter()
                        .zip(magic)
                        .all(|(&encoded, plain)| encoded ^ key == plain)
                    {
                        let Some(decoded) = decode_xor_fat_macho(&encoded_section[cursor..], key)
                        else {
                            continue;
                        };
                        found = Some((key, decoded));
                        break;
                    }
                }

                if let Some((key, decoded)) = found {
                    let mut strings =
                        crate::raw::extract_raw_strings(&decoded, min_length, &[], &[]);
                    let payload_offset = start.saturating_add(cursor);
                    for string in &mut strings {
                        string.data_offset =
                            string.data_offset.saturating_add(payload_offset as u64);
                        string.method = StringMethod::XorDecode;
                    }
                    // Preserve the one-byte key as an analyst-visible fact while
                    // tying it to the encoded payload's source offset.
                    out.push(ExtractedString {
                        value: format!("0x{key:02x}"),
                        data_offset: payload_offset as u64,
                        data_len: 1,
                        kind: Some(crate::StringKind::XorKey),
                        method: StringMethod::XorDecode,
                        ..Default::default()
                    });
                    out.extend(strings);
                    payload_count += 1;
                    cursor = cursor.saturating_add(decoded.len());
                } else {
                    cursor += 1;
                }
            }
            if payload_count >= MAX_PAYLOADS {
                return out;
            }
        }
    }
    out
}

/// Decode a single-byte-XOR universal Mach-O at a known candidate offset.
/// The architecture table determines the exact extent; every slice must parse
/// as Mach-O. Returns at most 32 MiB, with no scanning of the surrounding data.
/// This lets consumers analyze the binary already discovered by string extraction.
#[must_use]
pub fn decode_xor_fat_macho(encoded: &[u8], key: u8) -> Option<Vec<u8>> {
    if key == 0 {
        return None;
    }
    let len = decode_fat_length(encoded, key)?;
    if !(4096..=32 * 1024 * 1024).contains(&len) {
        return None;
    }
    let decoded: Vec<u8> = encoded[..len].iter().map(|b| b ^ key).collect();
    is_valid_fat_macho(&decoded).then_some(decoded)
}

fn decode_fat_length(encoded: &[u8], key: u8) -> Option<usize> {
    let mut header: [u8; 8] = encoded.get(..8)?.try_into().ok()?;
    header.iter_mut().for_each(|b| *b ^= key);
    let magic = u32::from_be_bytes(header[..4].try_into().ok()?);
    if !matches!(magic, 0xcafebabe | 0xbebafeca | 0xcafebabf | 0xbfbafeca) {
        return None;
    }
    let swapped = matches!(magic, 0xbebafeca | 0xbfbafeca);
    let is_64 = matches!(magic, 0xcafebabf | 0xbfbafeca);
    let arch_count = if swapped {
        u32::from_le_bytes(header[4..8].try_into().ok()?)
    } else {
        u32::from_be_bytes(header[4..8].try_into().ok()?)
    };
    if !(1..=32).contains(&arch_count) {
        return None;
    }
    let entry_size = if is_64 { 32usize } else { 20usize };
    let table_end =
        8usize.checked_add(usize::try_from(arch_count).ok()?.checked_mul(entry_size)?)?;
    if table_end > encoded.len() {
        return None;
    }
    let decoded_table: Vec<u8> = encoded[..table_end].iter().map(|byte| byte ^ key).collect();
    let mut payload_end = table_end;
    for index in 0..usize::try_from(arch_count).ok()? {
        let entry = 8 + index * entry_size;
        let (offset, size) = if is_64 {
            let off = u64::from_be_bytes(decoded_table[entry + 8..entry + 16].try_into().ok()?);
            let len = u64::from_be_bytes(decoded_table[entry + 16..entry + 24].try_into().ok()?);
            if swapped {
                (off.swap_bytes(), len.swap_bytes())
            } else {
                (off, len)
            }
        } else {
            let off = u32::from_be_bytes(decoded_table[entry + 8..entry + 12].try_into().ok()?);
            let len = u32::from_be_bytes(decoded_table[entry + 12..entry + 16].try_into().ok()?);
            if swapped {
                (u64::from(off.swap_bytes()), u64::from(len.swap_bytes()))
            } else {
                (u64::from(off), u64::from(len))
            }
        };
        if offset == 0 || size == 0 {
            return None;
        }
        let arch_end = usize::try_from(offset.checked_add(size)?).ok()?;
        payload_end = payload_end.max(arch_end);
    }
    (payload_end <= encoded.len()).then_some(payload_end)
}

fn is_valid_fat_macho(data: &[u8]) -> bool {
    let Ok(Object::Mach(goblin::mach::Mach::Fat(fat))) = Object::parse(data) else {
        return false;
    };
    let mut arch_count = 0;
    for arch in fat.into_iter() {
        if !matches!(arch, Ok(goblin::mach::SingleArch::MachO(_))) {
            return false;
        }
        arch_count += 1;
    }
    arch_count > 0
}

fn code_contains_u32(code: &[u8], value: u32) -> bool {
    let bytes = value.to_le_bytes();
    code.windows(bytes.len()).any(|window| window == bytes)
}

fn decode_preview(encoded: &[u8], seed: u64, multiplier: u64, modulus: u64, mask: u8) -> Vec<u8> {
    let mut state = seed;
    encoded
        .iter()
        .map(|&byte| {
            let state_byte = u8::try_from(state & 0xff).unwrap_or(0);
            let plain = byte ^ state_byte ^ mask;
            state = state.wrapping_mul(multiplier) % modulus;
            plain
        })
        .collect()
}

fn looks_like_script_or_command(bytes: &[u8]) -> bool {
    let printable = bytes
        .iter()
        .filter(|&&byte| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        .count();
    if bytes.is_empty() || printable * 100 < bytes.len() * 92 {
        return false;
    }
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    [
        "osascript",
        "do shell script",
        "#!/bin/sh",
        "#!/bin/bash",
        "powershell",
        "<?xml",
        "curl ",
        "wget ",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }
    counts
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let probability = count as f64 / bytes.len() as f64;
            -probability * probability.log2()
        })
        .sum()
}
