//! Bounded extraction for native cipher loaders.
//!
//! Some native loaders evolve a small state with `state = state * a % m`
//! and XOR each payload byte with the low state byte and a fixed mask. The
//! parameters and source range can come from explicit analyst input. The
//! automatic Mach-O passes search only parameters the loader's own code
//! names: a seed that also appears in `__text`, and at most 64 multiplier and
//! 64 modulus immediates from it, or a modulus derived from an embedded clock
//! string. Every mask is tried on a short preview, and a payload is decoded
//! only when that preview begins like a script or shell command.

use crate::{ExtractedString, StringMethod, classify_string};
use goblin::Object;
use goblin::mach::MachO;
use std::collections::BTreeSet;

/// Bits per byte below which a blob is not ciphertext.
const MIN_ENTROPY: f64 = 6.5;
/// Bytes decoded to judge a candidate before decoding it all.
const PREVIEW_SIZE: usize = 96;

/// A linear-congruential keystream, as native cipher loaders use it: each
/// byte is XORed with the state's low byte and `mask`, then
/// `state = state * multiplier % modulus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lcg {
    /// The state before the first byte.
    pub seed: u64,
    /// The state's multiplier.
    pub multiplier: u64,
    /// The state's modulus.
    pub modulus: u64,
    /// A constant XORed into every byte.
    pub mask: u8,
}

impl Lcg {
    /// `encoded` XORed with this keystream.
    fn apply(&self, encoded: &[u8]) -> Vec<u8> {
        let mut state = self.seed;
        encoded
            .iter()
            .map(|&byte| {
                let plain = byte ^ state.to_le_bytes()[0] ^ self.mask;
                state = state.wrapping_mul(self.multiplier) % self.modulus;
                plain
            })
            .collect()
    }
}

/// Why [`decode_lcg_xor`] decoded nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LcgError {
    /// The range is empty, or the multiplier or modulus is zero.
    BadParameters,
    /// The range runs past the end of the data.
    OutOfBounds,
    /// The bytes decode, but not to readable text.
    NotReadable,
}

impl std::fmt::Display for LcgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadParameters => "empty range, or a zero multiplier or modulus",
            Self::OutOfBounds => "range runs past the end of the input",
            Self::NotReadable => "parameters do not decode the range to readable text",
        })
    }
}

impl std::error::Error for LcgError {}

/// Decode the LCG-XOR bytes at `range` in `data` into a string.
pub fn decode_lcg_xor(
    data: &[u8],
    range: std::ops::Range<usize>,
    lcg: &Lcg,
) -> Result<ExtractedString, LcgError> {
    if range.is_empty() || lcg.modulus == 0 || lcg.multiplier == 0 {
        return Err(LcgError::BadParameters);
    }
    let offset = range.start;
    let decoded = lcg.apply(data.get(range).ok_or(LcgError::OutOfBounds)?);

    // Explicit decoding is useful only when it yields readable material. A
    // lossy conversion keeps ASCII scripts with a trailing NUL intact while
    // rejecting ciphertext that merely happens to produce replacement text.
    let value = String::from_utf8_lossy(&decoded)
        .trim_end_matches('\0')
        .to_owned();
    let readable = value
        .chars()
        .filter(|&c| crate::text::is_readable(c))
        .count();
    if value.is_empty() || readable * 5 < value.chars().count() * 4 {
        return Err(LcgError::NotReadable);
    }

    Ok(ExtractedString {
        kind: classify_string(&value),
        value,
        data_offset: offset as u64,
        data_len: u32::try_from(decoded.len()).unwrap_or(u32::MAX),
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
    clock_lcg_xor(macho, data, slice_base, min_length)
        .or_else(|| const_lcg_xor(macho, data, slice_base, min_length))
        .into_iter()
        .collect()
}

/// The x86-64 `__const` loader shape of [`extract_macho_lcg_xor`].
fn const_lcg_xor(
    macho: &MachO<'_>,
    data: &[u8],
    slice_base: u64,
    min_length: usize,
) -> Option<ExtractedString> {
    const MAX_SECTION_SIZE: u64 = 8 * 1024 * 1024;
    if macho.header.cputype != goblin::mach::constants::cputype::CPU_TYPE_X86_64 {
        return None;
    }

    // The last section of each name, which is what a name-keyed lookup
    // returned: `__DATA_CONST,__const` over `__TEXT,__const` when both exist.
    let sections = crate::binary::collect_macho_section_info(macho);
    let last = |name: &str| sections.iter().rev().find(|s| s.name == name);
    let constant = last("__const")?;
    let text = last("__text")?;
    if constant.size <= 4 || constant.size > MAX_SECTION_SIZE {
        return None;
    }
    let constant_start = slice_base.saturating_add(constant.file_offset);
    let constant_bytes = crate::binary::file_range(data, constant_start, constant.size)?;
    let code_bytes =
        crate::binary::file_range(data, slice_base.saturating_add(text.file_offset), text.size)?;

    let seed_word = crate::bytes::u32_le(constant_bytes, 0)?;
    if !(0x1000..=0xffff).contains(&seed_word) || !code_contains_u32(code_bytes, seed_word) {
        return None;
    }
    let encoded = &constant_bytes[4..];
    if crate::bytes::entropy(encoded) < MIN_ENTROPY {
        return None;
    }

    // The recurrence constants are immediates in the decoder's code. Scanning
    // overlapping little-endian words is intentionally bounded to `__text`.
    // More than `MAX_CANDIDATES` distinct values of either kind is not a
    // compact decoder, so the scan gives up as soon as one set overflows.
    const MAX_CANDIDATES: usize = 64;
    let mut multipliers = BTreeSet::new();
    let mut moduli = BTreeSet::new();
    for &word in code_bytes.array_windows::<4>() {
        let value = u32::from_le_bytes(word);
        if value & 1 == 0 {
            continue;
        }
        let set = if (0x1_0000..=0x10_0000).contains(&value) {
            &mut multipliers
        } else if (0x1000..0x1_0000).contains(&value) {
            &mut moduli
        } else {
            continue;
        };
        if set.insert(u64::from(value)) && set.len() > MAX_CANDIDATES {
            return None;
        }
    }

    let preview_len = encoded.len().min(PREVIEW_SIZE);
    for &multiplier in &multipliers {
        for &modulus in &moduli {
            if multiplier == modulus {
                continue;
            }
            // The mask XORs every byte, so the keystream is shared by all 256.
            let lcg = Lcg {
                seed: u64::from(seed_word),
                multiplier,
                modulus,
                mask: 0,
            };
            let unmasked = lcg.apply(&encoded[..preview_len]);
            let mut preview = [0u8; PREVIEW_SIZE];
            let preview = &mut preview[..preview_len];
            for mask in 0..=u8::MAX {
                for (out, &byte) in preview.iter_mut().zip(&unmasked) {
                    *out = byte ^ mask;
                }
                if !looks_like_script_or_command(preview) {
                    continue;
                }
                let offset = usize::try_from(constant_start.checked_add(4)?).ok()?;
                let end = offset.checked_add(encoded.len())?;
                return decode_lcg_xor(data, offset..end, &Lcg { mask, ..lcg })
                    .ok()
                    .filter(|s| s.value.len() >= min_length);
            }
        }
    }
    None
}

/// Recover the small native-loader variant that derives its LCG modulus from
/// an embedded `HH:MM:SS` string. The seed and multiplier must also appear in
/// the architecture's code, and the decoded preview must identify a command
/// or script before the payload is fully decoded.
fn clock_lcg_xor(
    macho: &MachO<'_>,
    data: &[u8],
    slice_base: u64,
    min_length: usize,
) -> Option<ExtractedString> {
    use goblin::mach::constants::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};

    const MAX_CODE: usize = 1024 * 1024;
    const MAX_PAYLOAD: usize = 8 * 1024 * 1024;

    let cpu = macho.header.cputype;
    if !matches!(cpu, CPU_TYPE_ARM64 | CPU_TYPE_X86_64) {
        return None;
    }

    let mut text = None;
    let mut constants = None;
    let mut cstrings = None;
    for (section, _) in crate::binary::macho_sections(macho)
        .filter(|(section, _)| section.segname().ok() == Some("__TEXT"))
    {
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
    let ((text_offset, text_size), (const_offset, const_size), (str_offset, str_size)) =
        (text?, constants?, cstrings?);
    if text_size == 0
        || text_size > MAX_CODE as u64
        || !(5..=MAX_PAYLOAD as u64 + 4).contains(&const_size)
        || str_size == 0
    {
        return None;
    }
    let section = |offset: u64, size: u64| {
        crate::binary::file_range(data, slice_base.checked_add(offset)?, size)
    };
    let code = section(text_offset, text_size)?;
    let constant = section(const_offset, const_size)?;
    let cstrings = section(str_offset, str_size)?;

    let seed = crate::bytes::u32_le(constant, 0)?;
    if !(0x1_0000..=0x1_ffff).contains(&seed) {
        return None;
    }
    let modulus = clock_modulus(cstrings)?;
    let x86 = cpu == CPU_TYPE_X86_64;
    if !loads_lcg_constants(code, x86, seed) {
        return None;
    }

    let max_len = constant.len().saturating_sub(4).min(MAX_PAYLOAD);
    let min_bound = max_len.saturating_sub(15).max(min_length);
    if min_bound > max_len {
        return None;
    }
    let payload_len = if x86 {
        code.array_windows::<4>().find_map(|&word| {
            let length = u32::from_le_bytes(word) as usize;
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
    }?;
    let encoded = constant.get(4..4 + payload_len)?;
    if encoded.len() < min_length || crate::bytes::entropy(encoded) < MIN_ENTROPY {
        return None;
    }
    let lcg = Lcg {
        seed: u64::from(seed),
        multiplier: u64::from(CLOCK_MULTIPLIER),
        modulus,
        mask: 0,
    };
    let preview = lcg.apply(&encoded[..encoded.len().min(PREVIEW_SIZE)]);
    if !looks_like_script_or_command(&preview) {
        return None;
    }
    let offset = usize::try_from(slice_base.checked_add(const_offset)?.checked_add(4)?).ok()?;
    decode_lcg_xor(data, offset..offset.checked_add(encoded.len())?, &lcg)
        .ok()
        .filter(|s| s.value.len() >= min_length)
}

/// The clock-variant loader's LCG multiplier.
const CLOCK_MULTIPLIER: u32 = 0x3785;

/// The LCG modulus the loader derives from an embedded `HH:MM:SS`: the
/// time in seconds, which must fit 16 bits.
fn clock_modulus(cstrings: &[u8]) -> Option<u64> {
    cstrings.windows(8).find_map(|value| {
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
    })
}

/// Whether `code` loads both the multiplier and `seed` as immediates: as raw
/// 32-bit constants on x86-64, or as MOVZ (plus MOVK for the seed's high
/// half) on ARM64.
fn loads_lcg_constants(code: &[u8], x86: bool, seed: u32) -> bool {
    if x86 {
        return code_contains_u32(code, CLOCK_MULTIPLIER) && code_contains_u32(code, seed);
    }
    let words = code.as_chunks::<4>().0;
    let has_multiplier = words.iter().any(|word| {
        let word = u32::from_le_bytes(*word);
        word & 0x7f80_001f == 0x5280_0009
            && (word >> 5) & 0xffff == CLOCK_MULTIPLIER
            && (word >> 21) & 3 == 0
    });
    has_multiplier
        && words.iter().zip(words.iter().skip(1)).any(|(movz, movk)| {
            let movz = u32::from_le_bytes(*movz);
            let movk = u32::from_le_bytes(*movk);
            movz & 0x7f80_001f == 0x5280_0001
                && (movz >> 5) & 0xffff == seed & 0xffff
                && movk & 0x7f80_001f == 0x7280_0001
                && (movk >> 5) & 0xffff == seed >> 16
                && (movk >> 21) & 3 == 1
        })
}

/// Extract printable strings from a validated single-byte-XOR Mach-O payload
/// embedded in a Mach-O `__const` section. This only accepts blobs whose
/// decoded bytes form a structurally valid universal Mach-O with valid slices;
/// it does not emit strings from arbitrary one-byte-XOR guesses.
#[must_use]
pub(crate) fn extract_macho_xor_macho_strings(
    macho: &MachO<'_>,
    data: &[u8],
    slice_base: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    const MAX_SECTION_SIZE: usize = 32 * 1024 * 1024;
    const MAX_PAYLOADS: usize = 8;
    /// Bytes the file may spend decoding candidates in full, over all its
    /// sections. A header planted every 28 bytes, each claiming the rest of
    /// the section, made the scan quadratic: a few megabytes cost hours.
    const MAX_DECODE_WORK: usize = 8 * MAX_SECTION_SIZE;
    const FAT_MAGICS: [[u8; 4]; 4] = [
        [0xca, 0xfe, 0xba, 0xbe], // FAT_MAGIC
        [0xbe, 0xba, 0xfe, 0xca], // FAT_CIGAM
        [0xca, 0xfe, 0xba, 0xbf], // FAT_MAGIC_64
        [0xbf, 0xba, 0xfe, 0xca], // FAT_CIGAM_64
    ];

    let mut out = Vec::new();
    let mut payload_count = 0;
    let mut work = 0usize;
    for (section, _) in crate::binary::macho_sections(macho) {
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
            && work <= MAX_DECODE_WORK
        {
            let mut found = None;
            for magic in FAT_MAGICS {
                let key = encoded_section[cursor] ^ magic[0];
                if encoded_section[cursor..cursor + 4]
                    .iter()
                    .zip(magic)
                    .all(|(&encoded, plain)| encoded ^ key == plain)
                {
                    work = work.saturating_add(
                        decode_fat_length(&encoded_section[cursor..], key).unwrap_or(0),
                    );
                    let Some(decoded) = decode_xor_fat_macho(&encoded_section[cursor..], key)
                    else {
                        continue;
                    };
                    found = Some((key, decoded));
                    break;
                }
            }

            if let Some((key, decoded)) = found {
                let mut strings = crate::raw::extract_raw_strings(&decoded, min_length, &[], &[]);
                let payload_offset = start.saturating_add(cursor);
                for string in &mut strings {
                    string.data_offset = string.data_offset.saturating_add(payload_offset as u64);
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
        if work > MAX_DECODE_WORK {
            tracing::debug!(MAX_DECODE_WORK, "fat Mach-O XOR: decode budget exhausted");
            return out;
        }
        if payload_count >= MAX_PAYLOADS {
            return out;
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
    let header = crate::bytes::array::<8>(encoded, 0)?.map(|b| b ^ key);
    let magic = crate::bytes::u32_be(&header, 0)?;
    if !matches!(magic, 0xcafebabe | 0xbebafeca | 0xcafebabf | 0xbfbafeca) {
        return None;
    }
    let swapped = matches!(magic, 0xbebafeca | 0xbfbafeca);
    let is_64 = matches!(magic, 0xcafebabf | 0xbfbafeca);
    let arch_count = if swapped {
        crate::bytes::u32_le(&header, 4)?
    } else {
        crate::bytes::u32_be(&header, 4)?
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
            let off = crate::bytes::u64_be(&decoded_table, entry + 8)?;
            let len = crate::bytes::u64_be(&decoded_table, entry + 16)?;
            if swapped {
                (off.swap_bytes(), len.swap_bytes())
            } else {
                (off, len)
            }
        } else {
            let off = crate::bytes::u32_be(&decoded_table, entry + 8)?;
            let len = crate::bytes::u32_be(&decoded_table, entry + 12)?;
            if swapped {
                (u64::from(off.swap_bytes()), u64::from(len.swap_bytes()))
            } else {
                (u64::from(off), u64::from(len))
            }
        };
        if offset == 0 || size == 0 {
            return None;
        }
        // Every slice must be Mach-O, so check its magic here, before a
        // caller decodes the whole claimed extent to find out.
        let slice = usize::try_from(offset).ok()?;
        let magic = u32::from_le_bytes(crate::bytes::array::<4>(encoded, slice)?.map(|b| b ^ key));
        if !matches!(magic, 0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe) {
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
