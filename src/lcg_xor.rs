//! Bounded extraction for native cipher loaders.
//!
//! Some native loaders evolve a small state with `state = state * a % m`
//! and XOR each payload byte with the low state byte and a fixed mask. The
//! parameters and source range can come from explicit analyst input. Automatic
//! Mach-O passes require identified loader structures or instruction patterns
//! before decoding, and validate the recovered bytes before emitting strings.

mod arm64_shuffled;
mod arm64_arithmetic;

use crate::{ExtractedString, StringMethod, classify_string};
use goblin::Object;
use goblin::mach::MachO;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::collections::HashMap;

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
        decoded.push(byte ^ state as u8 ^ mask);
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
    if macho.header.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64 {
        return extract_arm64_lcg(macho, slice_base, min_length);
    }
    if macho.header.cputype != goblin::mach::constants::cputype::CPU_TYPE_X86_64 {
        return Vec::new();
    }
    const MAX_SECTION_SIZE: usize = 8 * 1024 * 1024;
    const MIN_ENTROPY: f64 = 6.5;
    const PREVIEW_SIZE: usize = 96;

    let sections = crate::binary::collect_macho_section_info(macho);
    let Some(constant) = sections.get("__const") else {
        return Vec::new();
    };
    let Some(text) = sections.get("__text") else {
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
    if seed_word < 0x1000 || seed_word > 0xffff || !code_contains_u32(code_bytes, seed_word) {
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
            multipliers.push(value as u64);
        } else if (0x1000..0x1_0000).contains(&value) {
            moduli.push(value as u64);
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

/// One verified ARM64 LCG loop shape, with immediate operands read from code.
/// No parameter search or emulation: unknown instruction forms are rejected.
fn extract_arm64_lcg(
    macho: &MachO<'_>,
    slice_base: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    const MAX_CODE: usize = 1024 * 1024;
    const MAX_PAYLOAD: usize = 8 * 1024 * 1024;
    const LOOP: [u32; 13] = [
        0x8b08014f, 0x394011ef, 0x4a0b0130, 0x4a1001ef, 0x8b080270, 0x3900120f, 0x1b0c7d29,
        0x9bad7d2f, 0xd36dfdef, 0x1b0ea5e9, 0x91000508, 0xeb14011f, 0x54fffe81,
    ];
    let (mut text, mut constant) = (None, None);
    for segment in &macho.segments {
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, bytes) in sections {
            if section.segname().ok() != Some("__TEXT") {
                continue;
            }
            match section.name().ok() {
                Some("__text") => text = Some((section.addr, bytes)),
                Some("__const") => constant = Some((section.addr, section.offset, bytes)),
                _ => {}
            }
        }
    }
    let (Some((code_addr, code)), Some((const_addr, const_offset, constants))) = (text, constant)
    else {
        return Vec::new();
    };
    if code.len() > MAX_CODE || constants.len() < 5 || constants.len() > MAX_PAYLOAD + 4 {
        return Vec::new();
    }
    let read_word = |bytes: &[u8]| u32::from_le_bytes(bytes[..4].try_into().unwrap());
    // MOVZ/MOVK W immediates. Fixed destination and halfword are part of the gate.
    let imm =
        |word: u32, opcode: u32| (word & !0x001f_ffe0 == opcode).then_some((word >> 5) & 0xffff);
    let mut candidates = 0;
    for pos in (12..code.len().saturating_sub(95)).step_by(4) {
        if read_word(&code[pos..]) != 0xd2800008 {
            continue;
        } // mov x8, #0
        let window = &code[pos..pos + 96];
        let w = |i: usize| read_word(&window[i * 4..]);
        if w(2) != 0xb90002a9 // str w9, [x21]
            || !LOOP.iter().enumerate().all(|(i, &expected)| w(i + 11) == expected)
        {
            continue;
        }
        let (Some(seed), Some(mask), Some(a_lo), Some(a_hi), Some(q_lo), Some(q_hi), Some(modulus)) = (
            imm(w(1), 0x52800009),
            imm(w(5), 0x5280000b),
            imm(w(6), 0x5280000c),
            imm(w(7), 0x72a0000c),
            imm(w(8), 0x5280000d),
            imm(w(9), 0x72a0000d),
            imm(w(10), 0x5280000e),
        ) else {
            continue;
        };
        let Some(length) = imm(read_word(&code[pos - 12..]), 0x52800014) else {
            continue;
        };
        if imm(read_word(&code[pos - 8..]), 0x52800001) != Some(length)
            || read_word(&code[pos - 4..]) & 0xfc00_0000 != 0x9400_0000
            || length == 0
            || mask > 255
            || modulus == 0
            || seed != read_word(constants)
        {
            continue;
        }
        // ADRP x10; ADD x10,x10,#imm must address this exact constant header.
        if w(3) & 0x9f00_001f != 0x9000_000a || w(4) & 0xffc0_03ff != 0x9100_014a {
            continue;
        }
        let page_delta = i64::from(((w(3) >> 5) & 0x7ffff) << 2 | ((w(3) >> 29) & 3));
        let pc = code_addr.saturating_add(pos as u64 + 12);
        let source = (pc & !4095)
            .wrapping_add_signed((page_delta << 43 >> 43) << 12)
            .wrapping_add(u64::from((w(4) >> 10) & 0xfff));
        if source != const_addr {
            continue;
        }
        let Some(encoded) = constants.get(4..4 + length as usize) else {
            continue;
        };
        if candidates == 8 {
            break;
        }
        candidates += 1;
        let multiplier = a_lo | (a_hi << 16);
        let reciprocal = q_lo | (q_hi << 16);
        let decode_byte = |state: &mut u32, byte: u8| {
            let plain = byte ^ (*state as u8) ^ (mask as u8);
            let product = state.wrapping_mul(multiplier);
            // Reproduce MUL W, UMULL, LSR #45, MSUB W exactly, including wrap.
            let quotient = ((u64::from(product) * u64::from(reciprocal)) >> 45) as u32;
            *state = product.wrapping_sub(quotient.wrapping_mul(modulus));
            plain
        };
        let mut preview = [0_u8; 96];
        let preview_len = encoded.len().min(preview.len());
        let mut state = seed;
        for (dst, &src) in preview.iter_mut().zip(encoded) {
            *dst = decode_byte(&mut state, src);
        }
        if !looks_like_script_or_command(&preview[..preview_len]) {
            continue;
        }
        let mut state = seed;
        let decoded: Vec<u8> = encoded
            .iter()
            .map(|&b| decode_byte(&mut state, b))
            .collect();
        let Ok(mut value) = String::from_utf8(decoded) else {
            continue;
        };
        value.truncate(value.trim_end_matches('\0').len());
        if value.len() < min_length
            || value
                .bytes()
                .any(|b| b < 32 && !matches!(b, b'\n' | b'\r' | b'\t'))
        {
            continue;
        }
        let Some(offset) = slice_base
            .checked_add(u64::from(const_offset))
            .and_then(|o| o.checked_add(4))
        else {
            continue;
        };
        return vec![ExtractedString {
            kind: classify_string(&value),
            value,
            data_offset: offset,
            data_len: length,
            method: StringMethod::XorDecode,
            ..Default::default()
        }];
    }
    Vec::new()
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
            if size < 4096 || size > MAX_SECTION_SIZE {
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
                    let mut strings = crate::raw::extract_raw_strings(
                        &decoded,
                        min_length,
                        None,
                        &[],
                        &HashMap::new(),
                        &[],
                    );
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

/// Recover hex/custom-Base64 strings from x86 and ARM64 arithmetic-table loaders.
/// The loop computes `(a[i] - c[i]) ^ b[i]`, optionally subtracting another
/// table byte (or `b[i]` again), and emits the low byte. Addresses and bounds come
/// from the instructions;
/// neither ciphertext offsets nor payload lengths are guessed.
#[must_use]
pub fn extract_macho_arithmetic_strings(
    macho: &MachO<'_>,
    slice_base: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    let arm = macho.header.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64;
    if !arm && macho.header.cputype != goblin::mach::constants::cputype::CPU_TYPE_X86_64 {
        return Vec::new();
    }
    let mut text = None;
    let mut constants = None;
    let mut cstring_size = 0;
    for segment in &macho.segments {
        if segment.name().ok() != Some("__TEXT") {
            continue;
        }
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, bytes) in sections {
            match section.name().ok() {
                Some("__text") => text = Some((section, bytes)),
                Some("__const") => constants = Some((section, bytes)),
                Some("__cstring") => cstring_size = section.size,
                _ => {}
            }
        }
    }
    let (Some((text_section, code)), Some((const_section, data))) = (text, constants) else {
        return Vec::new();
    };
    // Reject ordinary binaries from section metadata, before disassembly.
    if cstring_size > 64
        || code.len() > 32 * 1024
        || !(64 * 1024..=8 * 1024 * 1024).contains(&data.len())
    {
        return Vec::new();
    }
    let tables = if arm {
        arm64_arithmetic::tables(code, text_section.addr)
    } else {
        let instructions: Vec<_> = Decoder::with_ip(64, code, text_section.addr, DecoderOptions::NONE)
            .into_iter()
            .filter(|i| i.mnemonic() != Mnemonic::Nop)
            .collect();
        let direct_loops = instructions.windows(18).filter_map(|s| {
            arithmetic_table_loop(s)
                .map(|(addresses, length)| ArithmeticTables {
                    addresses,
                    length,
                    subtract_address: Some(addresses[2]),
                    permutation: None,
                    literal_tail: None,
                })
                .or_else(|| arithmetic_permuted_table_loop(s))
        });
        let state_machine_loops = instructions
            .windows(33)
            .filter_map(arithmetic_state_machine_loop)
            .map(|(addresses, length)| ArithmeticTables {
                addresses,
                length,
                subtract_address: None,
                permutation: None,
                literal_tail: None,
            });
        let four_table_loops = instructions
            .windows(15)
            .filter_map(arithmetic_four_table_loop);
        direct_loops
            .chain(state_machine_loops)
            .chain(four_table_loops)
            .take(8)
            .collect::<Vec<_>>()
    };
    let mut blocks = Vec::new();
    let mut seen_tables = Vec::new();
    for tables in tables {
        // Initial and checksum-fallback loops can reference identical tables.
        // Count both toward the work cap, but decode each table set only once.
        if seen_tables.contains(&tables) {
            continue;
        }
        seen_tables.push(tables);
        let ArithmeticTables {
            addresses,
            length,
            subtract_address,
            permutation,
            literal_tail,
        } = tables;
        let table_offset = |address: u64| {
            let offset = usize::try_from(address.checked_sub(const_section.addr)?).ok()?;
            (offset.checked_add(length)? <= data.len()).then_some(offset)
        };
        let [Some(a), Some(c), Some(b)] = addresses.map(table_offset) else {
            continue;
        };
        let subtract_base = if let Some(address) = subtract_address {
            let Some(offset) = table_offset(address) else {
                continue;
            };
            Some(offset)
        } else {
            None
        };
        if let Some(address) = permutation {
            let Some(offset) = table_offset(address) else {
                continue;
            };
            let index_length = length - if literal_tail.is_some() { 8 } else { 0 };
            let indexes = &data[offset..offset + index_length];
            // Each input and output uses the same permuted index. Only a
            // complete permutation (including any explicit tail writes) justifies
            // decoding directly in index order.
            let mut seen = vec![false; length / 4];
            if !indexes.chunks_exact(4).all(|word| {
                let index = u32::from_le_bytes([word[0], word[1], word[2], word[3]]) as usize;
                index < seen.len() && !std::mem::replace(&mut seen[index], true)
            }) || literal_tail.is_some_and(|tail| {
                tail.into_iter().any(|(index, _)| {
                    index >= seen.len() || std::mem::replace(&mut seen[index], true)
                })
            }) {
                continue;
            }
        }
        let mut hex = Vec::with_capacity(length / 4);
        for offset in (0..length).step_by(4) {
            let mask = data[b + offset];
            let byte = data[a + offset].wrapping_sub(data[c + offset]) ^ mask;
            let byte = if let Some(base) = subtract_base {
                byte.wrapping_sub(data[base + offset])
            } else {
                byte
            };
            let byte = if let Some(tail) = literal_tail {
                tail.into_iter()
                    .find(|(index, _)| *index == offset / 4)
                    .map_or(byte, |(_, literal)| literal)
            } else {
                byte
            };
            if !byte.is_ascii_hexdigit() {
                hex.clear();
                break;
            }
            hex.push(byte);
        }
        if !hex.is_empty()
            && let Some(decoded) = decode_hex(&hex)
        {
            blocks.push((decoded, a, length));
        }
    }
    let Some((alphabet, _, _)) = blocks
        .iter()
        .find(|(bytes, _, _)| bytes.len() == 64 && has_unique_bytes(bytes))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (encoded, offset, length) in &blocks {
        if encoded == alphabet {
            continue;
        }
        let Some(decoded) = decode_custom_base64(encoded, alphabet) else {
            continue;
        };
        let Ok(value) = String::from_utf8(decoded) else {
            continue;
        };
        if value.len() < min_length
            || !value
                .chars()
                .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        {
            continue;
        }
        // Provenance points to the primary array; the other two arrays are
        // masks used by the validated arithmetic loop.
        let Some(data_offset) = slice_base
            .checked_add(u64::from(const_section.offset))
            .and_then(|base| base.checked_add(*offset as u64))
        else {
            continue;
        };
        out.push(ExtractedString {
            value,
            data_offset,
            data_len: *length as u32,
            method: StringMethod::Base64ObfuscatedDecode,
            kind: None,
            ..Default::default()
        });
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ArithmeticTables {
    addresses: [u64; 3],
    length: usize,
    subtract_address: Option<u64>,
    permutation: Option<u64>,
    // Two constant-folded writes replacing the final permutation entries.
    literal_tail: Option<[(usize, u8); 2]>,
}

/// Recognize the four-table permutation loop used both directly and as the
/// checksum fallback of an indirect dispatcher. Its transform is
/// `((A[index] - C[index]) ^ B[index]) - D[index]`. The caller verifies the
/// permutation before treating its traversal order as irrelevant.
fn arithmetic_four_table_loop(s: &[Instruction]) -> Option<ArithmeticTables> {
    use Mnemonic::{Add, Cmp, Jne, Lea, Mov, Movsxd, Sub, Xor};
    use Register::{EAX, R8, R9, R10D, R10L, RAX, RBX, RCX, RDI, RDX, RSI};
    let mnemonics = [
        Xor, Lea, Lea, Lea, Lea, Lea, Movsxd, Mov, Sub, Xor, Sub, Mov, Add, Cmp, Jne,
    ];
    if !s.iter().zip(mnemonics).all(|(i, m)| i.mnemonic() == m) {
        return None;
    }
    let load = |i: &Instruction, base| {
        i.op0_register() == R10D
            && i.op1_kind() == OpKind::Memory
            && i.memory_size() == iced_x86::MemorySize::UInt32
            && i.memory_base() == base
            && i.memory_index() == R9
            && i.memory_index_scale() == 4
            && i.memory_displacement64() == 0
    };
    if s[0].op0_register() != EAX
        || s[0].op1_register() != EAX
        || !s[1..6]
            .iter()
            .zip([RCX, RDX, RSI, RDI, R8])
            .all(|(i, r)| i.op0_register() == r && i.is_ip_rel_memory_operand())
        || s[6].op0_register() != R9
        || s[6].op1_kind() != OpKind::Memory
        || s[6].memory_size() != iced_x86::MemorySize::Int32
        || s[6].memory_index_scale() != 1
        || s[6].memory_displacement64() != 0
        || !((s[6].memory_base() == RAX && s[6].memory_index() == RCX)
            || (s[6].memory_base() == RCX && s[6].memory_index() == RAX))
        || !load(&s[7], RDX)
        || !load(&s[8], RSI)
        || !load(&s[9], RDI)
        || !load(&s[10], R8)
        || s[11].op0_kind() != OpKind::Memory
        || s[11].op1_register() != R10L
        || s[11].memory_size() != iced_x86::MemorySize::UInt8
        || s[11].memory_base() != RBX
        || s[11].memory_index() != R9
        || s[11].memory_index_scale() != 1
        || s[11].memory_displacement64() != 0
        || s[12].op0_register() != RAX
        || s[12].try_immediate(1).ok()? != 4
        || s[13].op0_register() != RAX
        || s[14].near_branch_target() != s[6].ip()
    {
        return None;
    }
    let length = usize::try_from(s[13].try_immediate(1).ok()?).ok()?;
    if !(32..=512 * 1024).contains(&length) || length % 8 != 0 {
        return None;
    }
    Some(ArithmeticTables {
        addresses: [
            s[2].ip_rel_memory_address(),
            s[3].ip_rel_memory_address(),
            s[4].ip_rel_memory_address(),
        ],
        length,
        subtract_address: Some(s[5].ip_rel_memory_address()),
        permutation: Some(s[1].ip_rel_memory_address()),
        literal_tail: None,
    })
}

/// Recognize a two-byte unrolled loop whose permutation indexes both source
/// tables and destination. The two compiler forms start at zero (loads at 0/4)
/// or one (loads at -4/0); both consume every permutation entry exactly once.
fn arithmetic_permuted_table_loop(s: &[Instruction]) -> Option<ArithmeticTables> {
    use Mnemonic::{Add, Cmp, Jne, Lea, Mov, Movsxd, Sub, Xor};
    use Register::{EAX, R8, R9D, R9L, R10, R11D, R11L, RAX, RCX, RDI, RDX, RSI};
    let mnemonics = [
        Lea, Lea, Lea, Lea, Movsxd, Mov, Sub, Xor, Movsxd, Mov, Sub, Xor, Mov, Mov, Add, Cmp, Jne,
    ];
    if !s[1..].iter().zip(mnemonics).all(|(i, m)| i.mnemonic() == m) {
        return None;
    }
    let start =
        if s[0].mnemonic() == Xor && s[0].op0_register() == EAX && s[0].op1_register() == EAX {
            0
        } else if s[0].mnemonic() == Mov
            && s[0].op0_register() == EAX
            && s[0].try_immediate(1).ok()? == 1
        {
            1
        } else {
            return None;
        };
    if !s[1..5]
        .iter()
        .zip([RCX, RDX, RSI, RDI])
        .all(|(i, r)| i.op0_register() == r && i.is_ip_rel_memory_operand())
    {
        return None;
    }
    let load = |i: &Instruction, dst, base, index, displacement| {
        i.op0_register() == dst
            && i.op1_kind() == OpKind::Memory
            && i.memory_size() == iced_x86::MemorySize::UInt32
            && i.memory_base() == base
            && i.memory_index() == index
            && i.memory_index_scale() == 4
            && i.memory_displacement64() == displacement
    };
    // MOVSXD reports Int32, unlike the unsigned arithmetic loads.
    let index_load = |i: &Instruction, dst, displacement| {
        i.op0_register() == dst
            && i.op1_kind() == OpKind::Memory
            && i.memory_size() == iced_x86::MemorySize::Int32
            && i.memory_base() == RCX
            && i.memory_index() == RAX
            && i.memory_index_scale() == 4
            && i.memory_displacement64() == displacement
    };
    let store = |i: &Instruction, index, byte| {
        i.op0_kind() == OpKind::Memory
            && i.op1_register() == byte
            && i.memory_size() == iced_x86::MemorySize::UInt8
            && matches!(
                i.memory_base(),
                Register::RBX | Register::R12 | Register::R13 | Register::R14 | Register::R15
            )
            && i.memory_base() == s[13].memory_base()
            && i.memory_index() == index
            && i.memory_index_scale() == 1
            && i.memory_displacement64() == 0
    };
    if !index_load(&s[5], R8, if start == 0 { 0 } else { (-4i64) as u64 })
        || !index_load(&s[9], R10, if start == 0 { 4 } else { 0 })
        || !load(&s[6], R9D, RDX, R8, 0)
        || !load(&s[7], R9D, RSI, R8, 0)
        || !load(&s[8], R9D, RDI, R8, 0)
        || !load(&s[10], R11D, RDX, R10, 0)
        || !load(&s[11], R11D, RSI, R10, 0)
        || !load(&s[12], R11D, RDI, R10, 0)
        || !store(&s[13], R8, R9L)
        || !store(&s[14], R10, R11L)
        || s[15].op0_register() != RAX
        || s[15].try_immediate(1).ok()? != 2
        || s[16].op0_register() != RAX
        || s[17].near_branch_target() != s[5].ip()
    {
        return None;
    }
    let count = usize::try_from(s[16].try_immediate(1).ok()?)
        .ok()?
        .checked_sub(start)?;
    if !(8..=128 * 1024).contains(&count) || count % 2 != 0 {
        return None;
    }
    Some(ArithmeticTables {
        addresses: [
            s[2].ip_rel_memory_address(),
            s[3].ip_rel_memory_address(),
            s[4].ip_rel_memory_address(),
        ],
        length: count * 4,
        subtract_address: None,
        permutation: Some(s[1].ip_rel_memory_address()),
        literal_tail: None,
    })
}

/// Recognize the compiler's complete arithmetic loop and its setup. Keeping
/// operand relationships, stack slot, stride and back edge in the signature
/// prevents inferring this transform from nearby LEAs alone.
fn arithmetic_table_loop(s: &[Instruction]) -> Option<([u64; 3], usize)> {
    use Mnemonic::{Add, Call, Cmp, Jne, Lea, Mov, Movsx, Sub, Xor};
    use Register::{AL, EAX, ECX, ESI, R12, R13, R14, R14D, R15, RBP, RBX, RDI};
    let mnemonics = [
        Xor, Lea, Lea, Lea, Lea, Mov, Sub, Mov, Xor, Mov, Sub, Mov, Movsx, Mov, Call, Add, Cmp, Jne,
    ];
    if !s.iter().zip(mnemonics).all(|(i, m)| i.mnemonic() == m) {
        return None;
    }
    let rr = |i: &Instruction, a, b| {
        i.op0_kind() == OpKind::Register
            && i.op1_kind() == OpKind::Register
            && i.op0_register() == a
            && i.op1_register() == b
    };
    let indexed = |i: &Instruction, table| {
        i.memory_size() == iced_x86::MemorySize::UInt32
            && i.memory_displacement64() == 0
            && i.memory_index_scale() == 1
            && ((i.memory_base() == R14 && i.memory_index() == table)
                || (i.memory_base() == table && i.memory_index() == R14))
    };
    let stack = |i: &Instruction| {
        i.memory_base() == RBP
            && i.memory_index() == Register::None
            && i.memory_size() == iced_x86::MemorySize::UInt32
            && i.memory_displacement64() == s[9].memory_displacement64()
    };
    if !rr(&s[0], R14D, R14D)
        || !s[1..4]
            .iter()
            .zip([R15, R12, R13])
            .all(|(i, r)| i.op0_register() == r && i.is_ip_rel_memory_operand())
        || s[4].op0_register() != RBX
        || s[4].memory_base() != RBP
        || s[5].op0_register() != EAX
        || !indexed(&s[5], R15)
        || s[6].op0_register() != EAX
        || !indexed(&s[6], R12)
        || s[7].op0_register() != ECX
        || !indexed(&s[7], R13)
        || !rr(&s[8], EAX, ECX)
        || s[9].op1_register() != EAX
        || !stack(&s[9])
        || s[10].op1_register() != ECX
        || !stack(&s[10])
        || s[11].op0_register() != EAX
        || !stack(&s[11])
        || !rr(&s[12], ESI, AL)
        || !rr(&s[13], RDI, RBX)
        || s[14].op0_kind() != OpKind::NearBranch64
        || s[15].op0_register() != R14
        || s[15].try_immediate(1).ok()? != 4
        || s[16].op0_register() != R14
        || s[17].near_branch_target() != s[5].ip()
    {
        return None;
    }
    let length = usize::try_from(s[16].try_immediate(1).ok()?).ok()?;
    if !(32..=512 * 1024).contains(&length) || length % 8 != 0 {
        return None;
    }
    Some((
        [
            s[1].ip_rel_memory_address(),
            s[2].ip_rel_memory_address(),
            s[3].ip_rel_memory_address(),
        ],
        length,
    ))
}

/// An older compiler variant wraps the subtraction/XOR loop in a three-state
/// dispatcher. Validate its complete control flow before trusting the bound;
/// the comparison is inclusive, so the table holds `last_index + 1` words.
fn arithmetic_state_machine_loop(s: &[Instruction]) -> Option<([u64; 3], usize)> {
    use Mnemonic::{Call, Cmp, Inc, Je, Jmp, Jne, Lea, Mov, Movsx, Movsxd, Setl, Sub, Test, Xor};
    use Register::{AL, EAX, ECX, ESI, R12, R12D, R13, R14D, R14L, R15, RAX, RBP, RBX, RDI};
    let mnemonics = [
        Xor, Lea, Lea, Lea, Xor, Mov, Movsxd, Xor, Cmp, Setl, Xor, Cmp, Jne, Lea, Mov, Sub, Xor,
        Movsx, Mov, Call, Mov, Jmp, Test, Je, Cmp, Jne, Mov, Inc, Mov, Jmp, Mov, Xor, Jmp,
    ];
    if !s.iter().zip(mnemonics).all(|(i, m)| i.mnemonic() == m) {
        return None;
    }
    let rr = |i: &Instruction, a, b| {
        i.op0_kind() == OpKind::Register
            && i.op1_kind() == OpKind::Register
            && i.op0_register() == a
            && i.op1_register() == b
    };
    let immediate = |i: &Instruction, register, value| {
        i.op0_register() == register && i.try_immediate(1).ok() == Some(value)
    };
    let indexed = |i: &Instruction, table| {
        i.op0_register() == EAX
            && i.op1_kind() == OpKind::Memory
            && i.memory_size() == iced_x86::MemorySize::UInt32
            && i.memory_base() == table
            && i.memory_index() == R12
            && i.memory_index_scale() == 4
            && i.memory_displacement64() == 0
    };
    let stack = |i: &Instruction| {
        i.memory_base() == RBP
            && i.memory_index() == Register::None
            && i.memory_size() == iced_x86::MemorySize::UInt32
            && i.memory_displacement64() == s[5].memory_displacement64()
    };
    if !rr(&s[0], ECX, ECX)
        || ![(1, R15), (2, R13), (13, RAX)]
            .iter()
            .all(|&(n, r)| s[n].op0_register() == r && s[n].is_ip_rel_memory_operand())
        || s[3].op0_register() != RBX
        || s[3].memory_base() != RBP
        || s[3].memory_index() != Register::None
        || !rr(&s[4], EAX, EAX)
        || s[5].op0_kind() != OpKind::Memory
        || s[5].op1_register() != ECX
        || !stack(&s[5])
        || !rr(&s[6], R12, ECX)
        || !rr(&s[7], R14D, R14D)
        || s[8].op0_register() != R12D
        || s[9].op0_register() != R14L
        || !immediate(&s[10], R14D, 3)
        || !immediate(&s[11], EAX, 1)
        || s[12].near_branch_target() != s[22].ip()
        || !indexed(&s[14], RAX)
        || !indexed(&s[15], R15)
        || !indexed(&s[16], R13)
        || !rr(&s[17], ESI, AL)
        || !rr(&s[18], RDI, RBX)
        || s[19].op0_kind() != OpKind::NearBranch64
        || !rr(&s[20], EAX, R14D)
        || s[21].near_branch_target() != s[11].ip()
        || !rr(&s[22], EAX, EAX)
        || s[23].near_branch_target() != s[30].ip()
        || !immediate(&s[24], EAX, 2)
        || s[25].near_branch_target() != s[32].next_ip()
        || s[26].op0_register() != ECX
        || s[26].op1_kind() != OpKind::Memory
        || !stack(&s[26])
        || s[27].op0_register() != ECX
        || !immediate(&s[28], EAX, 1)
        || s[29].near_branch_target() != s[5].ip()
        || !immediate(&s[30], EAX, 1)
        || !rr(&s[31], ECX, ECX)
        || s[32].near_branch_target() != s[5].ip()
    {
        return None;
    }
    let count = usize::try_from(s[8].try_immediate(1).ok()?)
        .ok()?
        .checked_add(1)?;
    if !(8..=128 * 1024).contains(&count) || count % 2 != 0 {
        return None;
    }
    Some((
        [
            s[13].ip_rel_memory_address(),
            s[1].ip_rel_memory_address(),
            s[2].ip_rel_memory_address(),
        ],
        count * 4,
    ))
}

/// Recover shuffled xorshift/Base64 AppleScript stages from a stripped
/// Mach-O loader. Candidate permutation tables must be complete permutations,
/// and the decoded stages must contain the expected script structure before
/// any strings are emitted.
#[must_use]
pub fn extract_macho_shuffled_xorshift_strings(
    macho: &MachO<'_>,
    data: &[u8],
    slice_base: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    if macho.header.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64 {
        return arm64_shuffled::extract(macho, slice_base, min_length);
    }
    const MAX_STAGE_BYTES: usize = 0x20_000;
    const ALPHABET_TABLE_LEN: usize = 0x100;
    const GATE_TABLE_LEN: usize = 0xb2c;
    const PAYLOAD_PROFILES: [(usize, usize, usize); 2] =
        [(0x1f160, 0xf8b0, 0xf8af), (0x1f248, 0xf924, 0xf923)];
    // This decoder targets a narrow, identified loader family. Cheap section
    // geometry checks must run before scanning code or looking for tables.
    const MIN_CONST_SIZE: usize = 0x3d000;
    const MAX_CONST_SIZE: usize = 0x41000;
    const MIN_CSTRING_SIZE: usize = 16;
    const MAX_CSTRING_SIZE: usize = 64;

    let mut out = Vec::new();
    if macho.header.cputype != goblin::mach::constants::cputype::CPU_TYPE_X86_64 {
        return out;
    }
    let eligible_layout = macho.segments.iter().any(|segment| {
        if segment.name().ok() != Some("__TEXT") {
            return false;
        }
        let Ok(sections) = segment.sections() else {
            return false;
        };
        let mut has_const = false;
        let mut has_cstrings = false;
        for (section, _) in sections {
            match section.name().ok() {
                Some("__const") => {
                    has_const =
                        (MIN_CONST_SIZE as u64..=MAX_CONST_SIZE as u64).contains(&section.size);
                }
                Some("__cstring") => {
                    has_cstrings =
                        (MIN_CSTRING_SIZE as u64..=MAX_CSTRING_SIZE as u64).contains(&section.size);
                }
                _ => {}
            }
        }
        has_const && has_cstrings
    });
    if !eligible_layout {
        return out;
    }
    let seeds = macho_movabs_seeds(macho, data, slice_base);
    if seeds.is_empty() {
        return out;
    }
    let const_references = macho_const_data_references(macho);
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
            if !(MIN_CONST_SIZE..=MAX_CONST_SIZE).contains(&size)
                || size < PAYLOAD_PROFILES[0].0 * 2
            {
                continue;
            }
            // The permutation tail in some builds sits in the gap immediately
            // following __const, before __cstring. Include that adjacent
            // __TEXT data while keeping the section start as the offset base.
            let region_size = size
                .saturating_add(4096)
                .min(data.len().saturating_sub(start));
            let Some(end) = start.checked_add(region_size) else {
                continue;
            };
            let Some(constant_data) = data.get(start..end) else {
                continue;
            };
            let alphabet_table = decode_hex_table(
                constant_data,
                ALPHABET_TABLE_LEN,
                0x80,
                &seeds,
                0x7e + 1,
                true,
                &const_references,
            )
            .or_else(|| {
                decode_unlinked_hex_table(
                    constant_data,
                    ALPHABET_TABLE_LEN,
                    0x80,
                    &seeds,
                    &const_references,
                    0x7e + 1,
                )
            });
            let Some((alphabet_hex, _, _)) = alphabet_table else {
                continue;
            };
            let Some(alphabet) = decode_hex(&alphabet_hex) else {
                continue;
            };
            if alphabet.len() != 64 || !has_unique_bytes(&alphabet) {
                continue;
            }

            let Some((gate_hex, gate_data_offset, _)) = decode_hex_table(
                constant_data,
                GATE_TABLE_LEN,
                0x596,
                &seeds,
                0x594 + 1,
                false,
                &const_references,
            ) else {
                continue;
            };
            let Some(gate_encoded) = decode_hex(&gate_hex) else {
                continue;
            };
            let Some(gate) = decode_custom_base64(&gate_encoded, &alphabet) else {
                continue;
            };
            if !gate.starts_with(b"osascript -e ")
                || !gate
                    .windows(b"system_profiler".len())
                    .any(|w| w == b"system_profiler")
            {
                continue;
            }

            let Some((payload_hex, payload_data_offset, payload_table_len)) = PAYLOAD_PROFILES
                .iter()
                .find_map(|&(table_len, output_len, skip)| {
                    decode_hex_table(
                        constant_data,
                        table_len,
                        output_len,
                        &seeds,
                        skip,
                        false,
                        &const_references,
                    )
                    .map(|(decoded, offset, _)| (decoded, offset, table_len))
                })
            else {
                continue;
            };
            let Some(payload_encoded) = decode_hex(&payload_hex) else {
                continue;
            };
            let Some(payload) = decode_custom_base64(&payload_encoded, &alphabet) else {
                continue;
            };
            if !payload.starts_with(b"osascript -e ")
                || !payload
                    .windows(b"/Library/LaunchDaemons".len())
                    .any(|w| w == b"/Library/LaunchDaemons")
                || !payload.windows(b"/contact".len()).any(|w| w == b"/contact")
            {
                continue;
            }

            // The short terminal-cleanup stage uses the same tables and seed
            // immediates, without a warm-up. Only inspect it after both larger
            // stages have qualified, so unrelated files incur no extra search.
            let cleanup = decode_hex_table(
                constant_data, 0x78, 0x3c, &seeds, 0, false, &const_references,
            ).and_then(|(hex, offset, _)| {
                let encoded = decode_hex(&hex)?;
                Some((decode_custom_base64(&encoded, &alphabet)?, offset, 0xf0))
            });
            for (value, table_offset, table_len) in [
                (gate, gate_data_offset, GATE_TABLE_LEN * 2),
                (payload, payload_data_offset, payload_table_len * 2),
            ].into_iter().chain(cleanup) {
                if value.len() < min_length || value.len() > MAX_STAGE_BYTES {
                    continue;
                }
                let Ok(value) = String::from_utf8(value) else {
                    continue;
                };
                out.push(ExtractedString {
                    value,
                    data_offset: start.saturating_add(table_offset) as u64,
                    data_len: table_len as u32,
                    method: StringMethod::Base64ObfuscatedDecode,
                    kind: None,
                    ..Default::default()
                });
            }
            return out;
        }
    }
    out
}

/// Find and decode one hex-wrapped shuffled table. The cipher stores one data
/// byte and one little-endian destination index for each output character;
/// a small alignment gap may separate the two arrays.
fn decode_hex_table(
    section: &[u8],
    table_len: usize,
    output_len: usize,
    seeds: &[u64],
    skip: usize,
    require_unique_decoded: bool,
    table_references: &[usize],
) -> Option<(Vec<u8>, usize, u64)> {
    for index_offset in find_permutation_tables(section, table_len, output_len, table_references) {
        for gap in (0..=16).step_by(2) {
            let Some(data_offset) = index_offset.checked_sub(table_len + gap) else {
                continue;
            };
            for &seed in seeds {
                let Some(decoded) = decode_shuffled_table(
                    section,
                    data_offset,
                    index_offset,
                    table_len,
                    seed,
                    skip,
                    output_len,
                ) else {
                    continue;
                };
                let Some(decoded) = trim_nul(&decoded) else {
                    continue;
                };
                if decode_hex(decoded)
                    .is_some_and(|bytes| !require_unique_decoded || has_unique_bytes(&bytes))
                {
                    return Some((decoded.to_vec(), data_offset, seed));
                }
            }
        }
    }
    None
}

fn has_unique_bytes(bytes: &[u8]) -> bool {
    let mut seen = [false; 256];
    bytes.iter().all(|&byte| {
        let slot = &mut seen[usize::from(byte)];
        if *slot {
            false
        } else {
            *slot = true;
            true
        }
    })
}

/// Some builds place the short alphabet's byte table well away from its
/// permutation table. Locate its source among the x86 code's references into
/// `__const`, then validate the complete decode.
fn decode_unlinked_hex_table(
    section: &[u8],
    table_len: usize,
    output_len: usize,
    seeds: &[u64],
    source_references: &[usize],
    skip: usize,
) -> Option<(Vec<u8>, usize, u64)> {
    for index_offset in find_permutation_tables(section, table_len, output_len, source_references) {
        let indexes = section.get(index_offset..index_offset + table_len)?;
        for &seed in seeds {
            let mut state = seed;
            for _ in 0..skip {
                state = xorshift64(state);
            }
            let mut stream = [((0u8, 0u16)); 16];
            for (index, item) in stream.iter_mut().enumerate() {
                state = xorshift64(state);
                let offset = index * 2;
                *item = (
                    state as u8,
                    u16::from_le_bytes([indexes[offset], indexes[offset + 1]]),
                );
            }
            for &data_offset in source_references {
                if data_offset
                    .checked_add(table_len)
                    .is_none_or(|end| end > index_offset)
                {
                    continue;
                }
                let mut addend = (-7i16) as u8;
                let mut matches_hex = true;
                for (index, &(key_byte, position)) in stream.iter().enumerate() {
                    let value = section[data_offset + index * 2].wrapping_add(addend)
                        ^ key_byte.wrapping_mul(0x1d);
                    if usize::from(position) >= output_len || !value.is_ascii_hexdigit() {
                        matches_hex = false;
                        break;
                    }
                    addend = addend.wrapping_sub(3);
                }
                if !matches_hex {
                    continue;
                }
                let Some(decoded) = decode_shuffled_table(
                    section,
                    data_offset,
                    index_offset,
                    table_len,
                    seed,
                    skip,
                    output_len,
                ) else {
                    continue;
                };
                let Some(decoded) = trim_nul(&decoded) else {
                    continue;
                };
                if decode_hex(decoded).is_some() {
                    return Some((decoded.to_vec(), data_offset, seed));
                }
            }
        }
    }
    None
}

/// Return offsets within the constant scan region targeted by RIP-relative x86
/// instructions. Some builds place their permutation array in adjacent
/// `__ustring` data immediately after `__const`.
/// This lets the nonadjacent alphabet table come from an actual decoder code
/// reference instead of searching every possible source offset in the section.
fn macho_const_data_references(macho: &MachO<'_>) -> Vec<usize> {
    let mut const_range = None;
    let mut text_sections = Vec::new();
    for segment in &macho.segments {
        if segment.name().ok() != Some("__TEXT") {
            continue;
        }
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, bytes) in sections {
            match section.name().ok() {
                Some("__const") => {
                    const_range = Some((section.addr, section.addr.saturating_add(section.size)));
                }
                Some("__text") => text_sections.push((section.addr, bytes)),
                _ => {}
            }
        }
    }
    let Some((const_start, const_end)) = const_range else {
        return Vec::new();
    };
    let const_end = const_end.saturating_add(4096);
    let mut offsets = Vec::new();
    for (text_start, bytes) in text_sections {
        let mut decoder = Decoder::with_ip(64, bytes, text_start, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                continue;
            }
            if instruction.is_ip_rel_memory_operand() {
                let target = instruction.ip_rel_memory_address();
                if (const_start..const_end).contains(&target) {
                    offsets.push((target - const_start) as usize);
                }
            }
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

/// Read 64-bit immediates from x86-64 `mov r64, imm64` instructions in code
/// sections. The cipher seed is embedded in this form in the loader; decoded
/// table content is still fully validated before the seed is accepted.
fn macho_movabs_seeds(macho: &MachO<'_>, data: &[u8], slice_base: u64) -> Vec<u64> {
    let mut seeds = Vec::new();
    for segment in &macho.segments {
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, _) in sections {
            if !section.name().is_ok_and(|name| name == "__text") {
                continue;
            }
            let Ok(start) = usize::try_from(slice_base.saturating_add(u64::from(section.offset)))
            else {
                continue;
            };
            let Ok(size) = usize::try_from(section.size) else {
                continue;
            };
            let Some(end) = start.checked_add(size) else {
                continue;
            };
            let Some(code) = data.get(start..end) else {
                continue;
            };
            for window in code.windows(10) {
                if window[0] & 0xf8 == 0x48 && (0xb8..=0xbf).contains(&window[1]) {
                    seeds.push(u64::from_le_bytes(window[2..10].try_into().unwrap()));
                }
            }
        }
    }
    seeds.sort_unstable();
    seeds.dedup();
    seeds
}

/// Return referenced index arrays that are exact permutations of `0..output_len`.
/// Decoder code references the arrays directly, so only those offsets need
/// validation; ordinary files never pay for section-wide window searches.
fn find_permutation_tables(
    section: &[u8],
    table_len: usize,
    output_len: usize,
    references: &[usize],
) -> Vec<usize> {
    let mut candidates = Vec::new();
    if table_len % 2 != 0 || table_len / 2 != output_len {
        return candidates;
    }
    for &start in references {
        let Some(indexes) = section.get(start..start.saturating_add(table_len)) else {
            continue;
        };
        let mut seen = vec![false; output_len];
        let plausible = indexes.chunks_exact(2).all(|pair| {
            let value = usize::from(u16::from_le_bytes([pair[0], pair[1]]));
            if value >= output_len || std::mem::replace(&mut seen[value], true) {
                false
            } else {
                true
            }
        });
        if plausible {
            candidates.push(start);
        }
    }
    candidates
}

fn decode_shuffled_table(
    section: &[u8],
    data_offset: usize,
    index_offset: usize,
    table_len: usize,
    seed: u64,
    skip: usize,
    output_len: usize,
) -> Option<Vec<u8>> {
    let data_end = data_offset.checked_add(table_len)?;
    let index_end = index_offset.checked_add(table_len)?;
    let source = section.get(data_offset..data_end)?;
    let indexes = section.get(index_offset..index_end)?;
    decode_shuffled_slices(source, indexes, seed, skip, output_len)
}

fn decode_shuffled_slices(
    source: &[u8],
    indexes: &[u8],
    seed: u64,
    skip: usize,
    output_len: usize,
) -> Option<Vec<u8>> {
    if source.len() != indexes.len() || source.len() != output_len.checked_mul(2)? {
        return None;
    }
    let mut state = seed;
    for _ in 0..skip {
        state = xorshift64(state);
    }
    let mut output = vec![0; output_len];
    let mut addend = (-7i16) as u8;
    for (&byte, index) in source.iter().step_by(2).zip(indexes.chunks_exact(2)) {
        state = xorshift64(state);
        let position = usize::from(u16::from_le_bytes([index[0], index[1]]));
        if position >= output.len() {
            return None;
        }
        output[position] = byte.wrapping_add(addend) ^ (state as u8).wrapping_mul(0x1d);
        addend = addend.wrapping_sub(3);
    }
    Some(output)
}

fn xorshift64(mut value: u64) -> u64 {
    value ^= value >> 12;
    value ^= value << 25;
    value ^= value >> 27;
    value
}

fn trim_nul(value: &[u8]) -> Option<&[u8]> {
    let end = value
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(value.len());
    (end > 0).then_some(&value[..end])
}

fn decode_hex(value: &[u8]) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in value.chunks_exact(2) {
        out.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
    }
    Some(out)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn decode_custom_base64(value: &[u8], alphabet: &[u8]) -> Option<Vec<u8>> {
    if alphabet.len() != 64 {
        return None;
    }
    let mut reverse = [-1i16; 256];
    for (index, &byte) in alphabet.iter().enumerate() {
        if reverse[usize::from(byte)] != -1 {
            return None;
        }
        reverse[usize::from(byte)] = index as i16;
    }
    let mut out = Vec::with_capacity(value.len().saturating_mul(3) / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for &byte in value {
        let sextet = reverse[usize::from(byte)];
        if sextet < 0 {
            return None;
        }
        accumulator = (accumulator << 6) | sextet as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    Some(out)
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
            let plain = byte ^ state as u8 ^ mask;
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

#[cfg(test)]
#[path = "lcg_xor/arithmetic_variant_tests.rs"]
mod arithmetic_variant_tests;
