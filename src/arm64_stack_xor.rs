//! Narrow ARM64 stack-XOR extraction for Mach-O malware.
//!
//! This intentionally handles a small compiler-shaped subset:
//! MOVZ/MOVK immediate construction, ADD-immediate stack pointers, unsigned
//! STR/LDR stack accesses, and BL sink detection. That covers binaries that
//! build ciphertext and XOR pads as stack immediates, then reuse the same pad
//! for command strings and filesystem/browser-wallet target strings.

use crate::classifier::classify_string;
use crate::types::{ExtractedString, StringKind, StringMethod};
use goblin::mach::constants::cputype::CPU_TYPE_ARM64;
use goblin::mach::constants::S_ATTR_SOME_INSTRUCTIONS;
use goblin::mach::MachO;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
enum RegValue {
    Imm(u64),
    Ptr(i64),
    Bytes(Vec<u8>),
}

/// Extract printable strings produced by XORing stack-resident ARM64 immediates.
pub(crate) fn extract_arm64_stack_xor_strings(
    macho: &MachO<'_>,
    arch_data: &[u8],
    arch_base_offset: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    if macho.header.cputype != CPU_TYPE_ARM64 || !imports_system(macho) {
        return Vec::new();
    }

    let mut results = Vec::new();

    for seg in &macho.segments {
        let Ok(sections) = seg.sections() else {
            continue;
        };
        for (section, _) in sections {
            if (section.flags & S_ATTR_SOME_INSTRUCTIONS) == 0 || section.size < 4 {
                continue;
            }

            let start = section.offset as usize;
            let size = section.size as usize;
            let Some(end) = start.checked_add(size) else {
                continue;
            };
            let Some(code) = arch_data.get(start..end) else {
                continue;
            };

            let section_name = section.name().ok().map(str::to_string);
            results.extend(extract_section(
                code,
                section.addr,
                arch_base_offset + u64::from(section.offset),
                section_name.as_deref(),
                min_length,
            ));
        }
    }

    dedup_results(results)
}

fn imports_system(macho: &MachO<'_>) -> bool {
    macho
        .imports()
        .is_ok_and(|imports| imports.iter().any(|import| import.name.contains("system")))
}

fn extract_section(
    code: &[u8],
    section_addr: u64,
    section_file_offset: u64,
    section_name: Option<&str>,
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut regs: HashMap<u8, RegValue> = HashMap::with_capacity(32);
    let mut memory: HashMap<i64, Vec<u8>> = HashMap::new();
    let mut sink_results = Vec::new();
    let mut decoded_arg_starts = HashSet::new();
    let mut recovered_pads: Vec<Vec<u8>> = Vec::new();
    let mut seen_values = HashSet::new();

    for (idx, chunk) in code.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let instr_off = (idx * 4) as u64;
        let pc = section_addr + instr_off;

        if let Some((rd, value)) = decode_mov_wide(word, &regs) {
            regs.insert(rd, RegValue::Imm(value));
            continue;
        }

        if let Some((rd, rn, imm)) = decode_add_imm(word) {
            let base = if rn == 31 {
                Some(0)
            } else {
                match regs.get(&rn) {
                    Some(RegValue::Ptr(offset)) => Some(*offset),
                    _ => None,
                }
            };
            if let Some(base) = base {
                regs.insert(rd, RegValue::Ptr(base + imm));
            } else {
                regs.remove(&rd);
            }
            continue;
        }

        if decode_bl_target(word, pc).is_some() {
            if let Some(RegValue::Ptr(arg0)) = regs.get(&0) {
                if decoded_arg_starts.insert(*arg0) {
                    let decoded = decode_stack_arg_with_candidate_pads(
                        &memory,
                        *arg0,
                        section_file_offset + instr_off,
                        section_name,
                        min_length,
                    );
                    for pad in decoded.pads {
                        if !recovered_pads.contains(&pad) {
                            recovered_pads.push(pad);
                        }
                    }
                    append_unique_results(&mut sink_results, decoded.results, &mut seen_values);
                }
            }
            continue;
        }

        if let Some(mem) = decode_unsigned_mem(word) {
            let Some(base) = ptr_offset(&regs, mem.rn) else {
                continue;
            };
            let disp = base + mem.disp;
            if mem.load {
                if let Some(bytes) = memory.get(&disp).cloned() {
                    regs.insert(mem.rt, RegValue::Bytes(bytes));
                } else {
                    regs.remove(&mem.rt);
                }
            } else if let Some(bytes) = reg_bytes(&regs, mem.rt, mem.size) {
                memory.insert(disp, bytes.clone());
                if !recovered_pads.is_empty() {
                    let decoded = decode_recent_stack_blobs_with_pads(
                        &memory,
                        disp,
                        &recovered_pads,
                        section_file_offset + instr_off,
                        section_name,
                        min_length,
                    );
                    append_unique_results(&mut sink_results, decoded, &mut seen_values);
                }
            }
        }
    }

    sink_results
}

fn ptr_offset(regs: &HashMap<u8, RegValue>, rn: u8) -> Option<i64> {
    if rn == 31 {
        return Some(0);
    }
    match regs.get(&rn) {
        Some(RegValue::Ptr(offset)) => Some(*offset),
        _ => None,
    }
}

fn reg_bytes(regs: &HashMap<u8, RegValue>, rt: u8, size: usize) -> Option<Vec<u8>> {
    match regs.get(&rt)? {
        RegValue::Imm(value) => Some(value.to_le_bytes()[..size].to_vec()),
        RegValue::Bytes(bytes) if bytes.len() >= size => Some(bytes[..size].to_vec()),
        _ => None,
    }
}

fn decode_mov_wide(word: u32, regs: &HashMap<u8, RegValue>) -> Option<(u8, u64)> {
    if (word & 0x1f80_0000) != 0x1280_0000 {
        return None;
    }
    let sf = (word >> 31) & 1;
    let opc = (word >> 29) & 0x3;
    let hw = (word >> 21) & 0x3;
    let imm16 = u64::from((word >> 5) & 0xffff);
    let rd = (word & 0x1f) as u8;
    if rd == 31 {
        return None;
    }
    let shift = hw * 16;
    if sf == 0 && shift >= 32 {
        return None;
    }

    match opc {
        2 => Some((rd, imm16 << shift)), // MOVZ
        3 => {
            let prev = match regs.get(&rd) {
                Some(RegValue::Imm(value)) => *value,
                _ => 0,
            };
            let mask = !(0xffff_u64 << shift);
            Some((rd, (prev & mask) | (imm16 << shift)))
        }
        _ => None,
    }
}

fn decode_add_imm(word: u32) -> Option<(u8, u8, i64)> {
    if (word & 0x1f00_0000) != 0x1100_0000 || ((word >> 30) & 1) != 0 {
        return None;
    }
    let rd = (word & 0x1f) as u8;
    let rn = ((word >> 5) & 0x1f) as u8;
    let mut imm = i64::from((word >> 10) & 0xfff);
    if ((word >> 22) & 1) != 0 {
        imm <<= 12;
    }
    Some((rd, rn, imm))
}

fn decode_bl_target(word: u32, pc: u64) -> Option<u64> {
    if (word & 0xfc00_0000) != 0x9400_0000 {
        return None;
    }
    let imm26 = i64::from(word & 0x03ff_ffff);
    let signed = (imm26 << 38) >> 36;
    Some(pc.wrapping_add_signed(signed))
}

struct MemInsn {
    rt: u8,
    rn: u8,
    disp: i64,
    size: usize,
    load: bool,
}

struct StackDecodeResults {
    results: Vec<ExtractedString>,
    pads: Vec<Vec<u8>>,
}

fn decode_unsigned_mem(word: u32) -> Option<MemInsn> {
    if (word & 0x3b00_0000) != 0x3900_0000 {
        return None;
    }
    let size_code = (word >> 30) & 0x3;
    let size = match size_code {
        0 => 1,
        2 => 4,
        3 => 8,
        _ => return None,
    };
    let imm12 = i64::from((word >> 10) & 0xfff);
    Some(MemInsn {
        rt: (word & 0x1f) as u8,
        rn: ((word >> 5) & 0x1f) as u8,
        disp: imm12 * size as i64,
        size,
        load: ((word >> 22) & 1) != 0,
    })
}

fn decode_stack_arg_with_candidate_pads(
    memory: &HashMap<i64, Vec<u8>>,
    cipher_start: i64,
    instr_off: u64,
    section_name: Option<&str>,
    min_length: usize,
) -> StackDecodeResults {
    let Some(cipher) = collect_contiguous(memory, cipher_start, 128) else {
        return StackDecodeResults {
            results: Vec::new(),
            pads: Vec::new(),
        };
    };
    if cipher.len() < min_length {
        return StackDecodeResults {
            results: Vec::new(),
            pads: Vec::new(),
        };
    }
    if cipher.get(..4).is_none_or(|prefix| looks_printable(prefix)) {
        return StackDecodeResults {
            results: Vec::new(),
            pads: Vec::new(),
        };
    }

    let mut results = Vec::new();
    let mut pads = Vec::new();
    let mut seen = HashSet::new();
    let mut starts: Vec<i64> = memory.keys().copied().collect();
    starts.sort_unstable();

    for pad_start in starts {
        if pad_start == cipher_start {
            continue;
        }
        let Some(pad) = collect_contiguous(memory, pad_start, cipher.len().max(32)) else {
            continue;
        };
        let max_len = cipher.len().min(pad.len()).min(64);
        for len in [16usize, 32, 48, 64] {
            if len < min_length || len > max_len {
                continue;
            }
            let decoded: Vec<u8> = cipher[..len]
                .iter()
                .zip(&pad[..len])
                .map(|(&x, &y)| x ^ y)
                .collect();
            if !looks_printable(&decoded) {
                continue;
            }
            let decoded_text = String::from_utf8_lossy(&decoded);
            let value = decoded_text
                .split('\0')
                .next()
                .unwrap_or("")
                .trim_end()
                .to_string();
            if value.len() < min_length
                || !looks_like_useful_decoded_string(&value)
                || !seen.insert(value.clone())
            {
                continue;
            }

            let kind = classify_string(&value).or(Some(StringKind::StackString));
            let key_len = pad.len().min(32).max(len);
            let key = pad[..key_len].to_vec();
            let key_value = format_xor_key(&key);
            if !pads.contains(&key) {
                pads.push(key);
            }
            if seen.insert(key_value.clone()) {
                results.push(ExtractedString {
                    value: key_value,
                    data_offset: instr_off.saturating_sub(1),
                    section: section_name.map(str::to_string),
                    method: StringMethod::XorStackPair,
                    kind: Some(StringKind::XorKey),
                    source: Some("arm64 stack xor key near system".to_string()),
                    ..Default::default()
                });
            }
            results.push(ExtractedString {
                value,
                data_offset: instr_off,
                section: section_name.map(str::to_string),
                method: StringMethod::XorStackPair,
                kind,
                source: Some("arm64 stack xor near system".to_string()),
                ..Default::default()
            });
        }
    }

    StackDecodeResults { results, pads }
}

fn decode_recent_stack_blobs_with_pads(
    memory: &HashMap<i64, Vec<u8>>,
    write_start: i64,
    pads: &[Vec<u8>],
    instr_off: u64,
    section_name: Option<&str>,
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    let mut starts: Vec<i64> = memory
        .keys()
        .copied()
        .filter(|&start| start <= write_start && write_start - start <= 128)
        .collect();
    starts.push(write_start);
    starts.sort_unstable();
    starts.dedup();

    for start in starts {
        let Some(cipher) = collect_contiguous(memory, start, 192) else {
            continue;
        };
        if cipher.len() < min_length {
            continue;
        }

        for pad in pads {
            if pad.is_empty() {
                continue;
            }
            let decoded: Vec<u8> = cipher
                .iter()
                .enumerate()
                .map(|(idx, &byte)| byte ^ pad[idx % pad.len()])
                .collect();

            for raw_value in printable_runs(&decoded, min_length) {
                let Some(value) = normalize_decoded_value(&raw_value, min_length) else {
                    continue;
                };
                if !looks_like_useful_decoded_string(&value) || !seen.insert(value.clone()) {
                    continue;
                }
                results.push(ExtractedString {
                    kind: classify_string(&value).or(Some(StringKind::StackString)),
                    value,
                    data_offset: instr_off,
                    section: section_name.map(str::to_string),
                    method: StringMethod::XorStackPair,
                    source: Some("arm64 stack xor blob".to_string()),
                    ..Default::default()
                });
            }
        }
    }

    results
}

fn printable_runs(decoded: &[u8], min_length: usize) -> Vec<String> {
    let mut runs = Vec::new();
    let mut start = None;

    for (idx, byte) in decoded
        .iter()
        .copied()
        .chain(std::iter::once(0))
        .enumerate()
    {
        let is_printable = byte.is_ascii_graphic() || byte == b' ' || byte == b'\t';
        match (start, is_printable) {
            (None, true) => start = Some(idx),
            (Some(run_start), false) => {
                if idx - run_start >= min_length {
                    let text = String::from_utf8_lossy(&decoded[run_start..idx])
                        .trim()
                        .to_string();
                    if text.len() >= min_length {
                        runs.push(text);
                    }
                }
                start = None;
            }
            _ => {}
        }
    }

    runs
}

fn normalize_decoded_value(value: &str, min_length: usize) -> Option<String> {
    let mut value = value.trim().to_string();
    if value.len() < min_length {
        return None;
    }

    for anchor in [
        "osascript",
        "dscl",
        "/Users/",
        "/Library/",
        "Library/",
        "Application Support",
        "BraveSoftware/",
        "Google/",
        "Chrome",
        "Chromium",
        "Cookies",
        "Login Data",
        "accounts-metadata/",
        ".electrum",
        ".walletwasabi",
        "Monero/",
        "Bitcoin",
        "wallet.dat",
        "Ledger",
        "ledger-wallet",
        "Exodus",
        "Atomic",
    ] {
        if let Some(idx) = value.find(anchor) {
            if idx > 0 && idx <= 24 {
                value = value[idx..].to_string();
                break;
            }
        }
    }

    value = value
        .trim_start_matches(|c: char| {
            c.is_ascii_punctuation() && c != '/' && c != '.' && c != '~' && c != '$'
        })
        .to_string();

    if value.starts_with("killall Terminal") {
        value.truncate("killall Terminal".len());
    } else if let Some(end) = value.find("login.keychain-db") {
        value.truncate(end + "login.keychain-db".len());
    } else if let Some(end) = value.find("login.keychain") {
        value.truncate(end + "login.keychain".len());
    } else if let Some(end) = value.find(".electrum-ltc/wallets") {
        value.truncate(end + ".electrum-ltc/wallets".len());
    } else if let Some(end) = value.find(".electrum/wallets") {
        value.truncate(end + ".electrum/wallets".len());
    } else if let Some(end) = value.find(".walletwasabi/client/Wallets") {
        value.truncate(end + ".walletwasabi/client/Wallets".len());
    } else if let Some(end) = value.find("Monero/wallets") {
        value.truncate(end + "Monero/wallets".len());
    } else if let Some(end) = value.find("wallet.dat") {
        value.truncate(end + "wallet.dat".len());
    } else if let Some(end) = value.find("BraveSoftware/Brave-Browser") {
        value.truncate(end + "BraveSoftware/Brave-Browser".len());
    } else if let Some(end) = value.find("Google/Chrome for Testing") {
        value.truncate(end + "Google/Chrome for Testing".len());
    } else if let Some(end) = value.find("Google/Chrome Canary") {
        value.truncate(end + "Google/Chrome Canary".len());
    } else if let Some(end) = value.find("Google/Chrome Beta") {
        value.truncate(end + "Google/Chrome Beta".len());
    } else if let Some(end) = value.find("Google/Chrome Dev") {
        value.truncate(end + "Google/Chrome Dev".len());
    }

    if value.starts_with("osascript")
        && !(value.contains("osascript -e '") || value.contains("osascript -e \""))
    {
        return None;
    }

    if value.len() >= min_length {
        Some(value)
    } else {
        None
    }
}

fn format_xor_key(key: &[u8]) -> String {
    let mut out = String::with_capacity(2 + key.len() * 2);
    out.push_str("0x");
    for byte in key {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn collect_contiguous(
    memory: &HashMap<i64, Vec<u8>>,
    start: i64,
    max_len: usize,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = start;
    while out.len() < max_len {
        let Some(chunk) = memory.get(&pos) else {
            break;
        };
        if chunk.is_empty() {
            break;
        }
        out.extend_from_slice(chunk);
        pos += chunk.len() as i64;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn looks_printable(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == 0)
}

fn looks_like_useful_decoded_string(s: &str) -> bool {
    if matches!(
        classify_string(s),
        Some(
            StringKind::ShellCmd
                | StringKind::AppleScript
                | StringKind::SuspiciousPath
                | StringKind::Path
                | StringKind::Url
        )
    ) {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    lower.contains("killall")
        || lower.contains("terminal")
        || lower.contains("dscl")
        || lower.contains("/users/")
        || lower.contains("/library/")
        || lower.contains("library/")
        || lower.contains("application support")
        || lower.contains("keychain")
        || lower.contains("cookies")
        || lower.contains("login data")
        || lower.contains("wallet")
        || lower.contains("wallets")
        || lower.contains("wallet.dat")
        || lower.contains("electrum")
        || lower.contains("exodus")
        || lower.contains("atomic")
        || lower.contains("ledger")
        || lower.contains("monero")
        || lower.contains("bitcoin")
        || lower.contains("wasabi")
        || lower.contains("chrome")
        || lower.contains("chromium")
        || lower.contains("brave")
        || lower.contains("safari")
        || lower.contains("sqlite")
        || lower.contains("osascript")
        || lower.contains("chmod")
        || lower.contains("curl")
}

fn append_unique_results(
    out: &mut Vec<ExtractedString>,
    results: Vec<ExtractedString>,
    seen: &mut HashSet<String>,
) {
    for result in results {
        if seen.insert(result.value.clone()) {
            out.push(result);
        }
    }
}

fn dedup_results(mut results: Vec<ExtractedString>) -> Vec<ExtractedString> {
    results.sort_by_key(|r| (r.data_offset, r.value.len()));
    let mut seen = HashSet::new();
    results
        .into_iter()
        .filter(|r| seen.insert(r.value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_movz_movk_wide_immediate() {
        let mut regs = HashMap::new();
        let (rd, value) = decode_mov_wide(0x528e_1288, &regs).expect("movz");
        assert_eq!(rd, 8);
        assert_eq!(value, 0x7094);
        regs.insert(rd, RegValue::Imm(value));
        let (_, value) = decode_mov_wide(0x72a6_2348, &regs).expect("movk");
        assert_eq!(value, 0x311a_7094);
    }

    #[test]
    fn decodes_add_sp_lsl12() {
        let (rd, rn, imm) = decode_add_imm(0x9140_13e9).expect("add");
        assert_eq!((rd, rn, imm), (9, 31, 0x4000));
    }

    #[test]
    fn decodes_str_w_unsigned_offset() {
        let mem = decode_unsigned_mem(0xb904_8128).expect("str");
        assert_eq!(mem.rt, 8);
        assert_eq!(mem.rn, 9);
        assert_eq!(mem.disp, 0x480);
        assert_eq!(mem.size, 4);
        assert!(!mem.load);
    }

    #[test]
    fn formats_binary_xor_key_as_hex() {
        assert_eq!(format_xor_key(&[0xff, 0x19, 0x76]), "0xff1976");
    }
}
