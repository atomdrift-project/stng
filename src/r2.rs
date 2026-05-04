//! Optional rizin/radare2 integration for smarter string extraction.
pub mod cache;
use crate::classifier::classify_string;
use crate::{ExtractedString, FunctionMetadata, StringKind, StringMethod};
use cache::R2Cache;
use std::collections::HashSet;
use std::process::Command;
use std::sync::OnceLock;

static TOOL: OnceLock<Option<&'static str>> = OnceLock::new();
#[must_use]
pub fn is_available() -> bool {
    get_tool().is_some()
}
pub fn flush_cache(file_path: &str) -> Result<(), std::io::Error> {
    R2Cache::new()?.clear(file_path)
}
fn get_tool() -> Option<&'static str> {
    *TOOL.get_or_init(|| {
        if Command::new("rizin")
            .arg("-v")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            Some("rizin")
        } else if Command::new("r2")
            .arg("-v")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            Some("r2")
        } else {
            None
        }
    })
}

#[must_use]
pub fn extract_string_boundaries(path: &str) -> Option<Vec<StringBoundary>> {
    let tool = get_tool()?;
    let file_size = std::fs::metadata(path).ok()?.len();
    if file_size > 10 * 1024 * 1024 {
        return None;
    }
    let data_strings = run_tool_command(tool, path, "izzj")?;
    if let Ok(json) = serde_json::from_str::<Vec<R2String>>(&data_strings) {
        Some(
            json.iter()
                .map(|s| StringBoundary {
                    offset: s.paddr,
                    length: if s.length > 0 {
                        s.length
                    } else {
                        s.string.len()
                    },
                })
                .collect(),
        )
    } else {
        None
    }
}

#[derive(serde::Deserialize, Clone)]
struct R2String {
    paddr: u64,
    string: String,
    section: String,
    #[serde(default)]
    length: usize,
}
#[derive(Debug, Clone)]
pub struct StringBoundary {
    pub offset: u64,
    pub length: usize,
}
#[derive(serde::Deserialize)]
struct R2Symbol {
    paddr: u64,
    name: String,
    #[serde(default)]
    section: Option<String>,
    #[serde(default)]
    r#type: String,
    #[serde(default)]
    bind: String,
}

#[must_use]
pub fn extract_strings(
    path: &str,
    min_length: usize,
    use_cache: bool,
) -> Option<Vec<ExtractedString>> {
    let tool = get_tool()?;
    let file_size = std::fs::metadata(path).ok()?.len();
    let is_large_file = file_size > 10 * 1024 * 1024;
    let path_owned = path.to_string();
    let (data_result, symbols_result) = if is_large_file {
        (
            None,
            run_tool_command_with_cache(tool, &path_owned, "isj", use_cache),
        )
    } else {
        rayon::join(
            || run_tool_command_with_cache(tool, &path_owned, "izzj", use_cache),
            || run_tool_command_with_cache(tool, &path_owned, "isj", use_cache),
        )
    };

    let mut strings = Vec::new();
    let mut seen = HashSet::new();
    if let Some(data_strings) = data_result {
        if let Ok(json) = serde_json::from_str::<Vec<R2String>>(&data_strings) {
            for s in json {
                if s.paddr > file_size {
                    continue;
                }
                if s.string.len() >= min_length && seen.insert(s.string.clone()) {
                    if let Some(decoded) = decode_spaced_ascii(&s.string) {
                        if decoded.len() >= min_length && seen.insert(decoded.clone()) {
                            let kind = classify_string(&decoded);
                            strings.push(ExtractedString {
                                value: decoded,
                                data_offset: s.paddr,
                                section: Some(s.section.clone()),
                                method: StringMethod::SpacedAscii,
                                kind,
                                raw: Some(s.string.clone()),
                                ..Default::default()
                            });
                        }
                    } else {
                        let kind = classify_string(&s.string);
                        strings.push(ExtractedString {
                            value: s.string,
                            data_offset: s.paddr,
                            section: Some(s.section),
                            method: StringMethod::R2String,
                            kind,
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }
    let function_metadata = extract_function_metadata(path, file_size, use_cache);
    if let Some(symbols) = symbols_result {
        if let Ok(json) = serde_json::from_str::<Vec<R2Symbol>>(&symbols) {
            for s in json {
                if s.paddr > file_size {
                    continue;
                }
                if s.name.len() >= min_length && seen.insert(s.name.clone()) {
                    let kind = Some(classify_r2_symbol(&s.r#type, &s.bind));
                    let func_meta = if s.r#type == "FUNC" || s.r#type == "METH" {
                        function_metadata.as_ref().and_then(|map| {
                            map.get(&s.name).cloned().or_else(|| {
                                let clean = s
                                    .name
                                    .strip_prefix("sym.")
                                    .or_else(|| s.name.strip_prefix("sym.imp."))
                                    .unwrap_or(&s.name);
                                map.get(clean).cloned()
                            })
                        })
                    } else {
                        None
                    };
                    strings.push(ExtractedString {
                        value: s.name,
                        data_offset: s.paddr,
                        section: s.section,
                        method: StringMethod::R2Symbol,
                        kind,
                        function_meta: func_meta,
                        ..Default::default()
                    });
                }
            }
        }
    }
    if strings.is_empty() {
        None
    } else {
        Some(strings)
    }
}

#[must_use]
pub fn extract_function_metadata(
    path: &str,
    file_size: u64,
    use_cache: bool,
) -> Option<std::collections::HashMap<String, FunctionMetadata>> {
    if file_size > 2 * 1024 * 1024 {
        return None;
    }
    let tool = get_tool()?;
    let functions_json = run_tool_command_with_cache(tool, path, "aa; aflj", use_cache)?;
    #[derive(serde::Deserialize)]
    struct R2Function {
        name: String,
        #[serde(default)]
        size: u64,
        #[serde(default)]
        nbbs: u64,
        #[serde(default)]
        edges: u64,
        #[serde(default)]
        ninstrs: u64,
        #[serde(default)]
        signature: Option<String>,
        #[serde(default)]
        noreturn: bool,
    }
    let functions: Vec<R2Function> = serde_json::from_str(&functions_json).ok()?;
    let mut metadata_map = std::collections::HashMap::new();
    for func in functions {
        let clean = func
            .name
            .strip_prefix("sym.")
            .or_else(|| func.name.strip_prefix("sym.imp."))
            .unwrap_or(&func.name)
            .to_string();
        metadata_map.insert(
            clean,
            FunctionMetadata {
                size: func.size,
                basic_blocks: func.nbbs,
                branches: func.edges,
                instructions: func.ninstrs,
                signature: func.signature,
                noreturn: if func.noreturn { Some(true) } else { None },
            },
        );
    }
    Some(metadata_map)
}

fn run_tool_command(tool: &str, path: &str, cmd: &str) -> Option<String> {
    run_tool_command_with_cache(tool, path, cmd, true)
}
fn run_tool_command_with_cache(
    tool: &str,
    path: &str,
    cmd: &str,
    use_cache: bool,
) -> Option<String> {
    if use_cache {
        if let Ok(cache) = R2Cache::new() {
            if let Some(cached) = cache.get(path, cmd) {
                return Some(cached);
            }
        }
    }
    let output = Command::new(tool)
        .args(["-q", "-c", cmd, path])
        .output()
        .ok()?;
    if output.status.success() {
        let result = String::from_utf8(output.stdout).ok()?;
        if use_cache {
            if let Ok(cache) = R2Cache::new() {
                let _ = cache.set(path, cmd, &result);
            }
        }
        Some(result)
    } else {
        None
    }
}

#[must_use]
pub fn decode_spaced_ascii(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.len() < 6 {
        return None;
    }
    let mut wide_pairs = 0;
    let mut total_pairs = 0;
    for i in (0..bytes.len() - 1).step_by(2) {
        total_pairs += 1;
        if (bytes[i].is_ascii_graphic() || bytes[i] == b' ')
            && (bytes[i + 1] == 0 || bytes[i + 1] == b' ')
        {
            wide_pairs += 1;
        }
    }
    if total_pairs < 4 || wide_pairs * 100 / total_pairs < 70 {
        return None;
    }
    let mut decoded = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_graphic() || bytes[i] == b' ' {
            decoded.push(bytes[i]);
            if i + 1 < bytes.len() && (bytes[i + 1] == 0 || bytes[i + 1] == b' ') {
                i += 2;
                continue;
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    let result = String::from_utf8(decoded).ok()?;
    if result.trim().len() >= 4 {
        Some(result.trim().to_string())
    } else {
        None
    }
}

fn classify_r2_symbol(type_str: &str, _bind: &str) -> StringKind {
    match type_str {
        "FUNC" | "METH" => StringKind::FuncName,
        "FILE" => StringKind::FilePath,
        _ => StringKind::Ident,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XorConfidence {
    High,
    Medium,
    Low,
}
#[derive(Debug, Clone)]
pub struct XorKeyInfo {
    pub key: Option<Vec<u8>>,
    pub length: usize,
    pub confidence: XorConfidence,
    pub reference_count: usize,
    pub offset: u64,
    pub source: String,
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let mut entropy = 0.0;
    let len = data.len() as f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[derive(serde::Deserialize, Default)]
struct R2Section {
    #[serde(default)]
    name: String,
    #[serde(default)]
    paddr: u64,
    #[serde(default)]
    vaddr: u64,
    #[serde(default)]
    vsize: u64,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    perm: String,
}
fn get_sections(tool: &str, path: &str) -> Vec<R2Section> {
    if let Some(output) = run_tool_command(tool, path, "iSj") {
        serde_json::from_str::<Vec<R2Section>>(&output).unwrap_or_default()
    } else {
        Vec::new()
    }
}
fn vaddr_to_paddr(vaddr: u64, sections: &[R2Section]) -> Option<u64> {
    for s in sections {
        if s.vsize > 0 && vaddr >= s.vaddr && vaddr < s.vaddr + s.vsize {
            return Some(s.paddr + (vaddr - s.vaddr));
        }
    }
    if vaddr >= 0x140000000 {
        Some(vaddr - 0x140000000)
    } else {
        None
    }
}

#[must_use]
pub fn extract_binary_xor_candidates(path: &str, data: &[u8]) -> Vec<ExtractedString> {
    let tool = get_tool().unwrap_or("rizin");
    let sections = get_sections(tool, path);
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    for section in sections {
        if section.perm.contains('x') || section.size == 0 {
            continue;
        }
        let Ok(start) = usize::try_from(section.paddr) else {
            continue;
        };
        let Ok(size) = usize::try_from(section.size) else {
            continue;
        };
        let end = start.saturating_add(size).min(data.len());
        if start >= end {
            continue;
        }
        let section_data = &data[start..end];
        for window in [16, 32, 64, 8] {
            if section_data.len() < window {
                continue;
            }
            for i in 0..=section_data.len() - window {
                let offset = (start + i) as u64;
                if seen.contains(&offset) {
                    continue;
                }
                let chunk = &section_data[i..i + window];
                if calculate_entropy(chunk) > 3.5 {
                    candidates.push(ExtractedString {
                        value: String::from_utf8_lossy(chunk).to_string(),
                        data_offset: offset,
                        section: Some(section.name.clone()),
                        method: StringMethod::Heuristic,
                        kind: Some(StringKind::XorKey),
                        raw: Some(hex::encode(chunk)),
                        ..Default::default()
                    });
                    seen.insert(offset);
                    if candidates.len() > 1000 {
                        return candidates;
                    }
                }
            }
        }
    }
    candidates
}

#[must_use]
pub fn verify_xor_keys(
    path: &str,
    _data: &[u8],
    candidates: &[ExtractedString],
) -> Vec<XorKeyInfo> {
    let Some(tool) = get_tool() else {
        return Vec::new();
    };
    let sections = get_sections(tool, path);
    let mut instr_results = Vec::new();
    let mut seen_keys = HashSet::new();
    let mut xor_instrs = Vec::new();
    if let Some(output) = run_tool_command(tool, path, "aaa; /at xor") {
        for line in output.lines() {
            if let Ok(addr) = u64::from_str_radix(
                line.split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_start_matches("0x"),
                16,
            ) {
                xor_instrs.push(addr);
            }
        }
    }
    if let Some(output) = run_tool_command(tool, path, "aaa; /at lea") {
        for line in output.lines() {
            if let Ok(lea_addr) = u64::from_str_radix(
                line.split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_start_matches("0x"),
                16,
            ) {
                if xor_instrs.iter().any(|&x| {
                    if x >= lea_addr {
                        x - lea_addr < 256
                    } else {
                        lea_addr - x < 256
                    }
                }) {
                    if let Some(ao_output) =
                        run_tool_command(tool, path, &format!("aoj 1 @ 0x{lea_addr:x}"))
                    {
                        if let Ok(json) = serde_json::from_str::<Vec<serde_json::Value>>(&ao_output)
                        {
                            if let Some(vaddr) = json
                                .first()
                                .and_then(|i| i.get("ptr"))
                                .and_then(serde_json::Value::as_u64)
                            {
                                if let Some(paddr) = vaddr_to_paddr(vaddr, &sections) {
                                    if !seen_keys.contains(&paddr) {
                                        for len in [16, 32, 8] {
                                            instr_results.push(XorKeyInfo {
                                                offset: paddr,
                                                key: None,
                                                length: len,
                                                confidence: XorConfidence::High,
                                                reference_count: 1,
                                                source: format!(
                                                    "xor_lea_prox_{len}@0x{lea_addr:x}"
                                                ),
                                            });
                                        }
                                        seen_keys.insert(paddr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let mut results = Vec::new();
    for c in candidates
        .iter()
        .filter(|candidate| (8..=64).contains(&candidate.value.len()))
        .take(100)
    {
        results.push(XorKeyInfo {
            key: Some(c.value.as_bytes().to_vec()),
            length: c.value.len(),
            confidence: XorConfidence::Low,
            reference_count: 1,
            offset: c.data_offset,
            source: "string_candidate".to_string(),
        });
    }
    for ir in instr_results {
        if !results
            .iter()
            .any(|r| r.offset == ir.offset && r.length == ir.length)
        {
            results.push(ir);
        }
    }
    results
}

#[must_use]
pub fn extract_connect_addrs(path: &str, data: &[u8]) -> Vec<ExtractedString> {
    let Some(tool) = get_tool() else {
        return Vec::new();
    };
    if data.len() > 10 * 1024 * 1024 {
        return scan_binary_for_connect_addrs(data);
    }
    let Some(output) = run_tool_command(tool, path, "aaa; e scr.color=0; s entry0; pdf") else {
        return Vec::new();
    };
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    if !output.contains("283")
        && !output.contains("syscall.connect")
        && !output.contains("sym.imp.connect")
    {
        return Vec::new();
    }
    if let Some(sockaddr) = parse_sockaddr_from_disasm(&output, data) {
        let ip = format!(
            "{}.{}.{}.{}",
            sockaddr.ip[0], sockaddr.ip[1], sockaddr.ip[2], sockaddr.ip[3]
        );
        let val = if sockaddr.port > 0 {
            format!("{}:{}", ip, sockaddr.port)
        } else {
            ip
        };
        if seen.insert(val.clone()) {
            results.push(ExtractedString {
                value: val,
                data_offset: sockaddr.offset,
                section: Some(".text".to_string()),
                method: StringMethod::InstructionPattern,
                kind: if sockaddr.port > 0 {
                    Some(StringKind::IPPort)
                } else {
                    Some(StringKind::IP)
                },
                source: Some("connect()".to_string()),
                ..Default::default()
            });
        }
    } else {
        for sockaddr in find_sockaddr_in_binary(data) {
            let ip = format!(
                "{}.{}.{}.{}",
                sockaddr.ip[0], sockaddr.ip[1], sockaddr.ip[2], sockaddr.ip[3]
            );
            let val = if sockaddr.port > 0 {
                format!("{}:{}", ip, sockaddr.port)
            } else {
                ip
            };
            if seen.insert(val.clone()) {
                results.push(ExtractedString {
                    value: val,
                    data_offset: sockaddr.offset,
                    section: Some(".text".to_string()),
                    method: StringMethod::InstructionPattern,
                    kind: if sockaddr.port > 0 {
                        Some(StringKind::IPPort)
                    } else {
                        Some(StringKind::IP)
                    },
                    source: Some("connect()".to_string()),
                    ..Default::default()
                });
            }
        }
    }
    results
}

fn scan_binary_for_connect_addrs(data: &[u8]) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    for sockaddr in find_sockaddr_in_binary(data) {
        let ip = format!(
            "{}.{}.{}.{}",
            sockaddr.ip[0], sockaddr.ip[1], sockaddr.ip[2], sockaddr.ip[3]
        );
        let val = if sockaddr.port > 0 {
            format!("{}:{}", ip, sockaddr.port)
        } else {
            ip
        };
        if seen.insert(val.clone()) {
            results.push(ExtractedString {
                value: val,
                data_offset: sockaddr.offset,
                section: Some(".text".to_string()),
                method: StringMethod::InstructionPattern,
                kind: if sockaddr.port > 0 {
                    Some(StringKind::IPPort)
                } else {
                    Some(StringKind::IP)
                },
                source: Some("connect()".to_string()),
                ..Default::default()
            });
        }
    }
    results
}

#[derive(Debug)]
struct SockaddrIn {
    ip: [u8; 4],
    port: u16,
    offset: u64,
}
fn parse_sockaddr_from_disasm(disasm: &str, _data: &[u8]) -> Option<SockaddrIn> {
    let (mut ip, mut port, mut offset, mut found, mut pending) = ([0u8; 4], 0u16, 0u64, 0, None);
    for line in disasm.lines() {
        if let Some(addr_str) = line.split_whitespace().next() {
            if let Ok(addr) = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16) {
                if offset == 0 {
                    offset = addr;
                }
            }
        }
        if (line.contains(" mov ") && line.contains(", #")) || line.contains(", 0x") {
            if let Some(imm) = line.rfind(", ") {
                if let Some(val) = line[imm + 2..].split_whitespace().next() {
                    if let Ok(b) = parse_imm(val) {
                        pending = Some(b);
                    }
                }
            }
        }
        if line.contains("strb") || line.contains("str ") {
            if let (Some(b), Some(sp)) = (pending, extract_stack_off(line)) {
                if (4..=7).contains(&sp) {
                    ip[sp as usize - 4] = b;
                    found += 1;
                } else if sp == 2 {
                    port = u16::from(b) << 8;
                } else if sp == 3 {
                    port |= u16::from(b);
                }
                pending = None;
            }
        }
    }
    if found == 4 && !is_z(&ip) {
        Some(SockaddrIn { ip, port, offset })
    } else {
        None
    }
}
fn parse_imm(s: &str) -> Result<u8, std::num::ParseIntError> {
    let c = s
        .trim_start_matches("0x")
        .trim_end_matches(|c: char| !c.is_ascii_hexdigit());
    if s.starts_with("0x") {
        u8::from_str_radix(c, 16)
    } else {
        c.parse::<u8>()
    }
}
fn extract_stack_off(line: &str) -> Option<u8> {
    let p: Vec<&str> = line.split_whitespace().collect();
    if p.len() >= 2 && p[1].len() >= 8 {
        if let Ok(o) = u8::from_str_radix(&p[1][0..2], 16) {
            return Some(o);
        }
    }
    if let Some(sp) = line.find("sp,") {
        if let Some(n) = line[sp + 3..]
            .trim_start_matches(|c: char| c.is_whitespace() || c == '#')
            .split(&[']', ','][..])
            .next()
        {
            return parse_imm(n).ok();
        }
    }
    None
}
fn is_z(ip: &[u8; 4]) -> bool {
    ip.iter().all(|&b| b == 0) || ip[0] == 0 || ip[0] >= 224
}
fn find_sockaddr_in_binary(data: &[u8]) -> Vec<SockaddrIn> {
    let mut res = Vec::new();
    let mut i = 0;
    while i + 32 <= data.len() {
        let (mut ip, mut f) = ([0u8; 4], 0);
        for j in 0..32 {
            if i + j + 8 > data.len() {
                break;
            }
            if data[i + j + 2] == 0xA0 && data[i + j + 3] == 0xE3 {
                let b = data[i + j];
                if i + j + 7 < data.len() && data[i + j + 6] == 0xCD && data[i + j + 7] == 0xE5 {
                    let o = data[i + j + 4];
                    if (4..=7).contains(&o) {
                        ip[o as usize - 4] = b;
                        f |= 1 << (o - 4);
                    }
                }
            }
        }
        if f == 15 && !is_z(&ip) {
            res.push(SockaddrIn {
                ip,
                port: 0,
                offset: i as u64,
            });
            i += 32;
        } else {
            i += 4;
        }
    }
    res
}
