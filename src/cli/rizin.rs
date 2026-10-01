//! rizin/radare2 integration for the stng CLI. The library runs no
//! subprocesses: this module runs rizin, caches its output (see [`cache`]) and
//! hands the results to extraction through [`stng::ExtractOptions`].
pub(crate) mod cache;
use cache::R2Cache;
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use stng::goblin::Object;
use stng::{
    ExtractOptions, ExtractedString, StringBoundary, StringKind, StringMethod, classify_string,
};

static TOOL: OnceLock<Option<&'static str>> = OnceLock::new();

/// In-process memoization of tool command outputs, keyed by
/// `(path, command, file size, mtime)`. Several extraction passes ask for the
/// same command on the same file (e.g. `izzj` for both string extraction and
/// XOR boundary hints); each spawn costs a full rizin startup + scan, so the
/// second caller waits on the first instead of re-running it. The size/mtime
/// key components keep long-lived library callers safe if a file changes on
/// disk between extractions; the size cap bounds growth for such callers.
type MemoKey = (String, String, u64, Option<std::time::SystemTime>);
type MemoCell = Arc<OnceLock<Option<Arc<String>>>>;
static MEMO: LazyLock<Mutex<HashMap<MemoKey, MemoCell>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
const MEMO_MAX_ENTRIES: usize = 16;
#[must_use]
pub(crate) fn is_available() -> bool {
    get_tool().is_some()
}
pub(crate) fn flush_cache(file_path: &str) -> Result<(), std::io::Error> {
    R2Cache::new()?.clear(file_path)
}
fn get_tool() -> Option<&'static str> {
    *TOOL.get_or_init(|| {
        if Command::new("rizin")
            .arg("-v")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            Some("rizin")
        } else if Command::new("r2")
            .arg("-v")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            Some("r2")
        } else {
            None
        }
    })
}

#[must_use]
pub(crate) fn extract_string_boundaries(
    path: &str,
    use_cache: bool,
) -> Option<Vec<StringBoundary>> {
    let tool = get_tool()?;
    let file_size = std::fs::metadata(path).ok()?.len();
    if file_size > 10 * 1024 * 1024 {
        return None;
    }
    let data_strings = run_tool_command_with_cache(tool, path, "izzj", use_cache)?;
    serde_json::from_str::<Vec<R2String>>(&data_strings)
        .ok()
        .map(|json| {
            json.iter()
                .map(|s| StringBoundary {
                    offset: s.paddr,
                    length: if s.length > 0 {
                        s.length
                    } else {
                        s.string.len()
                    },
                })
                .collect()
        })
}

#[derive(serde::Deserialize, Clone)]
struct R2String {
    paddr: u64,
    string: String,
    #[serde(default)]
    length: usize,
}
#[derive(serde::Deserialize)]
struct R2Symbol {
    paddr: u64,
    name: String,
    #[serde(default)]
    r#type: String,
}

#[must_use]
pub(crate) fn extract_strings(
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
    if let Some(data_strings) = data_result
        && let Ok(json) = serde_json::from_str::<Vec<R2String>>(&data_strings)
    {
        for s in json {
            if s.paddr > file_size {
                continue;
            }
            if s.string.len() >= min_length && seen.insert(s.string.clone()) {
                if let Some(decoded) = stng::decode_spaced_ascii(&s.string) {
                    if decoded.len() >= min_length && seen.insert(decoded.clone()) {
                        let kind = classify_string(&decoded);
                        strings.push(ExtractedString {
                            value: decoded,
                            data_offset: s.paddr,
                            method: StringMethod::SpacedAscii,
                            kind,
                            ..Default::default()
                        });
                    }
                } else {
                    let kind = classify_string(&s.string);
                    strings.push(ExtractedString {
                        value: s.string,
                        data_offset: s.paddr,
                        method: StringMethod::R2String,
                        kind,
                        ..Default::default()
                    });
                }
            }
        }
    }
    if let Some(symbols) = symbols_result
        && let Ok(json) = serde_json::from_str::<Vec<R2Symbol>>(&symbols)
    {
        for s in json {
            if s.paddr > file_size {
                continue;
            }
            if s.name.len() >= min_length && seen.insert(s.name.clone()) {
                let kind = Some(match s.r#type.as_str() {
                    "FUNC" | "METH" => StringKind::FuncName,
                    "FILE" => StringKind::FilePath,
                    _ => StringKind::Ident,
                });
                strings.push(ExtractedString {
                    value: s.name,
                    data_offset: s.paddr,
                    method: StringMethod::R2Symbol,
                    kind,
                    ..Default::default()
                });
            }
        }
    }
    if strings.is_empty() {
        None
    } else {
        Some(strings)
    }
}

fn run_tool_command_with_cache(
    tool: &str,
    path: &str,
    cmd: &str,
    use_cache: bool,
) -> Option<Arc<String>> {
    let key = match std::fs::metadata(path) {
        Ok(m) => (
            path.to_string(),
            cmd.to_string(),
            m.len(),
            m.modified().ok(),
        ),
        Err(_) => (path.to_string(), cmd.to_string(), 0, None),
    };
    let cell = {
        let mut memo = match MEMO.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if memo.len() >= MEMO_MAX_ENTRIES && !memo.contains_key(&key) {
            memo.clear();
        }
        memo.entry(key).or_default().clone()
    };
    cell.get_or_init(|| spawn_tool_command(tool, path, cmd, use_cache).map(Arc::new))
        .clone()
}

fn spawn_tool_command(tool: &str, path: &str, cmd: &str, use_cache: bool) -> Option<String> {
    if use_cache
        && let Ok(cache) = R2Cache::new()
        && let Some(cached) = cache.get(path, cmd)
    {
        return Some(cached);
    }
    let output = Command::new(tool)
        .args(["-q", "-c", cmd, path])
        .output()
        .ok()?;
    if output.status.success() {
        let result = String::from_utf8(output.stdout).ok()?;
        if use_cache && let Ok(cache) = R2Cache::new() {
            let _ = cache.set(path, cmd, &result);
        }
        Some(result)
    } else {
        None
    }
}

#[derive(serde::Deserialize, Default)]
struct R2Section {
    #[serde(default)]
    paddr: u64,
    #[serde(default)]
    vaddr: u64,
    #[serde(default)]
    vsize: u64,
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

/// File offsets of XOR keys: the operand of each `lea` within 256 bytes of a
/// `xor` instruction, mapped from its virtual address to the file.
fn xor_key_offsets(path: &str, use_cache: bool) -> Vec<u64> {
    let Some(tool) = get_tool() else {
        return Vec::new();
    };
    let sections: Vec<R2Section> = run_tool_command_with_cache(tool, path, "iSj", use_cache)
        .and_then(|output| serde_json::from_str(&output).ok())
        .unwrap_or_default();
    let mut offsets = Vec::new();
    let mut seen_keys = HashSet::new();
    let mut xor_instrs = Vec::new();
    // Run both instruction searches in one rizin session: `aaa` is by far the
    // most expensive step, so two separate subprocesses would redo the whole
    // analysis. `/at` prints one match per line, each starting with `0x<addr>`,
    // and emits the xor-search hits before the lea-search hits. A `p8 1 @ 0`
    // between them prints a single line of bare hex (never `0x…`), so the
    // first non-`0x` line marks the xor→lea boundary — architecture-independent,
    // unlike matching on the mnemonic (ARM uses `eor`/`adrp`, not `xor`/`lea`).
    let instr_output =
        run_tool_command_with_cache(tool, path, "aaa; /at xor; p8 1 @ 0; /at lea", use_cache);
    let mut lea_addrs = Vec::new();
    let mut in_lea = false;
    for line in instr_output
        .as_deref()
        .map(String::as_str)
        .unwrap_or("")
        .lines()
    {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(hex) = line.strip_prefix("0x") else {
            in_lea = true; // the p8 marker line separating the two searches
            continue;
        };
        let Ok(addr) = u64::from_str_radix(hex.split_whitespace().next().unwrap_or(""), 16) else {
            continue;
        };
        if in_lea {
            lea_addrs.push(addr);
        } else {
            xor_instrs.push(addr);
        }
    }
    // Keep only lea addresses within 256 bytes of a xor instruction, then
    // decode them all in a single batched session — each `aoj` subprocess
    // would otherwise pay a full tool startup + binary load. `aoj 1` emits one
    // JSON array per address, so the batched output is a whitespace-separated
    // stream of arrays parsed in order (no `aaa` needed — `aoj` analyses a
    // single op at the given address).
    let near_xor: Vec<u64> = lea_addrs
        .into_iter()
        .filter(|&lea_addr| {
            xor_instrs.iter().any(|&x| {
                if x >= lea_addr {
                    x - lea_addr < 256
                } else {
                    lea_addr - x < 256
                }
            })
        })
        .collect();
    if !near_xor.is_empty() {
        let batched = near_xor
            .iter()
            .map(|addr| format!("aoj 1 @ 0x{addr:x}"))
            .collect::<Vec<_>>()
            .join("; ");
        let ao_outputs = run_tool_command_with_cache(tool, path, &batched, use_cache);
        let stream = serde_json::Deserializer::from_str(
            ao_outputs.as_deref().map(String::as_str).unwrap_or(""),
        )
        .into_iter::<Vec<serde_json::Value>>();
        for json in stream.flatten() {
            if let Some(vaddr) = json
                .first()
                .and_then(|i| i.get("ptr"))
                .and_then(serde_json::Value::as_u64)
                && let Some(paddr) = vaddr_to_paddr(vaddr, &sections)
                && !seen_keys.contains(&paddr)
            {
                offsets.push(paddr);
                seen_keys.insert(paddr);
            }
        }
    }
    offsets
}

#[must_use]
pub(crate) fn extract_connect_addrs(
    path: &str,
    data: &[u8],
    use_cache: bool,
) -> Vec<ExtractedString> {
    let Some(tool) = get_tool() else {
        return Vec::new();
    };
    if data.len() > 10 * 1024 * 1024 {
        return scan_binary_for_connect_addrs(data);
    }
    let Some(output) =
        run_tool_command_with_cache(tool, path, "aaa; e scr.color=0; s entry0; pdf", use_cache)
    else {
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
        let es = sockaddr_to_string(&sockaddr);
        if seen.insert(es.value.clone()) {
            results.push(es);
        }
        results
    } else {
        scan_binary_for_connect_addrs(data)
    }
}

/// Render a parsed sockaddr as an `ip` or `ip:port` ExtractedString.
fn sockaddr_to_string(sockaddr: &SockaddrIn) -> ExtractedString {
    let ip = format!(
        "{}.{}.{}.{}",
        sockaddr.ip[0], sockaddr.ip[1], sockaddr.ip[2], sockaddr.ip[3]
    );
    let (value, kind) = if sockaddr.port > 0 {
        (format!("{ip}:{}", sockaddr.port), Some(StringKind::IPPort))
    } else {
        (ip, Some(StringKind::IP))
    };
    ExtractedString {
        value,
        data_offset: sockaddr.offset,
        method: StringMethod::InstructionPattern,
        kind,
        ..Default::default()
    }
}

fn scan_binary_for_connect_addrs(data: &[u8]) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    for sockaddr in find_sockaddr_in_binary(data) {
        let es = sockaddr_to_string(&sockaddr);
        if seen.insert(es.value.clone()) {
            results.push(es);
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
        if let Some(addr_str) = line.split_whitespace().next()
            && let Ok(addr) = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16)
            && offset == 0
        {
            offset = addr;
        }
        if ((line.contains(" mov ") && line.contains(", #")) || line.contains(", 0x"))
            && let Some(imm) = line.rfind(", ")
            && let Some(val) = line[imm + 2..].split_whitespace().next()
            && let Ok(b) = parse_imm(val)
        {
            pending = Some(b);
        }
        if (line.contains("strb") || line.contains("str "))
            && let (Some(b), Some(sp)) = (pending, extract_stack_off(line))
        {
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
    if p.len() >= 2
        && p[1].len() >= 8
        && let Some(s) = p[1].get(0..2)
        && let Ok(o) = u8::from_str_radix(s, 16)
    {
        return Some(o);
    }
    if let Some(sp) = line.find("sp,")
        && let Some(n) = line[sp + 3..]
            .trim_start_matches(|c: char| c.is_whitespace() || c == '#')
            .split(&[']', ','][..])
            .next()
    {
        return parse_imm(n).ok();
    }
    None
}
fn is_z(ip: &[u8; 4]) -> bool {
    ip[0] == 0 || ip[0] >= 224
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

/// Files above this size get no rizin analysis: `aaa` on them takes minutes.
const MAX_ANALYSIS_SIZE: usize = 10 * 1024 * 1024;

/// Run the rizin analyses extraction can use on the file at `path` (whose
/// bytes are `data`) and attach the results to `opts`. They run concurrently;
/// `izzj` is shared through the memo, and each `aaa` is the expensive part.
///
/// - strings and symbols, except for Go binaries, whose strings come from
///   their own structures;
/// - string extents, when `xor` scanning will use them to aim decoding;
/// - `connect()` addresses, for files that may be ARM, the only architecture
///   that pass understands;
/// - XOR key locations, when `xorscan` asks for them.
pub(crate) fn attach(
    mut opts: ExtractOptions,
    path: &str,
    data: &[u8],
    xor: bool,
    xorscan: bool,
    use_cache: bool,
) -> ExtractOptions {
    let min_length = opts.min_length;
    let strings = !stng::is_go_binary(data);
    let connect = data.len() <= MAX_ANALYSIS_SIZE
        && Object::parse(data)
            .is_ok_and(|o| !matches!(o, Object::Unknown(_)) && arm_arch_possible(&o));
    let (strings, boundaries, connect, keys) = std::thread::scope(|scope| {
        let strings = strings.then(|| scope.spawn(|| extract_strings(path, min_length, use_cache)));
        let boundaries = xor.then(|| scope.spawn(|| extract_string_boundaries(path, use_cache)));
        let connect = connect.then(|| scope.spawn(|| extract_connect_addrs(path, data, use_cache)));
        let keys = xorscan.then(|| scope.spawn(|| xor_key_offsets(path, use_cache)));
        (
            strings.and_then(|h| h.join().ok()).flatten(),
            boundaries.and_then(|h| h.join().ok()).flatten(),
            connect.and_then(|h| h.join().ok()),
            keys.and_then(|h| h.join().ok()),
        )
    });
    if let Some(strings) = strings {
        opts = opts.with_r2_strings(strings);
    }
    if let Some(boundaries) = boundaries {
        opts = opts.with_rizin_boundaries(boundaries);
    }
    if let Some(connect) = connect {
        opts = opts.with_rizin_connect_addrs(connect);
    }
    if let Some(keys) = keys {
        opts = opts.with_xor_key_offsets(keys);
    }
    opts
}

/// Whether `object` could be an ARM binary (32- or 64-bit), including
/// formats whose architecture we can't positively identify.
///
/// The connect()-address disassembly pass only understands ARM patterns:
/// its entry-point scan greps for the ARM EABI connect syscall number (283)
/// or a direct connect call, and its parser matches `strb`/`str` stores to
/// `sp`-relative sockaddr offsets. On a positively-identified non-ARM
/// binary that pass cannot produce a true detection, so spending a full
/// rizin `aaa` analysis on it buys nothing.
fn arm_arch_possible(object: &Object<'_>) -> bool {
    use stng::goblin::mach::constants::cputype::{CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_ARM64_32};
    match object {
        Object::Elf(elf) => matches!(
            elf.header.e_machine,
            stng::goblin::elf::header::EM_ARM | stng::goblin::elf::header::EM_AARCH64
        ),
        Object::PE(pe) => matches!(
            pe.header.coff_header.machine,
            stng::goblin::pe::header::COFF_MACHINE_ARM
                | stng::goblin::pe::header::COFF_MACHINE_ARMNT
                | stng::goblin::pe::header::COFF_MACHINE_ARM64
                | stng::goblin::pe::header::COFF_MACHINE_THUMB
        ),
        Object::Mach(stng::goblin::mach::Mach::Binary(macho)) => matches!(
            macho.header.cputype,
            CPU_TYPE_ARM | CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32
        ),
        Object::Mach(stng::goblin::mach::Mach::Fat(fat)) => fat.arches().map_or(true, |arches| {
            arches
                .iter()
                .any(|a| matches!(a.cputype, CPU_TYPE_ARM | CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32))
        }),
        _ => true,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn extract_stack_off_multibyte_does_not_panic() {
        // Lines from r2 visual output can contain box-drawing chars like '│'
        // whose first byte spans multiple bytes — slicing &s[0..2] would
        // panic at a non-char boundary.
        assert_eq!(extract_stack_off("  │││  something"), None);
        assert_eq!(extract_stack_off("x │││││││ y"), None);
    }

    #[test]
    fn extract_stack_off_hex_prefix() {
        // 8+ char ASCII token in second column parses as hex u8 from first 2 chars.
        assert_eq!(extract_stack_off("op 0412abcd rest"), Some(0x04));
    }

    #[test]
    fn extract_stack_off_sp_offset() {
        assert_eq!(extract_stack_off("str w8, [sp, #0x4]"), Some(4));
    }
}

/// Moved from `tests/` when this module moved from the library to the CLI.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod helper_tests {
    /// Additional tests for r2 module helper functions
    /// Covers src/r2.rs helper functions and edge cases
    use std::fs;
    use std::path::PathBuf;

    // Helper to create a unique temporary file path
    fn temp_file_path(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "{}_{}_{}.bin",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        path
    }

    // Helper to create a temporary file with content
    fn create_temp_file(prefix: &str, content: &[u8]) -> PathBuf {
        let path = temp_file_path(prefix);
        fs::write(&path, content).unwrap();
        path
    }

    /// Test flush_cache with non-existent file
    #[test]
    fn test_flush_cache_nonexistent_file() {
        let fake_path = "/tmp/nonexistent_file_for_r2_test_12345.bin";

        // Should fail gracefully (cache module handles this)
        let result = super::flush_cache(fake_path);

        // Error is acceptable for non-existent file
        let _ = result;
    }

    /// Test flush_cache with real file
    #[test]
    fn test_flush_cache_real_file() {
        let temp_path = create_temp_file("r2_flush", b"test content for flush");
        let file_path = temp_path.to_str().unwrap();

        // Should succeed even if cache doesn't exist
        let result = super::flush_cache(file_path);
        assert!(result.is_ok(), "Flush should succeed for valid file path");

        let _ = fs::remove_file(temp_path);
    }

    /// Test extract_string_boundaries with large file (should skip)
    #[test]
    fn test_extract_string_boundaries_large_file() {
        // Create a file > 10MB (will be skipped)
        let temp_path = create_temp_file("r2_large", &vec![0u8; 11 * 1024 * 1024]);
        let file_path = temp_path.to_str().unwrap();

        let result = super::extract_string_boundaries(file_path, true);

        // Should return None for files > 10MB
        assert!(result.is_none(), "Should skip files larger than 10MB");

        let _ = fs::remove_file(temp_path);
    }

    /// Test extract_string_boundaries with small file
    #[test]
    fn test_extract_string_boundaries_small_file() {
        let temp_path = create_temp_file("r2_small", b"small test file");
        let file_path = temp_path.to_str().unwrap();

        let result = super::extract_string_boundaries(file_path, true);

        // May return None if r2/rizin not available, or Some if available
        // Just verify it doesn't panic
        if let Some(boundaries) = result {
            // If r2 is available and found strings, verify structure
            for boundary in &boundaries {
                assert!(boundary.offset < 1024 * 1024, "Offset should be reasonable");
                assert!(boundary.length > 0, "Length should be positive");
            }
        }

        let _ = fs::remove_file(temp_path);
    }

    /// Test extract_string_boundaries with non-existent file
    #[test]
    fn test_extract_string_boundaries_nonexistent() {
        let fake_path = "/tmp/nonexistent_file_boundaries_test.bin";

        let result = super::extract_string_boundaries(fake_path, true);

        // Should return None for non-existent file
        assert!(result.is_none(), "Should return None for non-existent file");
    }

    /// Test extract_strings with non-existent file
    #[test]
    fn test_extract_strings_nonexistent_file() {
        let result = super::extract_strings("/nonexistent/path/test.bin", 4, false);
        assert!(result.is_none(), "Should return None for non-existent file");
    }

    /// Test extract_strings with large file (should use fast mode)
    #[test]
    fn test_extract_strings_large_file_fast_mode() {
        // Create a file > 10MB
        let temp_path = create_temp_file("r2_extract_large", &vec![0xAAu8; 11 * 1024 * 1024]);
        let file_path = temp_path.to_str().unwrap();

        let result = super::extract_strings(file_path, 4, false);

        // May return None if r2/rizin not available
        // If r2 is available, should use symbols-only mode (fast)
        // Just verify it doesn't panic or hang
        if let Some(strings) = result {
            // Verify all strings have valid offsets
            let file_size = 11_u64 * 1024 * 1024;
            for s in &strings {
                assert!(
                    s.data_offset < file_size,
                    "Offset should be within file bounds"
                );
            }
        }

        let _ = fs::remove_file(temp_path);
    }

    /// Test extract_strings with cache enabled vs disabled
    #[test]
    fn test_extract_strings_caching() {
        let temp_path = create_temp_file("r2_cache_test", b"test content for caching");
        let file_path = temp_path.to_str().unwrap();

        // First call with cache enabled
        let result1 = super::extract_strings(file_path, 4, true);

        // Second call with cache enabled (should hit cache if r2 available)
        let result2 = super::extract_strings(file_path, 4, true);

        // Third call with cache disabled
        let result3 = super::extract_strings(file_path, 4, false);

        // All should return the same result (if r2 available)
        // Just verify consistency
        if let (Some(s1), Some(s2), Some(s3)) = (result1, result2, result3) {
            assert_eq!(s1.len(), s2.len(), "Cached result should match");
            assert_eq!(s1.len(), s3.len(), "Non-cached result should match");
        }

        // Clean up cache
        let _ = super::flush_cache(file_path);
        let _ = fs::remove_file(temp_path);
    }

    /// Test is_available doesn't panic
    #[test]
    fn test_is_available_no_panic() {
        let available = super::is_available();
        // Just verify it returns a boolean without panicking
        let _ = available; // just verify it returns without panicking
    }

    /// Test extract_connect_addrs with non-existent file
    #[test]
    fn test_extract_connect_addrs_nonexistent() {
        let fake_data = b"test data";

        let result = super::extract_connect_addrs("/nonexistent/path.bin", fake_data, true);

        // Should return empty for non-existent file
        assert!(
            result.is_empty(),
            "Should return empty for non-existent file"
        );
    }

    /// Test extract_connect_addrs with large file (should use fast scan)
    #[test]
    fn test_extract_connect_addrs_large_file() {
        let large_data = vec![0u8; 11 * 1024 * 1024];
        let temp_path = create_temp_file("r2_connect_large", &large_data);
        let file_path = temp_path.to_str().unwrap();

        let result = super::extract_connect_addrs(file_path, &large_data, true);

        // Should use binary scan for large files (no r2 analysis)
        // Result may be empty if no connect patterns found
        assert!(result.len() < 1000, "Should not find excessive addresses");

        let _ = fs::remove_file(temp_path);
    }

    /// Test extract_connect_addrs with empty data
    #[test]
    fn test_extract_connect_addrs_empty_data() {
        let temp_path = create_temp_file("r2_connect_empty", b"");
        let file_path = temp_path.to_str().unwrap();

        let result = super::extract_connect_addrs(file_path, b"", true);

        // Should return empty for empty data
        assert!(result.is_empty(), "Should return empty for empty data");

        let _ = fs::remove_file(temp_path);
    }
}
