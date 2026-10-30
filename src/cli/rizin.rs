//! rizin/radare2 integration for the stng CLI. The library runs no
//! subprocesses: this module runs rizin, caches its output (see [`cache`]) and
//! hands the results to extraction through [`stng::ExtractOptions`].
mod cache;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, mpsc};
use std::thread::ScopedJoinHandle;
use std::time::Duration;
use stng::goblin::Object;
use stng::{
    ExtractOptions, ExtractedString, StringBoundary, StringKind, StringMethod, classify_string,
};

static TOOL: OnceLock<Option<PathBuf>> = OnceLock::new();

/// How long one rizin command may run. A crafted binary can keep `aaa` busy
/// indefinitely; past this the pass is dropped, not the run.
const TOOL_TIMEOUT: Duration = Duration::from_secs(300);
/// Output past this is dropped with the pass. `izzj` on a 10 MB file is tens
/// of MB; a binary built to inflate it should not take the host's memory.
const MAX_TOOL_OUTPUT: u64 = 512 * 1024 * 1024;
/// Remove the cached rizin output for `data`.
pub(crate) fn flush_cache(data: &[u8]) -> io::Result<()> {
    match tool_path() {
        Some(tool) => cache::Entry::open(data, tool)?.clear(),
        None => Ok(()),
    }
}

fn tool_path() -> Option<&'static Path> {
    TOOL.get_or_init(|| resolve_tool("rizin").or_else(|| resolve_tool("r2")))
        .as_deref()
}

/// Resolve a tool through absolute PATH entries only. An empty or relative
/// entry searches the working directory, which may be the sample tree.
fn resolve_tool(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let names = candidate_names(name);
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .find_map(|dir| {
            names
                .iter()
                .map(|candidate| dir.join(candidate))
                .find(|candidate| is_executable(candidate))
        })
}

#[cfg(windows)]
fn candidate_names(name: &str) -> Vec<String> {
    vec![
        name.to_string(),
        format!("{name}.exe"),
        format!("{name}.cmd"),
        format!("{name}.bat"),
    ]
}

#[cfg(not(windows))]
fn candidate_names(name: &str) -> Vec<String> {
    vec![name.to_string()]
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Environment variables a native parser needs to start and locate its own
/// runtime resources. Secrets from the scanner process are deliberately not
/// inherited by a tool that consumes hostile bytes.
const TOOL_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
];

fn scrub_env(cmd: &mut Command) {
    cmd.env_clear();
    for key in TOOL_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
}

/// The extents of the strings rizin finds in data sections.
fn extract_string_boundaries(session: &Session<'_>) -> Vec<StringBoundary> {
    if session.data.len() > MAX_ANALYSIS_SIZE {
        return Vec::new();
    }
    session
        .run_json::<Vec<R2String>>("izzj")
        .unwrap_or_default()
        .iter()
        .map(|s| {
            let len = if s.length > 0 {
                s.length
            } else {
                s.string.len()
            };
            StringBoundary::new(s.paddr, len)
        })
        .collect()
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

/// The strings rizin finds in data sections, and the symbol names. A file
/// too large to scan for strings still gets its symbols.
fn extract_strings(session: &Session<'_>, min_length: usize) -> Vec<ExtractedString> {
    let file_size = session.data.len() as u64;
    let (data_strings, symbols) = if session.data.len() > MAX_ANALYSIS_SIZE {
        (None, session.run_json::<Vec<R2Symbol>>("isj"))
    } else {
        rayon::join(
            || session.run_json::<Vec<R2String>>("izzj"),
            || session.run_json::<Vec<R2Symbol>>("isj"),
        )
    };

    let mut strings = Vec::new();
    let mut seen = HashSet::new();
    if let Some(json) = data_strings {
        for s in json {
            if s.paddr > file_size {
                continue;
            }
            if s.string.len() >= min_length && seen.insert(s.string.clone()) {
                if let Some(decoded) = stng::decode_spaced_ascii(&s.string) {
                    if decoded.len() >= min_length && seen.insert(decoded.clone()) {
                        let kind = classify_string(&decoded);
                        strings.push(
                            ExtractedString::new(decoded, s.paddr, StringMethod::SpacedAscii)
                                .with_kind(kind),
                        );
                    }
                } else {
                    let kind = classify_string(&s.string);
                    strings.push(
                        ExtractedString::new(s.string, s.paddr, StringMethod::RizinString)
                            .with_kind(kind),
                    );
                }
            }
        }
    }
    if let Some(json) = symbols {
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
                strings.push(
                    ExtractedString::new(s.name, s.paddr, StringMethod::RizinSymbol)
                        .with_kind(kind),
                );
            }
        }
    }
    strings
}

/// One input's rizin analyses: the snapshot rizin reads, its cache entry,
/// and the output of each command run so far. Passes that need the same
/// command (`izzj` serves both strings and XOR boundaries) share one run:
/// each costs a full rizin startup and scan, so the second waits on the first.
struct Session<'a> {
    tool: &'a Path,
    data: &'a [u8],
    input: TempInput,
    cache: Option<cache::Entry>,
    outputs: Mutex<HashMap<String, Output>>,
}

/// A command's output, filled by whichever pass asks for it first.
type Output = Arc<OnceLock<Option<Arc<String>>>>;

impl<'a> Session<'a> {
    fn new(tool: &'a Path, data: &'a [u8], use_cache: bool) -> io::Result<Self> {
        let cache = if use_cache {
            cache::Entry::open(data, tool)
                .inspect_err(|e| tracing::debug!(error = %e, "rizin cache unavailable"))
                .ok()
        } else {
            None
        };
        Ok(Self {
            tool,
            data,
            input: TempInput::write(data)?,
            cache,
            outputs: Mutex::default(),
        })
    }

    /// The output of `command`, from this session, the cache, or rizin.
    fn run(&self, command: &str) -> Option<Arc<String>> {
        let cell = self
            .outputs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(command.to_string())
            .or_default()
            .clone();
        cell.get_or_init(|| {
            if let Some(cached) = self.cache.as_ref().and_then(|c| c.get(command)) {
                return Some(Arc::new(cached));
            }
            let output =
                run_tool_with_timeout(self.tool, self.input.path(), command, TOOL_TIMEOUT)?;
            if let Some(cache) = &self.cache
                && let Err(e) = cache.set(command, &output)
            {
                tracing::debug!(command, error = %e, "could not cache rizin output");
            }
            Some(Arc::new(output))
        })
        .clone()
    }

    /// The output of `command` parsed as JSON. Output rizin produced but
    /// stng cannot parse is logged: it means a rizin version stng does not
    /// understand.
    fn run_json<T: serde::de::DeserializeOwned>(&self, command: &str) -> Option<T> {
        let output = self.run(command)?;
        serde_json::from_str(&output)
            .inspect_err(|e| tracing::warn!(command, error = %e, "unparseable rizin output"))
            .ok()
    }
}

/// Own the child through every early return and panic. Group cleanup runs
/// before reaping the leader, while its process-group ID is still reserved.
struct ToolChild {
    child: std::process::Child,
    #[cfg(unix)]
    watchdog: stng_process::Watchdog,
}

impl ToolChild {
    fn spawn(command: &mut Command, timeout: Duration) -> std::io::Result<Self> {
        #[cfg(unix)]
        let watchdog = stng_process::Watchdog::arm(command, timeout)?;
        Ok(Self {
            child: command.spawn()?,
            #[cfg(unix)]
            watchdog,
        })
    }

    fn has_exited(&mut self) -> std::io::Result<bool> {
        #[cfg(unix)]
        {
            stng_process::exited_unreaped(&self.child)
        }
        #[cfg(not(unix))]
        {
            self.child.try_wait().map(|status| status.is_some())
        }
    }

    fn finish(&mut self) -> Option<std::process::ExitStatus> {
        #[cfg(unix)]
        self.watchdog.kill_group(&self.child);
        let _ = self.child.kill();
        self.child.wait().ok()
    }
}

impl Drop for ToolChild {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

fn run_tool_with_timeout(tool: &Path, path: &Path, cmd: &str, timeout: Duration) -> Option<String> {
    let mut command = Command::new(tool);
    command
        .args(["-NN", "-q", "-c", cmd])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    scrub_env(&mut command);
    let started = std::time::Instant::now();
    let mut guard = ToolChild::spawn(&mut command, timeout)
        .inspect_err(|e| tracing::warn!(cmd, error = %e, "could not start rizin"))
        .ok()?;
    drop(command);
    let stdout = guard.child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("stng-rizin-drain".into())
        .spawn(move || {
            let mut out = Vec::new();
            let read = stdout.take(MAX_TOOL_OUTPUT + 1).read_to_end(&mut out);
            let _ = tx.send(read.map(|_| out));
        })
        .inspect_err(|e| tracing::warn!(error = %e, "could not start the rizin reader"))
        .ok()?;
    let mut output = None;
    loop {
        if output.is_none() {
            match rx.try_recv() {
                Ok(Ok(out)) if out.len() as u64 <= MAX_TOOL_OUTPUT => output = Some(out),
                Ok(Ok(_)) => {
                    tracing::warn!(
                        cmd,
                        "rizin output exceeded {MAX_TOOL_OUTPUT} bytes; dropped"
                    );
                    return None;
                }
                Ok(Err(e)) => {
                    tracing::warn!(cmd, error = %e, "could not read rizin output");
                    return None;
                }
                Err(mpsc::TryRecvError::Disconnected) => return None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        match guard.has_exited() {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                tracing::warn!(cmd, error = %e, "could not poll rizin");
                return None;
            }
        }
        if started.elapsed() >= timeout {
            // Kill before logging: a blocked stderr must not delay cleanup.
            let _ = guard.finish();
            tracing::warn!(cmd, "rizin ran past {timeout:?}; killed");
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Kill descendants holding stdout before waiting for the drain. EOF does
    // not imply process exit, and process exit does not imply pipe closure.
    let status = guard.finish()?;
    if !status.success() {
        tracing::debug!(cmd, path = %path.display(), %status, "rizin failed");
        return None;
    }
    let Some(out) = output.or_else(|| rx.recv_timeout(Duration::from_secs(5)).ok()?.ok()) else {
        tracing::warn!(cmd, "rizin output could not be read");
        return None;
    };
    if out.len() as u64 > MAX_TOOL_OUTPUT {
        tracing::warn!(
            cmd,
            "rizin output exceeded {MAX_TOOL_OUTPUT} bytes; dropped"
        );
        return None;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
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
    // Section fields echo the binary's headers, so no sum of them is trusted
    // not to wrap.
    for s in sections {
        if let Some(delta) = vaddr.checked_sub(s.vaddr)
            && delta < s.vsize
        {
            return s.paddr.checked_add(delta);
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
fn xor_key_offsets(session: &Session<'_>) -> Vec<u64> {
    let sections: Vec<R2Section> = session.run_json("iSj").unwrap_or_default();
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
    let instr_output = session.run("aaa; /at xor; p8 1 @ 0; /at lea");
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
        let ao_outputs = session.run(&batched);
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

/// Addresses an ARM binary builds in a `sockaddr_in` before `connect()`,
/// from the disassembly of its entry point, or failing that from a scan of
/// its bytes for the stores that build one.
fn extract_connect_addrs(session: &Session<'_>) -> Vec<ExtractedString> {
    let Some(output) = session.run("aaa; e scr.color=0; s entry0; pdf") else {
        return Vec::new();
    };
    if !output.contains("283")
        && !output.contains("syscall.connect")
        && !output.contains("sym.imp.connect")
    {
        return Vec::new();
    }
    match parse_sockaddr_from_disasm(&output) {
        Some(sockaddr) => vec![sockaddr_to_string(&sockaddr)],
        None => scan_binary_for_connect_addrs(session.data),
    }
}

/// Render a parsed sockaddr as an `ip` or `ip:port` ExtractedString.
fn sockaddr_to_string(sockaddr: &SockaddrIn) -> ExtractedString {
    let ip = format!(
        "{}.{}.{}.{}",
        sockaddr.ip[0], sockaddr.ip[1], sockaddr.ip[2], sockaddr.ip[3]
    );
    let (value, kind) = if sockaddr.port > 0 {
        (format!("{ip}:{}", sockaddr.port), Some(StringKind::IpPort))
    } else {
        (ip, Some(StringKind::Ip))
    };
    ExtractedString::new(value, sockaddr.offset, StringMethod::InstructionPattern).with_kind(kind)
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
fn parse_sockaddr_from_disasm(disasm: &str) -> Option<SockaddrIn> {
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
    if found == 4 && !is_unroutable(&ip) {
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
/// Whether `ip` is in 0.0.0.0/8 or at or past 224.0.0.0 (multicast and
/// reserved): bytes that look like an address but cannot be a server.
fn is_unroutable(ip: &[u8; 4]) -> bool {
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
        if f == 15 && !is_unroutable(&ip) {
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

/// An immutable copy of the bytes handed to the disassembler. The CLI reads
/// the input before analysis; passing its original path would let a rename or
/// symlink swap make rizin parse different bytes from the Rust extractors.
struct TempInput(PathBuf);

impl TempInput {
    fn write(data: &[u8]) -> std::io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::path::absolute(std::env::temp_dir())?;
        for _ in 0..128 {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("stng-rizin-{}-{id}.bin", std::process::id()));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            match options.open(&path) {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(data).and_then(|()| file.flush()) {
                        let _ = std::fs::remove_file(&path);
                        return Err(error);
                    }
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique rizin input",
        ))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempInput {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Files above this size get no rizin analysis: `aaa` on them takes minutes.
const MAX_ANALYSIS_SIZE: usize = 10 * 1024 * 1024;

/// Run the rizin analyses extraction can use on an immutable snapshot of
/// `data` and attach the results to `opts`; without rizin, `opts` is
/// returned as is. The analyses run concurrently, sharing `izzj` through the
/// session; each `aaa` is the expensive part.
///
/// - strings and symbols, except for Go binaries, whose strings come from
///   their own structures;
/// - string extents, when `xor` scanning will use them to aim decoding;
/// - `connect()` addresses, for files that may be ARM, the only architecture
///   that pass understands;
/// - XOR key locations, when `xorscan` asks for them.
pub(crate) fn attach(
    opts: ExtractOptions,
    data: &[u8],
    xor: bool,
    xorscan: bool,
    use_cache: bool,
) -> ExtractOptions {
    let Some(tool) = tool_path() else {
        return opts;
    };
    let session = match Session::new(tool, data, use_cache) {
        Ok(session) => session,
        Err(e) => {
            tracing::warn!(error = %e, "rizin skipped: could not snapshot the input");
            return opts;
        }
    };
    let session = &session;
    let min_length = opts.min_length();
    let strings = !stng::is_go_binary(data);
    let connect = data.len() <= MAX_ANALYSIS_SIZE
        && Object::parse(data)
            .is_ok_and(|o| !matches!(o, Object::Unknown(_)) && arm_arch_possible(&o));
    let mut hints = stng::ExternalHints::default();
    std::thread::scope(|scope| {
        let strings = strings.then(|| scope.spawn(|| extract_strings(session, min_length)));
        let boundaries = xor.then(|| scope.spawn(|| extract_string_boundaries(session)));
        let connect = connect.then(|| scope.spawn(|| extract_connect_addrs(session)));
        let keys = xorscan.then(|| scope.spawn(|| xor_key_offsets(session)));
        hints.strings = joined(strings, "strings");
        hints.boundaries = joined(boundaries, "string extents");
        hints.connect_addrs = joined(connect, "connect addresses");
        hints.xor_key_offsets = joined(keys, "XOR keys");
    });
    opts.with_hints(hints)
}

/// The result of a pass that ran, or nothing for one that did not. A pass
/// that panicked is logged and contributes nothing: the rest of the
/// analysis stands.
fn joined<T: Default>(pass: Option<ScopedJoinHandle<'_, T>>, name: &str) -> T {
    match pass.map(ScopedJoinHandle::join) {
        Some(Ok(result)) => result,
        Some(Err(_)) => {
            tracing::warn!(pass = name, "rizin pass panicked; its results are dropped");
            T::default()
        }
        None => T::default(),
    }
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
mod tests;
