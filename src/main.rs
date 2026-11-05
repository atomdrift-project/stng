// Allow unwrap/expect/panic in test code — panicking on failure is idiomatic in tests.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! The `stng` command: extract and classify the strings in a file, or in
//! every file under a directory.

// Use jemalloc on unix systems where it isn't the OS default (see Cargo.toml).
// `--features jemalloc-prof` adds heap profiling (`make heap-benchmark`).
#[cfg(all(
    unix,
    not(any(
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    ))
))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::{Context, Result};
use clap::Parser;
use cli::args::{LcgRange, XorKey};
use cli::output::{self, Style, safe_path};
use std::collections::HashSet;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use stng::{ExtractedString, StringMethod, XorMode};

mod cli;

#[derive(Parser, Debug)]
#[command(name = "stng")]
#[command(
    author,
    version,
    about = "Security-focused string extraction for binary analysis"
)]
#[command(long_about = "
stng extracts and classifies strings from binaries with a focus on
security research. It highlights IOCs like IPs, URLs, shell commands,
and suspicious paths while filtering noise. XOR-encoded strings are
detected by default.

EXAMPLES:
    stng malware.elf                   # Full analysis with single-byte XOR detection
    stng -i malware.elf                # Filter out raw scan noise
    stng --xor 0xAB malware.elf        # Decode with a hex XOR key
    stng --xor secretkey malware.elf   # Decode with a text XOR key
    stng --xorscan malware.elf         # XOR-scan Go binaries too
    stng --no-xor malware.elf          # Disable all XOR detection
    stng --json malware.elf            # JSON output for tooling
    stng --json samples/               # One JSON object per file
")]
struct Cli {
    /// File to analyze, or a directory to analyze every file under
    target: PathBuf,

    /// Minimum string length to extract
    #[arg(short = 'm', long, default_value = "4", value_parser = clap::value_parser!(u16).range(1..))]
    min_length: u16,

    /// Output as JSON: an array of strings, or for a directory one
    /// `{"path", "strings"}` object per line
    #[arg(long)]
    json: bool,

    /// Simple output (one string per line, no columns)
    #[arg(long, conflicts_with = "json")]
    simple: bool,

    /// Show detected language and exit
    #[arg(long)]
    detect: bool,

    /// Show unfiltered results including garbage/noise
    #[arg(long)]
    unfiltered: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Filter out raw scan noise (keep structured and symbol data)
    #[arg(short = 'i', long)]
    interesting: bool,

    /// Disable XOR-encoded string detection
    #[arg(long, conflicts_with_all = ["xor", "xorscan", "xor_lcg"])]
    no_xor: bool,

    /// XOR key: hex digits after `0x` or `hex:` (`0xABCD`), otherwise the
    /// literal text
    #[arg(long, value_parser = cli::args::parse_xor_key)]
    xor: Option<XorKey>,

    /// Decode an analyst-identified LCG-XOR range:
    /// seed,multiplier,modulus,mask,offset,length (decimal or 0x-prefixed)
    #[arg(
        long,
        value_name = "SEED,MUL,MOD,MASK,OFFSET,LENGTH",
        value_parser = cli::args::parse_lcg,
        conflicts_with = "xor"
    )]
    xor_lcg: Option<LcgRange>,

    /// XOR-scan Go binaries too, which are skipped by default
    #[arg(long, conflicts_with = "xor")]
    xorscan: bool,

    /// Skip XOR scanning for binaries carrying an Apple or Microsoft platform
    /// signature (not verified, so a sample can fake one)
    #[arg(long)]
    skip_platform_signed: bool,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,
}

/// One file's extraction stops getting faster at about 16 threads. Past that,
/// idle workers only burn CPU: on a 128-core machine the default pool was
/// 15–40% slower than 16 threads and used 4–8× the CPU.
const MAX_THREADS: usize = 16;

fn main() -> ExitCode {
    let cli = Cli::parse();
    if std::env::var_os("RAYON_NUM_THREADS").is_none() {
        let n = std::thread::available_parallelism().map_or(1, |n| n.get().min(MAX_THREADS));
        // Fails only if a pool already exists, which then stays as it is.
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global();
    }
    let level = if cli.debug {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };
    // Diagnostics go to stderr so they never mix with the listing or JSON.
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_writer(io::stderr)
        .with_ansi(io::stderr().is_terminal())
        .init();

    let tty = io::stdout().is_terminal();
    let no_color = cli.no_color || std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    let style = Style::new(!no_color && !cli.json && tty, tty);
    let mut out = io::BufWriter::new(io::stdout().lock());
    match run(&cli, &style, &mut out) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        // The reader went away (`stng … | head`): stop quietly, as cat does.
        Err(e) if is_broken_pipe(&e) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("stng: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Analyze the target, a file or every regular file under a directory.
/// `Ok(false)` means some file in a directory could not be analyzed; each one
/// was reported as it happened.
fn run(cli: &Cli, style: &Style, out: &mut impl Write) -> Result<bool> {
    let root = &cli.target;
    let meta = std::fs::metadata(root).with_context(|| safe_path(root))?;
    if !cli.no_xor && !cli.json && !cli.debug && !cli.detect && io::stderr().is_terminal() {
        eprintln!("Scanning for encoded material...");
    }
    if !meta.is_dir() {
        // A FIFO or device would block or never end.
        if !meta.is_file() {
            anyhow::bail!("{}: not a regular file or directory", safe_path(root));
        }
        analyze(cli, root, &meta, style, false, out).with_context(|| safe_path(root))?;
        return Ok(true);
    }
    let mut ok = true;
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = match std::fs::read_dir(&dir) {
            Ok(entries) => entries.flatten().collect(),
            Err(e) => {
                eprintln!("stng: {}: {e}", safe_path(&dir));
                ok = false;
                continue;
            }
        };
        // Name order: a directory's files, then its subdirectories.
        entries.sort_by_key(std::fs::DirEntry::path);
        let mut subdirs = Vec::new();
        for entry in entries {
            let path = entry.path();
            // Not followed: a symlink could lead anywhere, a FIFO or device
            // would block or never end.
            match entry.metadata() {
                Ok(m) if m.is_dir() => subdirs.push(path),
                Ok(m) if m.is_file() => {
                    // A sample that trips a bug stops only its own analysis;
                    // the panic hook has already reported it.
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        analyze(cli, &path, &m, style, true, &mut *out)
                    }))
                    .unwrap_or_else(|_| {
                        Err(anyhow::anyhow!("internal error (a bug; please report it)"))
                    });
                    match result {
                        Ok(()) => {}
                        Err(e) if is_broken_pipe(&e) => return Err(e),
                        Err(e) => {
                            eprintln!("stng: {}: {e:#}", safe_path(&path));
                            ok = false;
                        }
                    }
                }
                Ok(_) => {
                    tracing::debug!(path = %safe_path(&path), "skipping: not a file or directory")
                }
                Err(e) => {
                    eprintln!("stng: {}: {e}", safe_path(&path));
                    ok = false;
                }
            }
        }
        stack.extend(subdirs.into_iter().rev());
    }
    Ok(ok)
}

/// Whether writing stdout failed because its reader closed.
fn is_broken_pipe(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|cause| cause.downcast_ref::<io::Error>())
        .any(|e| e.kind() == io::ErrorKind::BrokenPipe)
}

/// Extract and print one file's strings. `listed` is what `stat` or the
/// directory listing said `path` was; `in_directory` selects the
/// one-object-per-line JSON form.
fn analyze(
    cli: &Cli,
    path: &Path,
    listed: &std::fs::Metadata,
    style: &Style,
    in_directory: bool,
    out: &mut impl Write,
) -> Result<()> {
    let data = read_regular_file(path, listed)?;
    if cli.detect {
        if in_directory {
            writeln!(out, "{}: {}", safe_path(path), stng::detect_language(&data))?;
        } else {
            writeln!(out, "{}", stng::detect_language(&data))?;
        }
        out.flush()?;
        return Ok(());
    }

    let key = cli.xor.as_ref().map(|k| k.0.as_slice());
    let mode = match key {
        Some(key) => XorMode::Key(key.to_vec()),
        None if cli.no_xor => XorMode::Off,
        None if cli.xorscan => XorMode::Scan,
        None => XorMode::Auto,
    };
    let opts = stng::ExtractOptions::new(usize::from(cli.min_length))
        .with_garbage_filter(!cli.unfiltered)
        .with_xor(mode)
        .with_platform_signed_skip(cli.skip_platform_signed);

    // Parsed once, for extraction and for the listing's format and overlay.
    let object = stng::goblin::Object::parse(&data).ok();
    let started = std::time::Instant::now();
    let mut strings = match &object {
        Some(object) => stng::extract_strings_from_parsed(object, &[], &data, &opts),
        None => stng::extract_strings_with_options(&data, &opts),
    };
    tracing::debug!(
        path = %safe_path(path),
        bytes = data.len(),
        strings = strings.len(),
        elapsed = ?started.elapsed(),
        "extracted"
    );
    if let Some(LcgRange(lcg, range)) = &cli.xor_lcg {
        let decoded = stng::decode_lcg_xor(&data, range.clone(), lcg).context("--xor-lcg")?;
        strings.push(decoded);
    }
    // `-i` first: the value dedup below keeps the lowest-offset copy, and
    // that is often the raw-scan hit `-i` drops, not its structured twin.
    if cli.interesting {
        strings.retain(|s| s.method != StringMethod::RawScan);
    }
    // Show each value once, except what was decoded from a script: those
    // are distinct finds that may repeat text found elsewhere.
    let mut seen = HashSet::new();
    strings.retain(|s| {
        s.method == StringMethod::ScriptDecode
            || seen.insert(s.value.trim().trim_end_matches(char::is_control).to_owned())
    });

    if cli.json {
        print_json(out, path, &strings, in_directory)?;
    } else if cli.simple {
        for s in &strings {
            writeln!(
                out,
                "{}",
                output::terminal_safe(s.value.trim_end_matches(char::is_control))
            )?;
        }
        out.flush()?;
        eprintln!("\n{} strings extracted", strings.len());
    } else {
        output::print_listing(out, path, &data, object.as_ref(), &mut strings, key, style)?;
    }
    out.flush()?;
    Ok(())
}

/// The contents of the regular file at `path`, which `listed` describes.
/// The checks are on the opened file, so one replaced after it was listed (by
/// a symlink to a secret, or to `/dev/zero`) is refused rather than read, and
/// one still growing is read only to the length it had.
fn read_regular_file(path: &Path, listed: &std::fs::Metadata) -> Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || !same_file(&meta, listed) {
        anyhow::bail!("changed while being read");
    }
    let mut data = Vec::new();
    file.take(meta.len()).read_to_end(&mut data)?;
    Ok(data)
}

#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    (a.dev(), a.ino()) == (b.dev(), b.ino())
}

/// Windows has no stable file identity in std; the type check stands alone.
#[cfg(not(unix))]
fn same_file(_: &std::fs::Metadata, _: &std::fs::Metadata) -> bool {
    true
}

/// The strings as a JSON array; in a directory, as one
/// `{"path": …, "strings": […]}` object per line.
fn print_json(
    out: &mut impl Write,
    path: &Path,
    strings: &[ExtractedString],
    in_directory: bool,
) -> io::Result<()> {
    #[derive(serde::Serialize)]
    struct File<'a> {
        path: std::borrow::Cow<'a, str>,
        strings: &'a [ExtractedString],
    }
    let json = if in_directory {
        let file = File {
            path: path.to_string_lossy(),
            strings,
        };
        serde_json::to_string(&file)?
    } else {
        serde_json::to_string_pretty(strings)?
    };
    // serde_json escapes C0 controls but passes DEL, C1 controls and bidi
    // overrides through, and JSON is often read on a terminal. Outside
    // strings there is only ASCII and the pretty form's newlines, so
    // escaping every other such character is the same JSON value.
    let unsafe_char = |c: char| c != '\n' && output::is_terminal_unsafe(c);
    let mut rest = json.as_str();
    while let Some((at, c)) = rest.char_indices().find(|&(_, c)| unsafe_char(c)) {
        out.write_all(&rest.as_bytes()[..at])?;
        write!(out, "\\u{:04x}", u32::from(c))?;
        rest = &rest[at + c.len_utf8()..];
    }
    out.write_all(rest.as_bytes())?;
    out.write_all(b"\n")
}
