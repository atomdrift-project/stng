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

use anyhow::Result;
use clap::Parser;
use cli::args::{LcgRange, XorKey};
use cli::output::{self, Style, safe_path};
use std::collections::HashSet;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
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
    stng --xorscan malware.elf         # Also decode keys rizin finds loaded by code
    stng --no-xor malware.elf          # Disable all XOR detection
    stng --json malware.elf            # JSON output for tooling
    stng --json samples/               # One JSON object per file
")]
struct Cli {
    /// File to analyze, or a directory to analyze every file under
    target: PathBuf,

    /// Minimum string length to extract
    #[arg(short = 'm', long, default_value = "4")]
    min_length: usize,

    /// Output as JSON: an array of strings, or for a directory one
    /// `{"path", "strings"}` object per line
    #[arg(long)]
    json: bool,

    /// Simple output (one string per line, no columns)
    #[arg(long)]
    simple: bool,

    /// Show detected language and exit
    #[arg(long)]
    detect: bool,

    /// Show unfiltered results including garbage/noise
    #[arg(long)]
    unfiltered: bool,

    /// Don't run rizin, even if installed
    #[arg(long, alias = "no-r2")]
    no_rizin: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Filter out raw scan noise (keep structured, rizin, and symbol data)
    #[arg(short = 'i', long)]
    interesting: bool,

    /// Disable XOR-encoded string detection
    #[arg(long)]
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

    /// Minimum length for XOR-decoded strings
    #[arg(long, default_value = "10")]
    xor_min_length: usize,

    /// Also decode with XOR keys rizin finds loaded by code (slow)
    #[arg(long)]
    xorscan: bool,

    /// Disable rizin result caching
    #[arg(long)]
    no_cache: bool,

    /// Clear cached rizin results for this file before analysis
    #[arg(long)]
    flush_cache: bool,

    /// Enable debug logging
    #[arg(long)]
    debug: bool,
}

/// One file's extraction stops getting faster at about 16 threads. Past that,
/// idle workers only burn CPU: on a 128-core machine the default pool was
/// 15–40% slower than 16 threads and used 4–8× the CPU.
const MAX_THREADS: usize = 16;

fn main() -> Result<()> {
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
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();

    let style = Style::new(!cli.no_color && !cli.json && io::stdout().is_terminal());
    let root = &cli.target;
    if !root.exists() {
        anyhow::bail!("Path does not exist: {}", safe_path(root));
    }
    if !root.is_dir() {
        return analyze(&cli, root, &style, false);
    }
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!("warning: {}: {e}", safe_path(&dir));
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => stack.push(path),
                Ok(t) if t.is_file() => {
                    if let Err(e) = analyze(&cli, &path, &style, true) {
                        eprintln!("warning: {}: {e}", safe_path(&path));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Extract and print one file's strings. `in_directory` selects the
/// one-object-per-line JSON form.
fn analyze(cli: &Cli, path: &Path, style: &Style, in_directory: bool) -> Result<()> {
    let data = std::fs::read(path)?;
    if cli.flush_cache
        && let Err(e) = cli::rizin::flush_cache(&data)
    {
        eprintln!("warning: failed to flush the rizin cache: {e}");
    }
    if cli.detect {
        println!("{}", stng::detect_language(&data));
        return Ok(());
    }

    let key = cli.xor.as_ref().map(|k| k.0.clone());
    let xorscan = cli.xorscan && key.is_none() && !cli.no_xor;
    let mode = match &key {
        Some(key) => XorMode::Key(key.clone()),
        None if cli.no_xor => XorMode::Off,
        None if xorscan => XorMode::Scan,
        None => XorMode::Auto,
    };
    let mut opts = stng::ExtractOptions::new(cli.min_length)
        .with_garbage_filter(!cli.unfiltered)
        .with_xor_min_length(cli.xor_min_length)
        .with_xor(mode);
    if !cli.no_rizin {
        let xor = *opts.xor() != XorMode::Off;
        opts = cli::rizin::attach(opts, &data, xor, xorscan, !cli.no_cache);
    }
    if !cli.no_xor
        && !cli.json
        && !cli.debug
        && io::stderr().is_terminal()
        && data.len() <= stng::MAX_XOR_SCAN_SIZE
    {
        eprintln!("Scanning file for encoded material...");
    }

    let mut strings = stng::extract_strings_with_options(&data, &opts);
    if let Some(LcgRange(lcg, range)) = &cli.xor_lcg {
        let decoded = stng::decode_lcg_xor(&data, range.clone(), lcg)
            .ok_or_else(|| anyhow::anyhow!("LCG-XOR parameters did not decode a readable range"))?;
        strings.push(decoded);
    }
    // Show each value once, except what was decoded from a script: those
    // are distinct finds that may repeat text found elsewhere.
    let mut seen = HashSet::new();
    strings.retain(|s| {
        s.method == StringMethod::ScriptDecode
            || seen.insert(s.value.trim().trim_end_matches(char::is_control).to_owned())
    });
    if cli.interesting {
        strings.retain(|s| s.method != StringMethod::RawScan);
    }

    if cli.json {
        print_json(path, &strings, in_directory)
    } else if cli.simple {
        for s in &strings {
            println!(
                "{}",
                output::terminal_safe(s.value.trim_end_matches(char::is_control))
            );
        }
        eprintln!("\n{} strings extracted", strings.len());
        Ok(())
    } else {
        output::print_listing(path, &data, &mut strings, key.as_deref(), style);
        Ok(())
    }
}

/// The strings as a JSON array; in a directory, as one
/// `{"path": …, "strings": […]}` object per line.
fn print_json(path: &Path, strings: &[ExtractedString], in_directory: bool) -> Result<()> {
    #[derive(serde::Serialize)]
    struct File<'a> {
        path: std::borrow::Cow<'a, str>,
        strings: &'a [ExtractedString],
    }
    let mut out = io::BufWriter::new(io::stdout().lock());
    if in_directory {
        let file = File {
            path: path.to_string_lossy(),
            strings,
        };
        serde_json::to_writer(&mut out, &file)?;
    } else {
        serde_json::to_writer_pretty(&mut out, strings)?;
    }
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}
