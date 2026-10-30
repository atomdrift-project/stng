//! The human-readable listing: a header, one row per string, and a summary
//! of the notable ones. Every string shown is the sample's, so all of it
//! passes through [`terminal_safe`].

use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::path::Path;
use stng::{ExtractedString, Severity, StringKind, StringMethod};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
/// Decoded and decrypted content, which should stand out.
const BRIGHT_YELLOW: &str = "\x1b[93m";

/// Columns before a row's value: indent, offset, method and kind.
const PREFIX_WIDTH: usize = 33;

/// How to render: in color or not, and how wide a value may run before it
/// wraps.
pub(crate) struct Style {
    color: bool,
    value_width: usize,
}

impl Style {
    /// The style for this run, reading the terminal width once.
    pub(crate) fn new(color: bool) -> Self {
        let width = terminal_size::terminal_size().map_or(120, |(w, _)| usize::from(w.0));
        let value_width = if width > PREFIX_WIDTH + 20 {
            width - PREFIX_WIDTH
        } else {
            120
        };
        Self { color, value_width }
    }

    fn paint(&self, code: &'static str) -> &'static str {
        if self.color { code } else { "" }
    }
}

/// The full listing for one file: header, rows in offset order, a note for
/// an overlay with no strings, and the notable summary.
pub(crate) fn print_listing(
    path: &Path,
    data: &[u8],
    strings: &mut [ExtractedString],
    xor_key: Option<&[u8]>,
    style: &Style,
) {
    if strings.is_empty() {
        println!("No strings found in {}", safe_path(path));
        return;
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let key = xor_key.map(String::from_utf8_lossy).or_else(|| {
        strings
            .iter()
            .find(|s| s.kind == Some(StringKind::XorKey))
            .map(|s| Cow::Borrowed(s.value.as_str()))
    });
    let key = key.map_or(String::new(), |k| format!(" · xor:{}", terminal_safe(&k)));
    println!(
        "{}{}{} · {} · {} bytes · {} strings · {}{key}{}",
        style.paint(BOLD),
        style.paint(DIM),
        terminal_safe(&name),
        binary_format(data),
        data.len(),
        strings.len(),
        super::hex(&Sha256::digest(data)),
        style.paint(RESET),
    );
    println!();

    strings.sort_by_key(|s| s.data_offset);
    for s in strings.iter() {
        print_string(s, style);
    }

    if let Some(overlay) = stng::detect_elf_overlay(data)
        && !strings
            .iter()
            .any(|s| s.data_offset >= overlay.start_offset)
    {
        let (dim, reset) = (style.paint(DIM), style.paint(RESET));
        println!();
        println!("{dim}── overlay ──{reset}");
        println!(
            "  {dim}{:>8x}{reset} {dim}{:<12}{reset} {dim}{} bytes (unprintable){reset}",
            overlay.start_offset, "-", overlay.size
        );
    }

    // High-severity strings, most actionable first: addresses, then commands
    // and paths, base64, overlays, URLs.
    let mut notable: Vec<&ExtractedString> = strings
        .iter()
        .filter(|s| {
            s.kind.map_or(Severity::Info, StringKind::severity) == Severity::High
                && s.kind != Some(StringKind::XorKey)
        })
        .collect();
    notable.sort_by_key(|s| match s.kind {
        Some(StringKind::Ip | StringKind::IpPort) => 0,
        Some(StringKind::ShellCmd | StringKind::SuspiciousPath) => 1,
        Some(StringKind::Base64) => 2,
        Some(StringKind::Overlay | StringKind::OverlayWide) => 3,
        Some(StringKind::Url) => 4,
        _ => 5,
    });
    notable.truncate(8);
    if !notable.is_empty() {
        println!();
        if style.color {
            println!("{RED}{BOLD}▌ Notable{RESET}");
        } else {
            println!("── Notable ──");
        }
        for s in notable {
            print_string(s, style);
        }
    }
    println!();
}

/// One string as one or more rows: offset, method, kind, value. Multi-line
/// values and long ones wrap, each row keeping its own offset.
fn print_string(s: &ExtractedString, style: &Style) {
    let kind = s.kind.map_or("-", StringKind::short_name);
    if s.kind == Some(StringKind::EntitlementsXml) {
        let mut offset = s.data_offset;
        for line in s.value.lines() {
            let safe = terminal_safe(line);
            let shown = if style.color {
                Cow::Owned(colorize_xml_line(&safe))
            } else {
                safe
            };
            print_row(
                offset,
                "",
                "entitlement",
                &shown,
                style.paint(CYAN),
                "",
                style,
            );
            offset += line.len() as u64 + 1;
        }
        return;
    }

    let decoded = matches!(
        s.method,
        StringMethod::XorDecode
            | StringMethod::XorStackPair
            | StringMethod::XorRepeatingKey
            | StringMethod::Base64ObfuscatedDecode
            | StringMethod::ScriptDecode
    );
    let (color, kind_color) = if decoded {
        (BRIGHT_YELLOW, BRIGHT_YELLOW)
    } else if s.kind == Some(StringKind::Section) {
        (DIM, DIM)
    } else {
        match s.kind.map_or(Severity::Info, StringKind::severity) {
            Severity::High => (RED, RED),
            Severity::Medium => (CYAN, CYAN),
            Severity::Low => (GREEN, GREEN),
            _ => ("", DIM),
        }
    };
    let (color, kind_color) = (style.paint(color), style.paint(kind_color));
    // An overlay's wide strings are labelled by their kind alone.
    let method = if s.kind == Some(StringKind::OverlayWide) {
        ""
    } else {
        s.method.short_name()
    };

    let value = s.value.trim_end_matches(|c: char| c.is_control());
    if decoded && value.contains('\n') {
        let mut offset = s.data_offset;
        for line in value.lines() {
            let shown = terminal_safe(line.trim_end_matches(|c: char| c.is_control()));
            print_row(offset, method, kind, &shown, kind_color, color, style);
            offset += line.len() as u64 + 1;
        }
        return;
    }
    let shown = terminal_safe(value);
    for (offset, line) in wrap_string_lines(&shown, s.data_offset, style.value_width) {
        print_row(offset, method, kind, &line, kind_color, color, style);
    }
}

fn print_row(
    offset: u64,
    method: &str,
    kind: &str,
    value: &str,
    kind_color: &str,
    color: &str,
    style: &Style,
) {
    let (dim, reset) = (style.paint(DIM), style.paint(RESET));
    println!(
        "  {dim}{offset:>8x}{reset} {kind_color}{method:<8}{reset} {kind_color}{kind:<12}{reset} {color}{value}{reset}"
    );
}

/// The container format and architecture, as `ELF x64` or `Mach-O fat`.
fn binary_format(data: &[u8]) -> String {
    use stng::goblin::Object;
    use stng::goblin::{elf::header as elf, mach::cputype as mach, pe::header as pe};

    match Object::parse(data) {
        Ok(Object::Elf(e)) => {
            let arch = match e.header.e_machine {
                elf::EM_X86_64 => "x64",
                elf::EM_386 => "x86",
                elf::EM_AARCH64 => "arm64",
                elf::EM_ARM => "arm32",
                elf::EM_MIPS => "mips",
                elf::EM_PPC => "ppc",
                elf::EM_PPC64 => "ppc64",
                elf::EM_RISCV => "riscv",
                elf::EM_S390 => "s390x",
                _ => "unknown",
            };
            format!("ELF {arch}")
        }
        Ok(Object::PE(p)) => {
            let arch = match p.header.coff_header.machine {
                pe::COFF_MACHINE_X86_64 => "x64",
                pe::COFF_MACHINE_X86 => "x86",
                pe::COFF_MACHINE_ARM64 => "arm64",
                pe::COFF_MACHINE_ARMNT => "arm32",
                _ => "unknown",
            };
            format!("PE {arch}")
        }
        Ok(Object::Mach(stng::goblin::mach::Mach::Binary(m))) => {
            let arch = match m.header.cputype() {
                mach::CPU_TYPE_X86_64 => "x64",
                mach::CPU_TYPE_X86 => "x86",
                mach::CPU_TYPE_ARM64 => "arm64",
                mach::CPU_TYPE_ARM => "arm32",
                mach::CPU_TYPE_POWERPC => "ppc",
                mach::CPU_TYPE_POWERPC64 => "ppc64",
                _ => "unknown",
            };
            format!("Mach-O {arch}")
        }
        Ok(Object::Mach(stng::goblin::mach::Mach::Fat(_))) => "Mach-O fat".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Colorize the first `<key>` (entitlement name) and `<string>` (value) element
/// on a plist line. The closing tag is searched for only after the opening tag:
/// the line comes from the sample, so the tags may appear in any order.
fn colorize_xml_line(line: &str) -> String {
    let mut output = line.to_string();
    for (open, close, color) in [("<key>", "</key>", RED), ("<string>", "</string>", CYAN)] {
        if let Some(start) = output.find(open).map(|i| i + open.len())
            && let Some(len) = output[start..].find(close)
        {
            let end = start + len;
            output = format!(
                "{}{color}{}{RESET}{}",
                &output[..start],
                &output[start..end],
                &output[end..]
            );
        }
    }
    output
}

/// `text` cut into lines of at most `max_width` characters, each with its
/// offset from `start_offset`. A zero width means no wrapping.
fn wrap_string_lines(text: &str, start_offset: u64, max_width: usize) -> Vec<(u64, String)> {
    if max_width == 0 {
        return vec![(start_offset, text.to_string())];
    }
    // One pass: a line ends every `max_width` characters. Recounting what
    // remains for each line made a multi-megabyte string quadratic.
    let mut result = Vec::new();
    let mut start = 0;
    for (count, (pos, _)) in text.char_indices().enumerate() {
        if count > 0 && count % max_width == 0 {
            result.push((start_offset + start as u64, text[start..pos].to_string()));
            start = pos;
        }
    }
    if start < text.len() {
        result.push((start_offset + start as u64, text[start..].to_string()));
    }
    result
}

/// `text` with every character a terminal would act on, rather than print,
/// replaced by its Rust escape (`\u{1b}`, `\r`). Extracted strings are the
/// attacker's: an ESC opens sequences that retitle the window, write the
/// clipboard (OSC 52), or move the cursor to hide or forge earlier lines; a
/// bare CR or newline overwrites or fakes a row; bidirectional overrides
/// reorder what is shown. Tab is harmless and stays.
pub(crate) fn terminal_safe(text: &str) -> Cow<'_, str> {
    let unsafe_char = |c: char| {
        (c.is_control() && c != '\t')
            || matches!(
                c,
                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            )
    };
    if !text.chars().any(unsafe_char) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        if unsafe_char(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// A path for a terminal message; file names are as hostile as contents.
pub(crate) fn safe_path(path: &Path) -> String {
    terminal_safe(&path.display().to_string()).into_owned()
}

#[cfg(test)]
mod tests;
