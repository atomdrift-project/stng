//! cmd.exe variable-expansion deobfuscation.
//!
//! Batch droppers hide their commands by spreading them across `set`
//! variables and splicing them back together at run time: `set ;{=ove /y`
//! followed by `m%;{% ...` runs `move /y ...`, and `%abc%s%def%et` runs `set`
//! because undefined variables expand to nothing. None of the command words
//! exist in the file as written, so string rules cannot see them.
//!
//! This module replays cmd's percent-expansion phase line by line, recording
//! each `set` as it goes, and returns the expanded script when doing so
//! reveals text that was not literally present. It is a static simulation:
//! no control flow, `call` double expansion, or `set /a` arithmetic.

use std::collections::HashMap;

use super::DeobfuscationResult;

/// Scripts larger than this are not simulated.
const MAX_INPUT: usize = 2 * 1024 * 1024;
/// Cap on the expanded output, so a doubling `set a=%a%%a%` chain cannot blow up.
const MAX_OUTPUT: usize = 4 * 1024 * 1024;
/// Cap on one variable's value.
const MAX_VALUE: usize = 32 * 1024;
/// Longest `%...%` body treated as a variable reference. Longer spans are
/// almost always two unrelated percent signs in prose.
const MAX_REF: usize = 64;

/// Environment variables cmd inherits. Undefined references to these keep
/// their literal spelling (the host fills them in); any other undefined
/// reference expands to nothing, exactly as cmd does.
const INHERITED: &[&str] = &[
    "allusersprofile",
    "appdata",
    "cd",
    "cmdcmdline",
    "cmdextversion",
    "commonprogramfiles",
    "commonprogramfiles(x86)",
    "commonprogramw6432",
    "computername",
    "comspec",
    "date",
    "errorlevel",
    "homedrive",
    "homepath",
    "localappdata",
    "logonserver",
    "number_of_processors",
    "os",
    "path",
    "pathext",
    "processor_architecture",
    "processor_identifier",
    "programdata",
    "programfiles",
    "programfiles(x86)",
    "programw6432",
    "public",
    "random",
    "systemdrive",
    "systemroot",
    "temp",
    "time",
    "tmp",
    "userdomain",
    "username",
    "userprofile",
    "windir",
];

#[derive(Default)]
struct Expander {
    vars: HashMap<String, String>,
    /// References to variables the script itself defined.
    defined_hits: usize,
    /// References to undefined, non-inherited variables (expanded to empty).
    noise_hits: usize,
}

impl Expander {
    fn lookup(&mut self, body: &str) -> Option<String> {
        // `name:~start,len` substring and `name:old=new` substitution.
        let (name, op) = match body.find(":~").or_else(|| body.find(':')) {
            Some(i) if i > 0 => (&body[..i], Some(&body[i..])),
            _ => (body, None),
        };
        let key = name.to_ascii_lowercase();
        let Some(value) = self.vars.get(&key).cloned() else {
            // Inherited variables keep their spelling for the host to fill;
            // an edit (`:~`, `:a=b`) on an unknown name is left as written.
            if INHERITED.contains(&key.as_str()) || op.is_some() {
                return None;
            }
            self.noise_hits += 1;
            return Some(String::new());
        };
        self.defined_hits += 1;
        let Some(op) = op else {
            return Some(value);
        };
        if let Some(spec) = op.strip_prefix(":~") {
            return Some(substring(&value, spec));
        }
        let spec = &op[1..];
        let (old, new) = spec.split_once('=')?;
        Some(replace_ci(&value, old, new))
    }

    fn expand_percent(&mut self, line: &str) -> String {
        let bytes = line.as_bytes();
        let mut out = String::with_capacity(line.len());
        let mut i = 0;
        while i < line.len() {
            let c = bytes[i];
            if c != b'%' {
                let ch = line[i..].chars().next().unwrap_or('\u{fffd}');
                out.push(ch);
                i += ch.len_utf8();
                continue;
            }
            // `%%` is a FOR variable or an escaped percent; `%0`..`%9` and
            // `%*` are arguments. All stay literal.
            match bytes.get(i + 1) {
                Some(b'%') => {
                    out.push_str("%%");
                    i += 2;
                    continue;
                }
                Some(d) if d.is_ascii_digit() || *d == b'*' || *d == b'~' => {
                    out.push('%');
                    i += 1;
                    continue;
                }
                _ => {}
            }
            let rest = &line[i + 1..];
            match rest.find('%') {
                Some(end) if end > 0 && end <= MAX_REF => {
                    let body = &rest[..end];
                    if let Some(v) = self.lookup(body) {
                        out.push_str(&v);
                    } else {
                        out.push('%');
                        out.push_str(body);
                        out.push('%');
                    }
                    i += end + 2;
                }
                _ => {
                    out.push('%');
                    i += 1;
                }
            }
        }
        out
    }

    fn expand_delayed(&mut self, line: &str) -> String {
        let mut out = String::with_capacity(line.len());
        let mut rest = line;
        while let Some(start) = rest.find('!') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            match after.find('!') {
                Some(end) if end > 0 && end <= MAX_REF => {
                    let body = &after[..end];
                    let key = body.split(':').next().unwrap_or(body).to_ascii_lowercase();
                    if self.vars.contains_key(&key) {
                        let v = self.lookup(body).unwrap_or_default();
                        out.push_str(&v);
                        rest = &after[end + 1..];
                        continue;
                    }
                    out.push('!');
                    rest = after;
                }
                _ => {
                    out.push('!');
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// Record every `set` statement in an already-expanded line.
    fn record_sets(&mut self, line: &str) {
        for stmt in split_statements(line) {
            let stmt = stmt.trim_start_matches(|c: char| c == '@' || c.is_whitespace());
            let Some(head) = stmt.get(..4) else { continue };
            if !head.eq_ignore_ascii_case("set ") {
                continue;
            }
            let rest = stmt[4..].trim_start();
            let lower = rest.to_ascii_lowercase();
            if lower.starts_with("/a") || lower.starts_with("/p") {
                continue;
            }
            // `set "name=value"`: the quotes wrap the whole assignment.
            let assignment =
                if rest.starts_with('"') && rest.trim_end().ends_with('"') && rest.len() > 2 {
                    let inner = &rest[1..rest.trim_end().len() - 1];
                    if inner.contains('=') { inner } else { rest }
                } else {
                    rest
                };
            let Some((name, value)) = assignment.split_once('=') else {
                continue;
            };
            if name.is_empty() || name.len() > MAX_REF {
                continue;
            }
            let value: String = value.chars().take(MAX_VALUE).collect();
            self.vars.insert(name.to_ascii_lowercase(), value);
        }
    }
}

/// Split on unquoted, unescaped `&` (also covers `&&`).
fn split_statements(line: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quote = false;
    let mut escaped = false;
    let mut start = 0;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '^' => escaped = true,
            '"' => in_quote = !in_quote,
            '&' | '|' if !in_quote => {
                parts.push(&line[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&line[start..]);
    parts
}

fn substring(value: &str, spec: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len() as i64;
    let (s, l) = match spec.split_once(',') {
        Some((s, l)) => (s.trim().parse::<i64>().ok(), l.trim().parse::<i64>().ok()),
        None => (spec.trim().parse::<i64>().ok(), None),
    };
    let Some(s) = s else { return String::new() };
    let start = if s < 0 { (n + s).max(0) } else { s.min(n) };
    let end = match l {
        None => n,
        Some(l) if l < 0 => (n + l).max(start),
        Some(l) => (start + l).min(n),
    };
    chars[start as usize..end as usize].iter().collect()
}

fn replace_ci(value: &str, old: &str, new: &str) -> String {
    if old.is_empty() {
        return value.to_string();
    }
    let lower = value.to_ascii_lowercase();
    // `*old=new` replaces everything up to and including the first match.
    if let Some(needle) = old.strip_prefix('*') {
        let needle = needle.to_ascii_lowercase();
        return match lower.find(&needle) {
            Some(i) if !needle.is_empty() => format!("{new}{}", &value[i + needle.len()..]),
            _ => value.to_string(),
        };
    }
    let needle = old.to_ascii_lowercase();
    let mut out = String::with_capacity(value.len());
    let mut i = 0;
    while let Some(pos) = lower[i..].find(&needle) {
        out.push_str(&value[i..i + pos]);
        out.push_str(new);
        i += pos + needle.len();
    }
    out.push_str(&value[i..]);
    out
}

/// Remove cmd's `^` escape from expanded text (`^^` keeps one caret).
fn unescape_carets(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '^' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Cheap pre-check: a script with no `set` assignment and no percent
/// references has nothing to expand.
fn worth_simulating(text: &str) -> (bool, bool) {
    let lower = text.to_ascii_lowercase();
    let worth = lower.contains("set ") && text.matches('%').count() >= 4;
    let has_remap_markers = lower.contains("chcp 708")
        && lower.contains("@manezao@=")
        && lower.contains("@jasa@=");
    (worth, has_remap_markers)
}

/// Decode the byte substitution used by CP708 batch obfuscators. They pair a
/// 94-byte table of high bytes with the printable ASCII set (excluding `"`),
/// then spell command text as `%<high-byte>%` variable references. Keep this
/// behind its distinctive table and codepage markers; ordinary batch files
/// should pay only the marker scan, and no locale or shell is invoked.
fn decode_codepage_remap(data: &[u8]) -> Option<Vec<u8>> {
    const TABLE_LEN: usize = 94;
    if !contains_ascii_case_insensitive(data, b"chcp 708")
        || !contains_ascii_case_insensitive(data, b"@manezao@=")
        || !contains_ascii_case_insensitive(data, b"@jasa@=")
    {
        return None;
    }

    let ascii = assignment_table(data, b"@manezao@=", TABLE_LEN)?;
    let encoded = assignment_table(data, b"@jasa@=", TABLE_LEN)?;
    let mut ascii_seen = [false; 128];
    let mut encoded_seen = [false; 256];
    for (&a, &e) in ascii.iter().zip(encoded) {
        if !(0x20..=0x7e).contains(&a)
            || e < 0x80
            || ascii_seen[a as usize]
            || encoded_seen[e as usize]
        {
            return None;
        }
        ascii_seen[a as usize] = true;
        encoded_seen[e as usize] = true;
    }
    let mut table = [0u8; 256];
    for (&from, &to) in encoded.iter().zip(ascii) {
        table[from as usize] = to;
    }

    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    let mut substitutions = 0;
    while i < data.len() {
        if data[i] == b'%' && i + 2 < data.len() && data[i + 2] == b'%' {
            let value = table[data[i + 1] as usize];
            if value != 0 {
                out.push(value);
                substitutions += 1;
                i += 3;
                continue;
            }
        }
        out.push(data[i]);
        i += 1;
    }

    // A full command is represented by many mapped variable references. This
    // excludes a stray marker or an incidental occurrence in documentation.
    (substitutions >= 16).then_some(out)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn assignment_table<'a>(data: &'a [u8], marker: &[u8], len: usize) -> Option<&'a [u8]> {
    for line in data.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(start) = line
            .windows(marker.len())
            .position(|window| window.eq_ignore_ascii_case(marker))
        else {
            continue;
        };
        let value = line.get(start + marker.len()..)?;
        let table = value.get(..len)?;
        // Both tables are quoted SET assignments; the following byte closes
        // the value and prevents consuming adjacent command text as table data.
        if value.get(len) == Some(&b'"') {
            return Some(table);
        }
        return None;
    }
    None
}

/// Expand cmd variables through a batch script.
///
/// Returns the expanded script when the replay resolved enough references
/// to have changed what the script visibly says: at least three references
/// to script-defined variables, or five noise references to undefined ones.
#[must_use]
pub fn expand_batch_variables(data: &[u8]) -> Option<DeobfuscationResult> {
    if data.len() > MAX_INPUT {
        return None;
    }
    let original = String::from_utf8_lossy(data);
    let (worth_simulating, has_remap_markers) = worth_simulating(&original);
    if !worth_simulating {
        return None;
    }
    let remapped = has_remap_markers
        .then(|| decode_codepage_remap(data))
        .flatten();
    let source = remapped.as_deref().unwrap_or(data);
    let text = if remapped.is_some() {
        String::from_utf8_lossy(source)
    } else {
        original
    };
    let delayed = text.to_ascii_lowercase().contains("enabledelayedexpansion");
    let mut exp = Expander::default();
    let mut out = String::with_capacity(text.len());
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let mut expanded = exp.expand_percent(line);
        if delayed {
            expanded = exp.expand_delayed(&expanded);
        }
        exp.record_sets(&expanded);
        out.push_str(&unescape_carets(&expanded));
        out.push('\n');
        if out.len() > MAX_OUTPUT {
            break;
        }
    }
    if remapped.is_none() && exp.defined_hits < 3 && exp.noise_hits < 5 {
        return None;
    }
    if out.trim_end() == text.trim_end() {
        return None;
    }
    Some(DeobfuscationResult {
        decoded: out,
        offset: 0,
        chain_description: if remapped.is_some() {
            "batch:codepage-remap+set-expansion".to_string()
        } else {
            "batch:set-expansion".to_string()
        },
        language: "batch",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand(src: &str) -> String {
        expand_batch_variables(src.as_bytes())
            .map(|r| r.decoded)
            .unwrap_or_default()
    }

    #[test]
    fn splices_punctuation_named_variables() {
        let src = "@echo off\nset ;{=ove /y\nset :D=\\*.* \\*.LaM\nm%;{% %wInDiR%%:D%\nm%;{% x%:D%\nM%;{% y%:D%\n";
        let out = expand(src);
        assert!(out.contains("move /y %wInDiR%\\*.* \\*.LaM"), "{out}");
    }

    #[test]
    fn undefined_noise_vars_vanish() {
        let src = "set x=1\n%a1%e%b2%c%c3%h%d4%o %e5%h%f6%i\n";
        assert!(expand(src).contains("echo hi"));
    }

    #[test]
    fn for_variables_and_arguments_stay() {
        let src = "set p=format\nset q=x\nset r=y\nfor %%K in (a b) do %p% %%K: %1 %q%%r%\n";
        assert!(expand(src).contains("for %%K in (a b) do format %%K: %1 xy"));
    }

    #[test]
    fn substring_and_replace() {
        let src = "set s=abcdefgh\necho %s:~2,3% %s:~-2% %s:~1,-5% %s:cd=XY% %s:*d=Z%\n";
        let out = expand(src);
        assert!(out.contains("echo cde gh bc abXYefgh Zefgh"), "{out}");
    }

    #[test]
    fn quoted_set_and_delayed_expansion() {
        let src = "setlocal enabledelayedexpansion\nset \"a=pow\"\nset \"b=ershell\"\n!a!!b! -nop & %a%%b%\n";
        assert!(expand(src).contains("powershell -nop & powershell"));
    }

    #[test]
    fn plain_script_is_not_reported() {
        let src = "@echo off\nset NAME=world\necho hello %NAME%\n";
        assert!(expand_batch_variables(src.as_bytes()).is_none());
    }

    #[test]
    fn caret_escapes_removed_after_expansion() {
        let src = "set a=c^md\nset b=x\nset c=y\n%a% /c %b%%c%\n";
        assert!(expand(src).contains("cmd /c xy"));
    }

    #[test]
    fn expands_chcp_remap_sample_into_hidden_python_launch() {
        let src = include_bytes!("../../testdata/script/batch-remap-sample.unknown");
        let out = expand_batch_variables(src).map(|r| r.decoded).unwrap_or_default();
        let lower = out.to_ascii_lowercase();
        assert!(lower.contains("powershell.exe -windowstyle hidden"), "{out}");
        assert!(lower.contains("c:\\\\users\\\\public\\\\document\\\\lib\\\\sim.py"), "{out}");
    }

    #[test]
    fn decodes_cp708_hidden_download_and_invoke_samples() {
        for (src, ip) in [
            (
                include_bytes!("../../testdata/script/batch-cp708-powershell-dropper-db9.bat").as_slice(),
                "20.91.202.137",
            ),
            (
                include_bytes!("../../testdata/script/batch-cp708-powershell-dropper-e289.bat").as_slice(),
                "20.91.206.86",
            ),
        ] {
            let result = expand_batch_variables(src).expect("CP708 payload should decode");
            let lower = result.decoded.to_ascii_lowercase();
            assert!(lower.contains("powershell.exe -ep bypass -nop -noexit -windowstyle hidden"), "{lower}");
            assert!(lower.contains(&format!("downloadstring('http://{ip}//?a=")));
            assert!(lower.contains("| iex"));
            assert_eq!(result.chain_description, "batch:codepage-remap+set-expansion");
        }
    }

    #[test]
    fn rejects_malformed_cp708_remap_tables() {
        let mut src = include_bytes!("../../testdata/script/batch-cp708-powershell-dropper-db9.bat").to_vec();
        let table = src
            .windows(b"@jasa@=".len())
            .position(|w| w.eq_ignore_ascii_case(b"@jasa@="))
            .unwrap();
        src[table + b"@jasa@=".len() + 1] = src[table + b"@jasa@=".len()];
        assert!(decode_codepage_remap(&src).is_none());
    }
}
