//! Repeating-key decoding from known-plaintext pattern hits: every key
//! alignment of the hit is decoded, grown while printable, and filtered.

use super::{Excluded, is_printable_byte_for_file_xor, key_preview};
use crate::validation;
use crate::xor::classify::{
    Verdict, classify_xor_string, clean_locale_trailing_garbage, clean_url_trailing_garbage,
    trim_consonant_clusters, trim_trailing_garbage,
};
use crate::xor::validate::is_locale_string;
use crate::{ExtractedString, StringKind, StringMethod};
use rayon::prelude::*;

/// Maximum number of valid strings to find before early termination.
/// After finding this many validated strings (of any kind), we can stop scanning.
/// This provides diminishing returns - 50 strings is typically enough to identify
/// XOR-encoded content and extract key IOCs without scanning the entire file.
/// Testing shows this reduces scan time by 10-100x while preserving malware detection.
pub(super) const MAX_STRINGS_BEFORE_EARLY_TERMINATION: usize = 50;

/// First window scanned when terminating early; each later one doubles.
pub(super) const EARLY_TERMINATION_WINDOW: usize = 4096;

/// Longest decode attempted from one offset.
pub(super) const MAX_PATTERN_DECODE: usize = 1024;

/// Simplified pattern-based extraction matching decode.py behavior.
/// Scans every offset, no overlap skipping, minimal filtering.
///
/// Every offset whose XOR decode starts a printable run yields a candidate (the
/// caller resolves overlaps), so decoding each offset independently re-walks a
/// run once per offset inside it: quadratic on null padding, which a printable
/// key decodes to printable text. [`Alignment`] finds each run once per key
/// alignment instead, and only its survivors are decoded and classified.
///
/// # Arguments
/// * `enable_early_termination` - If true, returns only the first
///   MAX_STRINGS_BEFORE_EARLY_TERMINATION strings by offset. Should be true for
///   auto-detection (speeds up candidate testing) and false for user-provided
///   keys (ensures complete extraction).
pub(super) fn extract_custom_xor_strings_pattern_based_simple(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    apply_filters: bool,
    excluded: &Excluded,
    enable_early_termination: bool,
) -> Vec<ExtractedString> {
    let mut alignments: Vec<Alignment> =
        (0..key.len().min(data.len())).map(Alignment::new).collect();
    let mut scan =
        |limit: usize| scan_alignments(&mut alignments, data, key, min_length, excluded, limit);
    let key_preview = key_preview(key);
    let finish = |&(pos, len): &(usize, usize)| {
        let decoded = data[pos..pos + len]
            .iter()
            .zip(key.iter().cycle())
            .map(|(b, k)| b ^ k)
            .collect();
        finish_xor_candidate(pos, decoded, min_length, apply_filters, &key_preview)
    };
    if !enable_early_termination {
        return scan(data.len())
            .par_iter()
            .with_min_len(crate::par::MIN_ITEMS_PER_JOB)
            .filter_map(finish)
            .collect();
    }
    // Keep the first strings by offset. Scanning windows that double in size,
    // and classifying their candidates in offset order, stops at the cut.
    let mut results = Vec::new();
    let (mut limit, mut window) = (0, EARLY_TERMINATION_WINDOW);
    while limit < data.len() {
        limit = limit.saturating_add(window).min(data.len());
        window = window.saturating_mul(2);
        for candidate in &scan(limit) {
            results.extend(finish(candidate));
            if results.len() == MAX_STRINGS_BEFORE_EARLY_TERMINATION {
                return results;
            }
        }
    }
    results
}

/// Advance every alignment to `limit`; the candidates found, by offset.
pub(super) fn scan_alignments(
    alignments: &mut [Alignment],
    data: &[u8],
    key: &[u8],
    min_length: usize,
    excluded: &Excluded,
    limit: usize,
) -> Vec<(usize, usize)> {
    let job_len = crate::par::job_len(alignments.len(), limit);
    let mut candidates: Vec<(usize, usize)> = alignments
        .par_iter_mut()
        .with_min_len(job_len)
        .flat_map_iter(|a| a.scan(data, key, min_length, excluded, limit))
        .collect();
    candidates.sort_unstable();
    candidates
}

/// Pattern-scan state for the offsets `phase, phase + k, …` (k = key length),
/// resumable so early termination can stop partway through a file.
///
/// From each offset the decode runs while bytes stay printable, at most
/// [`MAX_PATTERN_DECODE`] bytes, and is cut at the first raw null that starts
/// garbage ([`starts_garbage`]). It survives if at least `min_length` long and
/// at most half raw nulls. Every offset of one alignment decodes a given byte
/// with the same key byte, so a run's end, and the first garbage null after a
/// point, hold for each later offset in that run: both are found once per run,
/// not once per offset.
pub(super) struct Alignment {
    phase: usize,
    /// The next offset to scan.
    next: usize,
    /// Bytes from the current offset up to `run_end` decode printable.
    run_end: usize,
    /// No garbage null in [garbage_from, garbage); `garbage` is one, or run_end.
    garbage_from: usize,
    garbage: usize,
    /// Raw bytes from the current offset up to `zeros_end` are null.
    zeros_end: usize,
}

impl Alignment {
    pub(super) fn new(phase: usize) -> Self {
        Self {
            phase,
            next: phase,
            run_end: 0,
            garbage_from: usize::MAX,
            garbage: 0,
            zeros_end: 0,
        }
    }

    /// The candidates at this alignment's offsets below `limit`, as
    /// `(offset, length)`.
    fn scan(
        &mut self,
        data: &[u8],
        key: &[u8],
        min_length: usize,
        excluded: &Excluded,
        limit: usize,
    ) -> Vec<(usize, usize)> {
        let (k, phase) = (key.len(), self.phase);
        let decode = |i: usize| data[i] ^ key[(i - phase) % k];
        let mut out = Vec::new();
        while self.next < limit.min(data.len()) {
            let pos = self.next;
            self.next += k;
            if pos >= self.run_end {
                self.run_end = pos;
                for &key_byte in key.iter().cycle() {
                    if self.run_end == data.len()
                        || !is_printable_byte_for_file_xor(data[self.run_end] ^ key_byte)
                    {
                        break;
                    }
                    self.run_end += 1;
                }
                self.garbage_from = usize::MAX;
            }
            let run_end = self.run_end;
            let end = run_end.min(pos + MAX_PATTERN_DECODE);
            if end - pos < min_length || excluded.contains(pos) {
                continue;
            }
            // Inside null padding, which a printable key decodes to printable
            // text. A leading null run longer than half the longest possible
            // decode makes any cut of it more than half null, rejected below.
            if pos >= self.zeros_end {
                self.zeros_end = data[pos..]
                    .iter()
                    .position(|&b| b != 0)
                    .map_or(data.len(), |n| pos + n);
            }
            if (self.zeros_end - pos) * 2 > end - pos {
                continue;
            }
            if !(self.garbage_from <= pos + 1 && pos < self.garbage) {
                self.garbage_from = pos + 1;
                self.garbage = (pos + 1..run_end)
                    .find(|&i| data[i] == 0 && starts_garbage(decode, i, run_end))
                    .unwrap_or(run_end);
            }
            let garbage = self.garbage;
            let cut = if end == run_end {
                (garbage < end).then_some(garbage)
            } else if garbage + 4 <= end {
                Some(garbage)
            } else {
                // The decode cap ended this run early, so a null within three
                // bytes of `end` sees a shorter window than it did against the run.
                (end.saturating_sub(3).max(pos + 1)..end)
                    .find(|&i| data[i] == 0 && starts_garbage(decode, i, end))
            };
            let stop = cut.unwrap_or(end);
            let len = stop - pos;
            // Mostly-null source decodes to the key reflected back, not content.
            let nulls = data[pos..stop].iter().filter(|&&b| b == 0).count();
            if len >= min_length && nulls * 2 <= len {
                out.push((pos, len));
            }
        }
        out
    }
}

/// Whether the raw null at `i` starts garbage in a decode ending at `end`: at
/// least two decoded bytes remain, and the first (up to) four hold three
/// consecutive ASCII consonants.
pub(super) fn starts_garbage(decode: impl Fn(usize) -> u8, i: usize, end: usize) -> bool {
    if end - i < 2 {
        return false;
    }
    let mut consonants = 0;
    for b in (i..end.min(i + 4)).map(decode) {
        let vowel = matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u');
        consonants = if b.is_ascii_alphabetic() && !vowel {
            consonants + 1
        } else {
            0
        };
        if consonants >= 3 {
            return true;
        }
    }
    false
}

/// Enough alphanumerics (60% under an auto-detected key, else 50%) and, for
/// ASCII text that is not a network indicator or a locale code (which lack
/// vowels by nature), a vowel ratio in a natural-language range.
pub(super) fn plausible_letters(s: &str, kind: Option<StringKind>, strict: bool) -> bool {
    let char_count = s.chars().count();
    let alnum = s.chars().filter(|c| c.is_alphanumeric()).count();
    let min_alnum_pct = if strict { 60 } else { 50 };
    if char_count > 0 && alnum * 100 < char_count * min_alnum_pct {
        return false;
    }
    let alpha = s.chars().filter(|c| c.is_alphabetic()).count();
    let network = matches!(
        kind,
        Some(StringKind::Url | StringKind::Ip | StringKind::IpPort)
    );
    if network || alpha < 3 || !s.is_ascii() || is_locale_string(s) {
        return true;
    }
    let vowels = s
        .bytes()
        .filter(|b| matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u'))
        .count();
    let (min_vowel, max_vowel) = if strict { (12, 65) } else { (10, 70) };
    (min_vowel..=max_vowel).contains(&(vowels * 100 / alpha))
}

/// Strip the junk a misaligned decode leaves after each kind: URL and locale
/// tails, a backtick and letter after a path (`` `R ``), shell garbage.
pub(super) fn trim_kind_tail(kind: Option<StringKind>, s: String) -> String {
    match kind {
        Some(StringKind::Url) => clean_url_trailing_garbage(&s),
        Some(StringKind::SuspiciousPath) if is_locale_string(&s) => {
            clean_locale_trailing_garbage(&s)
        }
        Some(StringKind::SuspiciousPath) => {
            let b = s.as_bytes();
            match b.iter().rposition(u8::is_ascii_alphabetic) {
                Some(idx) if idx > 0 && b[idx - 1] == b'`' => s[..idx - 1].to_string(),
                _ => s,
            }
        }
        Some(StringKind::ShellCmd) => trim_trailing_garbage(&s).to_string(),
        _ => s,
    }
}

/// Validate, clean and classify one decoded candidate from the pattern scan.
pub(super) fn finish_xor_candidate(
    pos: usize,
    decoded: Vec<u8>,
    min_length: usize,
    apply_filters: bool,
    key_preview: &str,
) -> Option<ExtractedString> {
    // Convert to string - if full conversion fails, try to salvage valid UTF-8 prefix
    let s = match String::from_utf8(decoded) {
        Ok(s) => s,
        Err(e) => {
            // UTF-8 conversion failed - try to salvage the valid prefix
            // This handles cases where valid ASCII/UTF-8 data is followed by garbage
            let valid_up_to = e.utf8_error().valid_up_to();
            if valid_up_to >= min_length {
                // We have enough valid UTF-8 data - recover bytes and use valid prefix
                let mut bytes = e.into_bytes();
                bytes.truncate(valid_up_to);
                // Garbage can decode to a valid multi-byte character before the
                // first invalid byte. After a long ASCII run, a non-ASCII tail of
                // at most one character belongs to that garbage.
                if let Some(ascii) = bytes.iter().position(|b| !b.is_ascii())
                    && ascii >= min_length
                    && std::str::from_utf8(&bytes[ascii..]).is_ok_and(|t| t.chars().count() == 1)
                {
                    bytes.truncate(ascii);
                }
                match String::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => return None, // Still invalid, skip
                }
            } else {
                // Not enough valid data
                return None;
            }
        }
    };

    // Must have at least one letter, unless it's a known shell redirect/operator
    let is_shell_op = s.contains("2>&") || s.contains("2>/") || s.contains("1>&");
    if !is_shell_op && !s.chars().any(char::is_alphabetic) {
        return None;
    }

    // Apply early trimming before classification to remove obvious garbage
    // This ensures classification sees clean strings
    let trimmed_s = trim_consonant_clusters(&s);

    // Re-check minimum length after consonant cluster trimming
    if trimmed_s.len() < min_length {
        return None;
    }

    // Classify the string. When apply_filters=true, reject unclassified strings.
    // When apply_filters=false, still classify to assign the correct kind for
    // overlap resolution (IOCs win over generic Const strings of similar length).
    let kind = match classify_xor_string(&trimmed_s) {
        Verdict::Keep(kind) => kind,
        Verdict::Reject if apply_filters => return None,
        Verdict::Reject => None,
    };

    // Keys that are paths were auto-detected; hold their output to a
    // stricter standard than a key the user gave.
    let strict = key_preview.starts_with('/') || key_preview.starts_with("C:\\");
    if !plausible_letters(&trimmed_s, kind, strict) {
        return None;
    }
    let cleaned_value = trim_kind_tail(kind, trimmed_s);

    // Category-specific cleaning (URL trailing garbage, shell cmd trimming, etc.) can
    // shorten the string below min_length. Re-check after cleaning.
    if cleaned_value.len() < min_length {
        return None;
    }

    // Pre-filter garbage before overlap removal: a garbage string that wins the overlap
    // contest would leave the byte range uncovered (the garbage gets removed in post-processing
    // but nothing else can fill that range). Skip it here so shorter, valid strings can win.
    //
    // Strings with embedded control characters (except tab/newline) are garbage.
    // Newlines are valid in multi-line XOR payloads (AppleScript, shell commands, etc.).
    let has_embedded_control = cleaned_value
        .bytes()
        .any(|b| b < 0x20 && b != b'\t' && b != b'\n');
    if has_embedded_control || validation::is_garbage(&cleaned_value) {
        return None;
    }

    Some(ExtractedString {
        value: cleaned_value,
        data_offset: pos as u64,
        data_len: 0,
        method: StringMethod::XorDecode,
        kind,
        fragments: None,
    })
}
