//! The straightforward implementations the scans replaced, kept as the
//! specification: each re-decodes from every offset, which is easy to read and
//! check but quadratic. The `differential` tests assert the fast scans match.

use super::repeating::finish_xor_candidate;
use super::rolling::ROLLING_XOR_PATTERNS;
use super::*;

/// Decode `data` under `key` from every offset, with no overlap skipping:
/// the specification of the fast repeating-key scan.
pub(super) fn pattern_scan(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    apply_filters: bool,
    excluded_ranges: &[(usize, usize)],
) -> Vec<ExtractedString> {
    let key_preview = key_preview(key);

    // Results come out in offset order.
    (0..data.len())
        .filter_map(|pos| {
            // XOR decode while printable: data[pos+j] ^ key[j % len(key)].
            // A result needs `min_length` printable bytes, so a position
            // whose prefix fails cannot yield one.
            let key_len = key.len();
            let remaining = data.len() - pos;
            if remaining < min_length {
                return None;
            }
            if !(0..min_length)
                .all(|j| is_printable_byte_for_file_xor(data[pos + j] ^ key[j % key_len]))
            {
                return None;
            }

            // Skip excluded ranges (only checked after the fast printable pre-filter)
            if excluded_ranges
                .iter()
                .any(|&(start, end)| pos >= start && pos < end)
            {
                return None;
            }

            let mut decoded = Vec::new();

            // Track positions of single nulls in raw data (potential garbage boundaries)
            let mut null_positions = Vec::new();

            let max_len = std::cmp::min(1024, data.len() - pos);
            for j in 0..max_len {
                let raw = data[pos + j];
                let byte = raw ^ key[j % key_len];

                // Check for consecutive nulls in raw data (indicates end of actual string data),
                // but only stop if the XOR-decoded byte is also non-printable. When the decoded
                // byte is printable, the null is part of the encrypted payload, not zero padding.
                if raw == 0 && pos + j + 1 < data.len() && data[pos + j + 1] == 0 {
                    if !is_printable_byte_for_file_xor(byte) {
                        break;
                    }
                    // Single null at this position (consecutive null handled above)
                    null_positions.push(j);
                } else if raw == 0 {
                    // Single null (not followed by another null) - potential garbage boundary
                    null_positions.push(j);
                }

                if is_printable_byte_for_file_xor(byte) {
                    decoded.push(byte);
                } else {
                    break;
                }
            }

            // Trim at null boundaries if we detect garbage (consonant clusters)
            // Check all nulls, trim at the first one followed by garbage
            // Skip null at position 0 (start of string) as it's not a garbage boundary
            let mut trim_at: Option<usize> = None;
            for &null_pos in &null_positions {
                if null_pos == 0 {
                    continue; // Don't trim at start of string (inner loop continue, not outer)
                }
                if null_pos < decoded.len() {
                    let after_null = &decoded[null_pos..];
                    // Need at least 2 chars after null to detect garbage (e.g., "aTr")
                    if after_null.len() >= 2 {
                        // Count the longest run of consecutive ASCII consonants
                        // in the first 4 bytes. Operate directly on bytes — no
                        // UTF-8 conversion needed since we only check ASCII letters.
                        let check_len = after_null.len().min(4);
                        let max_consecutive = after_null[..check_len]
                            .iter()
                            .fold((0u32, 0u32), |(max, cur), &b| {
                                if b.is_ascii_alphabetic() {
                                    let is_vowel = matches!(
                                        b.to_ascii_lowercase(),
                                        b'a' | b'e' | b'i' | b'o' | b'u'
                                    );
                                    if is_vowel {
                                        (max, 0)
                                    } else {
                                        let next = cur + 1;
                                        (max.max(next), next)
                                    }
                                } else {
                                    (max, 0)
                                }
                            })
                            .0;

                        if max_consecutive >= 3 {
                            trim_at = Some(null_pos);
                            break; // Trim at first garbage boundary
                        }
                    }
                }
            }

            if let Some(trim_pos) = trim_at {
                decoded.truncate(trim_pos);
            }

            // Check minimum length after trimming
            if decoded.len() < min_length {
                return None;
            }

            // Skip strings decoded from null-heavy regions. When raw bytes are
            // mostly zero the XOR output is just the key text reflected back —
            // not actual encrypted content.
            let raw_null_count = data[pos..pos + decoded.len()]
                .iter()
                .filter(|&&b| b == 0)
                .count();
            if raw_null_count * 2 > decoded.len() {
                return None;
            }

            finish_xor_candidate(pos, decoded, min_length, apply_filters, &key_preview)
        })
        .collect()
}

/// The offsets [`pattern_scan`] decodes into strings, with their decoded
/// lengths: its per-offset walk, null trim and null-ratio checks, verbatim.
pub(super) fn pattern_candidates(
    data: &[u8],
    key: &[u8],
    min_length: usize,
    excluded_ranges: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for pos in 0..data.len() {
        let key_len = key.len();
        let remaining = data.len() - pos;
        if remaining < min_length {
            continue;
        }
        if !(0..min_length)
            .all(|j| is_printable_byte_for_file_xor(data[pos + j] ^ key[j % key_len]))
        {
            continue;
        }

        // Skip excluded ranges (only checked after the fast printable pre-filter)
        if excluded_ranges
            .iter()
            .any(|&(start, end)| pos >= start && pos < end)
        {
            continue;
        }

        let mut decoded = Vec::new();

        // Track positions of single nulls in raw data (potential garbage boundaries)
        let mut null_positions = Vec::new();

        let max_len = std::cmp::min(1024, data.len() - pos);
        for j in 0..max_len {
            let raw = data[pos + j];
            let byte = raw ^ key[j % key_len];

            // Check for consecutive nulls in raw data (indicates end of actual string data),
            // but only stop if the XOR-decoded byte is also non-printable. When the decoded
            // byte is printable, the null is part of the encrypted payload, not zero padding.
            if raw == 0 && pos + j + 1 < data.len() && data[pos + j + 1] == 0 {
                if !is_printable_byte_for_file_xor(byte) {
                    break;
                }
                // Single null at this position (consecutive null handled above)
                null_positions.push(j);
            } else if raw == 0 {
                // Single null (not followed by another null) - potential garbage boundary
                null_positions.push(j);
            }

            if is_printable_byte_for_file_xor(byte) {
                decoded.push(byte);
            } else {
                break;
            }
        }

        // Trim at null boundaries if we detect garbage (consonant clusters)
        // Check all nulls, trim at the first one followed by garbage
        // Skip null at position 0 (start of string) as it's not a garbage boundary
        let mut trim_at: Option<usize> = None;
        for &null_pos in &null_positions {
            if null_pos == 0 {
                continue; // Don't trim at start of string (inner loop continue, not outer)
            }
            if null_pos < decoded.len() {
                let after_null = &decoded[null_pos..];
                // Need at least 2 chars after null to detect garbage (e.g., "aTr")
                if after_null.len() >= 2 {
                    // Count the longest run of consecutive ASCII consonants
                    // in the first 4 bytes. Operate directly on bytes — no
                    // UTF-8 conversion needed since we only check ASCII letters.
                    let check_len = after_null.len().min(4);
                    let max_consecutive = after_null[..check_len]
                        .iter()
                        .fold((0u32, 0u32), |(max, cur), &b| {
                            if b.is_ascii_alphabetic() {
                                let is_vowel = matches!(
                                    b.to_ascii_lowercase(),
                                    b'a' | b'e' | b'i' | b'o' | b'u'
                                );
                                if is_vowel {
                                    (max, 0)
                                } else {
                                    let next = cur + 1;
                                    (max.max(next), next)
                                }
                            } else {
                                (max, 0)
                            }
                        })
                        .0;

                    if max_consecutive >= 3 {
                        trim_at = Some(null_pos);
                        break; // Trim at first garbage boundary
                    }
                }
            }
        }

        if let Some(trim_pos) = trim_at {
            decoded.truncate(trim_pos);
        }

        // Check minimum length after trimming
        if decoded.len() < min_length {
            continue;
        }

        // Skip strings decoded from null-heavy regions. When raw bytes are
        // mostly zero the XOR output is just the key text reflected back —
        // not actual encrypted content.
        let raw_null_count = data[pos..pos + decoded.len()]
            .iter()
            .filter(|&&b| b == 0)
            .count();
        if raw_null_count * 2 > decoded.len() {
            continue;
        }
        out.push((pos, decoded.len()));
    }
    out
}

/// Extract strings using rolling/index-based XOR with known plaintext patterns.
///
/// This function detects XOR obfuscation where the key is short (1-4 bytes) and cycles.
/// It uses known plaintext patterns (Windows environment variables, registry paths)
/// to derive candidate keys, then validates by checking if multiple patterns decode
/// correctly with the same key.
///
/// This is common in .NET malware like Redline Stealer which XORs configuration
/// strings with short cycling keys.
pub(super) fn rolling(
    data: &[u8],
    min_length: usize,
    excluded_ranges: &[(usize, usize)],
) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    // Pre-seed covered_ranges with excluded_ranges (code sections). The
    // while-loop below already skips offsets inside any covered range, so
    // code segments are never inspected.
    let mut covered_ranges: Vec<(usize, usize)> = excluded_ranges.to_vec();

    // Try key lengths from 1 to 4 bytes
    for key_len in 1..=4usize {
        for pattern in ROLLING_XOR_PATTERNS {
            if pattern.len() < key_len {
                continue;
            }

            let max_offset = data.len().saturating_sub(pattern.len());
            let mut offset = 0;
            while offset < max_offset {
                // Skip offsets inside already-extracted regions
                if let Some(&(_, end)) = covered_ranges
                    .iter()
                    .find(|&&(start, end)| offset >= start && offset < end)
                {
                    offset = end;
                    continue;
                }

                // Derive candidate key on the stack (max 4 bytes)
                let mut candidate_key = [0u8; 4];
                candidate_key[..key_len]
                    .iter_mut()
                    .zip(&data[offset..])
                    .zip(pattern.iter())
                    .for_each(|((slot, &d), &p)| *slot = d ^ p);

                // Skip keys that are all zeros
                if candidate_key[..key_len].iter().all(|&b| b == 0) {
                    offset += 1;
                    continue;
                }
                // Skip keys where all bytes are identical (likely false positive)
                if key_len > 1
                    && candidate_key[..key_len]
                        .iter()
                        .all(|&b| b == candidate_key[0])
                {
                    offset += 1;
                    continue;
                }

                // Validate: does entire pattern decode correctly with this key?
                // Inline comparison — no allocation needed.
                let valid = (0..pattern.len())
                    .all(|i| (data[offset + i] ^ candidate_key[i % key_len]) == pattern[i]);
                if !valid {
                    offset += 1;
                    continue;
                }

                // Count how many OTHER patterns also decode correctly nearby
                let mut pattern_matches = 1u32;
                for other_pattern in ROLLING_XOR_PATTERNS {
                    if std::ptr::eq((*pattern).as_ptr(), (*other_pattern).as_ptr()) {
                        continue;
                    }

                    let search_start = offset.saturating_sub(2048);
                    let search_end =
                        (offset + 2048).min(data.len().saturating_sub(other_pattern.len()));

                    // Inline byte-wise XOR comparison — no allocation
                    if (search_start..search_end).any(|check_offset| {
                        (0..other_pattern.len()).all(|i| {
                            (data[check_offset + i] ^ candidate_key[i % key_len])
                                == other_pattern[i]
                        })
                    }) {
                        pattern_matches += 1;
                    }
                }

                if pattern_matches < 2 {
                    offset += 1;
                    continue;
                }

                // Valid key found — extract strings from an 8KB region around the match
                let region_start = offset.saturating_sub(4096);
                let region_end = (offset + 4096).min(data.len());
                let region = &data[region_start..region_end];
                covered_ranges.push((region_start, region_end));

                // Fixed 2026-10-01: decode with the key aligned to `offset`.
                let skew = key_len - (offset - region_start) % key_len;
                let decoded: Vec<u8> = region
                    .iter()
                    .enumerate()
                    .map(|(i, &b)| b ^ candidate_key[(i + skew) % key_len])
                    .collect();
                let mut run_start = 0;
                for run in decoded.split(|&b| !is_printable_byte_for_file_xor(b)) {
                    let start = run_start;
                    run_start += run.len() + 1;
                    if run.len() >= min_length
                        && let Ok(s) = std::str::from_utf8(run)
                        && s.bytes().any(|b| b.is_ascii_alphabetic())
                    {
                        results.push(ExtractedString {
                            value: s.to_owned(),
                            data_offset: (region_start + start) as u64,
                            method: StringMethod::XorDecode,
                            kind: classify_xor_string(s).kind(),
                            ..Default::default()
                        });
                    }
                }

                // Jump past the extracted region
                offset = region_end;
            }
        }
    }

    // Deduplicate by offset + value
    results.sort_by_key(|s| s.data_offset);
    results.dedup_by(|a, b| a.data_offset == b.data_offset && a.value == b.value);

    results
}

/// The single-byte anchors as [`super::single_byte_xor_anchors`] replaced
/// them: every pattern XOR'd with every allowed key (and in UTF-16LE form when
/// `wide`), in one large automaton.
pub(super) fn single_byte_anchors(data: &[u8], wide: bool) -> Vec<(usize, u8, bool)> {
    /// An automaton and each pattern's `(key, wide)`.
    type Anchors = (AhoCorasick, Vec<(u8, bool)>);
    static AUTOMATA: LazyLock<[Anchors; 2]> = LazyLock::new(|| [build(false), build(true)]);
    fn build(wide: bool) -> Anchors {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut info = Vec::new();
        for key in 1u8..=255 {
            if SKIP_XOR_KEYS.contains(&key) {
                continue;
            }
            for prefix in XOR_PATTERNS {
                patterns.push(prefix.iter().map(|b| b ^ key).collect());
                info.push((key, false));
                if wide {
                    patterns.push(prefix.iter().flat_map(|&b| [b ^ key, key]).collect());
                    info.push((key, true));
                }
            }
        }
        (
            AhoCorasick::new(&patterns).expect("reference automaton"),
            info,
        )
    }
    let (ac, info) = &AUTOMATA[usize::from(wide)];
    let mut found: Vec<(usize, u8, bool)> = ac
        .find_overlapping_iter(data)
        .map(|m| {
            let (key, is_wide) = info[m.pattern().as_usize()];
            (m.start(), key, is_wide)
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

#[cfg(test)]
mod differential {
    use super::super::extract_custom_xor_strings_pattern_based_simple;
    use super::super::repeating::{Alignment, scan_alignments};
    use super::super::rolling::{ROLLING_XOR_PATTERNS, extract_rolling_xor_with_known_plaintext};
    use rayon::prelude::*;

    /// xorshift64*: deterministic cases, so a failure reproduces by seed.
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
        }
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    const WORDS: &[&str] = &[
        "http://",
        "evil.example.com/",
        "payload",
        "/bin/sh",
        "-c ",
        "curl ",
        "C:\\Windows\\",
        "System32",
        "cmd.exe",
        "powershell",
        "Mozilla/5.0",
        "strstr",
        "passwd",
        ".dll",
        "VirtualAlloc",
        "Library",
        "the ",
        "quick ",
        "brown ",
        "rhythm",
        "xyzzy",
        "tsktsk",
    ];

    /// Mixed content: null padding (often longer than the 1 KB decode cap),
    /// random bytes, and text XOR'd with `key` at a random alignment, some of
    /// it long and sprinkled with raw nulls (which decode to key bytes, so the
    /// run continues and each null is a potential garbage boundary).
    fn buffer(rng: &mut Rng, len: usize, key: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let mut segment = Vec::new();
            match rng.below(5) {
                0 => segment.resize(1 + rng.below(3000), 0),
                4 => {
                    // Long runs (past the decode cap) with raw nulls: either
                    // consonant-dense, cut at nearly every null, or syllables
                    // whose rare consonant clusters put garbage boundaries at
                    // every distance from a capped decode's end.
                    const CONSONANTS: &[u8] = b"bcdfghjklmnpqrstvwxzBCDFGHJKLMNPQRSTVWXZ";
                    const VOWELS: &[u8] = b"aeiouAEIOU";
                    let dense = rng.below(2) == 0;
                    let len = 1100 + rng.below(1500);
                    // Syllable runs get a raw null then "xyz" about every
                    // 1.1 KB, so some capped decode ends just past one.
                    let first_cluster = rng.below(550);
                    let mut clusters = Vec::new();
                    while segment.len() < len {
                        segment.push(CONSONANTS[rng.below(CONSONANTS.len())]);
                        if !dense {
                            if segment.len() / 2 % 550 == first_cluster {
                                clusters.push(segment.len());
                                segment.extend_from_slice(b"xyz");
                            }
                            segment.push(VOWELS[rng.below(VOWELS.len())]);
                        }
                    }
                    let phase = rng.below(key.len());
                    for (i, b) in segment.iter_mut().enumerate() {
                        *b ^= key[(i + phase) % key.len()];
                    }
                    let gap = if dense {
                        2 + rng.below(6)
                    } else {
                        30 + rng.below(60)
                    };
                    for i in (rng.below(gap)..segment.len()).step_by(gap) {
                        segment[i] = 0;
                    }
                    for c in clusters {
                        segment[c - 1] = 0;
                    }
                }
                kind => {
                    let words = if kind == 3 { 300 } else { 12 };
                    for _ in 0..1 + rng.below(words) {
                        segment.extend_from_slice(WORDS[rng.below(WORDS.len())].as_bytes());
                    }
                    let phase = rng.below(key.len());
                    for (i, b) in segment.iter_mut().enumerate() {
                        *b ^= key[(i + phase) % key.len()];
                    }
                    if kind == 3 {
                        let gap = 2 + rng.below(30);
                        for i in (rng.below(gap)..segment.len()).step_by(gap) {
                            segment[i] = 0;
                        }
                    }
                }
            }
            out.extend(segment);
        }
        out.truncate(len);
        out
    }

    fn excluded(rng: &mut Rng, len: usize) -> Vec<(usize, usize)> {
        (0..rng.below(3))
            .map(|_| {
                let start = rng.below(len);
                (start, start + rng.below(2000))
            })
            .collect()
    }

    #[test]
    fn pattern_scan_matches_reference() {
        const KEY_BYTES: &[u8] = b"/UsersbcdfghjklmnpqrstvwxzBCDFGHJKLMNPQRSTVWXZ0123456789._-";
        let hits: usize = (0..160u64)
            .into_par_iter()
            .map(|seed| {
                let mut rng = Rng::new(seed);
                let key: Vec<u8> = (0..2 + rng.below(31))
                    .map(|_| KEY_BYTES[rng.below(KEY_BYTES.len())])
                    .collect();
                let len = 512 + rng.below(8 * 1024);
                let data = buffer(&mut rng, len, &key);
                let min_length = [4, 6, 10][rng.below(3)];
                let filters = rng.below(2) == 0;
                let excluded = excluded(&mut rng, data.len());
                let skip = super::super::Excluded::new(&excluded);
                let fresh = || -> Vec<Alignment> {
                    (0..key.len().min(data.len())).map(Alignment::new).collect()
                };
                let candidates =
                    scan_alignments(&mut fresh(), &data, &key, min_length, &skip, data.len());
                assert_eq!(
                    candidates,
                    super::pattern_candidates(&data, &key, min_length, &excluded),
                    "seed {seed}, candidates"
                );
                // Resuming across arbitrary windows finds the same candidates.
                let (mut resumed, mut alignments, mut limit) = (Vec::new(), fresh(), 0);
                while limit < data.len() {
                    limit += 1 + rng.below(3000);
                    resumed.extend(scan_alignments(
                        &mut alignments,
                        &data,
                        &key,
                        min_length,
                        &skip,
                        limit,
                    ));
                }
                assert_eq!(resumed, candidates, "seed {seed}, resumed");
                let want = super::pattern_scan(&data, &key, min_length, filters, &excluded);
                let got = extract_custom_xor_strings_pattern_based_simple(
                    &data, &key, min_length, filters, &skip, false,
                );
                assert_eq!(got, want, "seed {seed}");
                let first = extract_custom_xor_strings_pattern_based_simple(
                    &data, &key, min_length, filters, &skip, true,
                );
                assert_eq!(first, want[..want.len().min(50)], "seed {seed}, early");
                want.len()
            })
            .sum();
        assert!(hits > 500, "cases should decode strings, got {hits}");
    }

    #[test]
    fn rolling_scan_matches_reference() {
        let hits: usize = (0..300u64)
            .into_par_iter()
            .map(|seed| {
                let mut rng = Rng::new(seed);
                let len = 1024 + rng.below(16 * 1024);
                let mut data = buffer(&mut rng, len, b"k");
                let key_len = 1 + rng.below(4);
                let key: Vec<u8> = match rng.below(6) {
                    0 => vec![0; key_len],
                    1 => vec![rng.next() as u8; key_len],
                    _ => (0..key_len).map(|_| rng.next() as u8).collect(),
                };
                // Plant patterns, clustered so some fall within 2 KB of another.
                let center = rng.below(data.len());
                for _ in 0..rng.below(5) {
                    let pattern = ROLLING_XOR_PATTERNS[rng.below(ROLLING_XOR_PATTERNS.len())];
                    let at = (center + rng.below(3000)).saturating_sub(1500);
                    if at + pattern.len() <= data.len() {
                        for (i, &p) in pattern.iter().enumerate() {
                            data[at + i] = p ^ key[i % key_len];
                        }
                    }
                }
                let min_length = [4, 8][rng.below(2)];
                let excluded = excluded(&mut rng, data.len());
                let want = super::rolling(&data, min_length, &excluded);
                let got = extract_rolling_xor_with_known_plaintext(&data, min_length, &excluded);
                assert_eq!(got, want, "seed {seed}");
                want.len()
            })
            .sum();
        assert!(hits > 50, "cases should decode strings, got {hits}");
    }

    #[test]
    fn single_byte_anchors_match_reference() {
        use super::super::{XOR_PATTERNS, single_byte_xor_anchors};
        let hits: usize = (0..200u64)
            .into_par_iter()
            .map(|seed| {
                let mut rng = Rng::new(seed);
                let mut data: Vec<u8> = (0..4096).map(|_| rng.next() as u8).collect();
                for _ in 0..rng.below(8) {
                    let pattern = XOR_PATTERNS[rng.below(XOR_PATTERNS.len())];
                    let key = rng.next() as u8;
                    let wide = rng.below(2) == 0;
                    let encoded: Vec<u8> = if wide {
                        pattern.iter().flat_map(|&b| [b ^ key, key]).collect()
                    } else {
                        pattern.iter().map(|b| b ^ key).collect()
                    };
                    let at = rng.below(data.len() - encoded.len());
                    data[at..at + encoded.len()].copy_from_slice(&encoded);
                }
                for wide in [false, true] {
                    assert_eq!(
                        single_byte_xor_anchors(&data, wide),
                        super::single_byte_anchors(&data, wide),
                        "seed {seed}, wide {wide}"
                    );
                }
                super::single_byte_anchors(&data, true).len()
            })
            .sum();
        assert!(hits > 300, "cases should plant anchors, got {hits}");
    }
}
