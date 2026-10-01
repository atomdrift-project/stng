//! Known-plaintext recovery of a PE encrypted with a short repeating XOR key.
//!
//! Droppers commonly ship their Windows payload as `payload[i] ^ key[i % n]`
//! inside a jar, zip or npm tarball and decrypt it at run time. To magic
//! detection the file is opaque bytes, so nothing downstream analyzes it.
//!
//! A PE opens with a DOS header whose content is almost fixed: `MZ`, a handful
//! of conventional linker values, a 32-byte run of reserved zeros at
//! `0x1c..0x3c`, and usually the standard DOS stub. XOR with that known
//! plaintext yields the key, so for each candidate period the key is *voted*
//! from those positions and then *validated* against structure the vote never
//! saw: the decoded `e_lfanew` must point inside the file at `PE\0\0`,
//! followed by a known COFF machine and an optional-header magic. That is
//! roughly 64 bits of independent evidence behind any accepted key, so random
//! data does not pass.
//!
//! The work is fixed, whatever the input size, and nothing is allocated. Key
//! bytes are voted lazily, only as validation reads them, and the cheapest
//! check that fails ends the period: for opaque data that is the range of the
//! decoded `e_lfanew`, which needs just the four key bytes at `0x3c..0x40`.
//! This is exact, not a heuristic prefilter: validation is the same
//! conjunction over the same voted bytes, evaluated in a different order, so
//! it accepts exactly the keys a full vote followed by validation would.
//!
//! This complements `scan::extract_rolling_xor_with_known_plaintext`, which
//! derives 1–4-byte keys from string prefixes at every offset of a PE and
//! keeps whatever decodes to text. That pass finds strings inside an image;
//! this one finds the image itself. The vote-then-validate split is what lets
//! the period reach 64 bytes here: every accepted key is checked against bytes
//! it was not derived from. The rolling pass could adopt it for longer keys,
//! but its acceptance test would need the same independence.

use crate::{ExtractedString, StringKind, StringMethod};

/// Largest key period tried.
const MAX_KEY_LEN: usize = 64;

/// Bytes of the DOS header and stub the vote reads: the source extent of
/// every recovered key.
const KEY_SOURCE_LEN: u32 = 0x80;
const TEMPLATE_LEN: usize = KEY_SOURCE_LEN as usize;
/// Maximum clear prefix before an XOR-encoded image. Small NOP sleds and
/// decoder prologues often precede the image; the search remains bounded.
const MAX_PE_PREFIX: usize = 16;

/// Smallest `e_lfanew` accepted: the DOS header itself is 0x40 bytes, and the
/// vote assumes the reserved region below it is zero.
const MIN_LFANEW: usize = 0x40;

/// COFF machine values of the Windows images worth recovering.
const KNOWN_MACHINES: [u16; 6] = [
    0x014c, // i386
    0x8664, // AMD64
    0xaa64, // ARM64
    0x01c4, // ARMNT
    0x01c0, // ARM
    0x0200, // IA64
];

/// Optional-header magics: PE32 and PE32+.
const OPTIONAL_MAGICS: [u16; 2] = [0x010b, 0x020b];

/// `e_magic` .. `e_ovno` as MSVC writes them.
const DOS_HEADER: &[u8; 0x1c] = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00";

/// The DOS stub MSVC, `MinGW`, Go and most other linkers emit at 0x40.
const DOS_STUB: &[u8; 0x39] =
    b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$";

/// Expected plaintext and vote weight for each of the first `TEMPLATE_LEN`
/// bytes of a PE. Weight 0 means unknown (`e_lfanew`).
///
/// Weights encode how universal each byte is: `MZ` is the definition, the
/// reserved zeros at `0x1c..0x3c` are zero in every linker's output, and the
/// other header fields and the stub vary (Borland/Delphi write other values
/// and a different stub), so they only break ties.
const TEMPLATE: [(u8, u8); TEMPLATE_LEN] = {
    let mut t = [(0u8, 0u8); TEMPLATE_LEN];
    let mut i = 0;
    while i < TEMPLATE_LEN {
        t[i] = match i {
            0 | 1 => (DOS_HEADER[i], 8),
            0x02..0x1c => (DOS_HEADER[i], 1),
            0x1c..0x3c => (0, 4),
            0x3c..0x40 => (0, 0),
            0x40..0x79 => (DOS_STUB[i - 0x40], 1),
            // Zero padding between the stub and the Rich or PE header.
            _ => (0, 1),
        };
        i += 1;
    }
    t
};

/// A repeating XOR key that decodes a whole file to a PE image.
///
/// The key is aligned to file offset 0: `plain[i] = data[i] ^ key[i % period]`.
/// It lives inline (no heap), so it can travel with a file's identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RepeatingXorKey {
    /// Bytes past `period` are zero.
    key: [u8; MAX_KEY_LEN],
    period: u8,
    /// Offset where the decoded image begins in the encoded file.
    pe_offset: u8,
}

impl RepeatingXorKey {
    /// The key bytes, aligned to file offset 0.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.key[..self.period()]
    }

    /// The key's period in bytes: the smallest that decodes the image.
    #[must_use]
    pub fn period(&self) -> usize {
        usize::from(self.period)
    }

    /// Offset of the decoded PE within the source file.
    #[must_use]
    pub fn pe_offset(&self) -> usize {
        usize::from(self.pe_offset)
    }

    /// The key as an `XorKey` string: arbitrary bytes rendered `0x<hex>`, as
    /// ARM64 stack-XOR recovery renders them, located at the header extent
    /// it was recovered from.
    pub(crate) fn to_key_string(self) -> ExtractedString {
        ExtractedString {
            value: format!("0x{}", crate::bytes::to_hex(self.bytes())),
            data_offset: u64::from(self.pe_offset),
            data_len: KEY_SOURCE_LEN,
            method: StringMethod::XorRepeatingKey,
            kind: Some(StringKind::XorKey),
            fragments: None,
        }
    }

    /// Decode `data`, the whole encoded file from offset 0.
    #[must_use]
    pub fn decode(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .zip(self.bytes().iter().cycle())
            .map(|(b, k)| b ^ k)
            .collect()
    }
}

/// Recover the repeating XOR key (period 1 to 64) that turns a PE at the
/// start of `data` or after a prefix of at most 16 bytes into a valid image,
/// returning the smallest period that validates.
///
/// Returns `None` for a plaintext PE (an all-zero key is not an encoding), and
/// for anything whose decoded header does not lead to `PE\0\0`, a known COFF
/// machine and a PE32/PE32+ optional-header magic.
#[must_use]
pub fn recover_repeating_xor_pe(data: &[u8]) -> Option<RepeatingXorKey> {
    // Keep the common case at offset zero as cheap as before. A short prefix
    // is tried only after a normal whole-file candidate fails.
    recover_at(data, 0).or_else(|| (1..=MAX_PE_PREFIX).find_map(|offset| recover_at(data, offset)))
}

fn recover_at(data: &[u8], pe_offset: usize) -> Option<RepeatingXorKey> {
    let image = data.get(pe_offset..)?;
    let head: &[u8; TEMPLATE_LEN] = image.first_chunk()?;
    // A plaintext PE is not an encoding. Checking it up front also keeps a
    // header that strays from the template from reading as a near-zero key.
    if is_pe_under(data, pe_offset, |_| 0) {
        return None;
    }
    // Each header byte's key candidate: what it XORs with to give the template.
    // The key stream is aligned to file offset zero even when the PE is
    // preceded by a clear stub or NOP prefix.
    let mut candidates = [0u8; TEMPLATE_LEN];
    for ((c, byte), (plain, _)) in candidates.iter_mut().zip(head).zip(&TEMPLATE) {
        *c = byte ^ plain;
    }
    let mut tally = [0u16; 256];
    for period in 1..=MAX_KEY_LEN {
        let mut key = LazyKey::new(&candidates, pe_offset, period);
        if !is_pe_under(data, pe_offset, |offset| key.at(offset, &mut tally)) {
            continue;
        }
        let key = key.complete(&mut tally);
        // A key with zero bytes (a little-endian DWORD such as `0x000000ab`)
        // votes all-zero at periods below its own; that is never the answer.
        if key.bytes().iter().any(|&k| k != 0) {
            return Some(key);
        }
    }
    None
}

/// The key of one candidate period, each byte voted on first use.
struct LazyKey<'a> {
    candidates: &'a [u8; TEMPLATE_LEN],
    pe_offset: usize,
    /// `1..=MAX_KEY_LEN`.
    period: usize,
    key: [u8; MAX_KEY_LEN],
    /// Bit `r` set once `key[r]` has been voted.
    voted: u64,
}

impl<'a> LazyKey<'a> {
    fn new(candidates: &'a [u8; TEMPLATE_LEN], pe_offset: usize, period: usize) -> Self {
        Self {
            candidates,
            pe_offset,
            period,
            key: [0; MAX_KEY_LEN],
            voted: 0,
        }
    }

    /// The key byte that applies at file offset `offset`.
    fn at(&mut self, offset: usize, tally: &mut [u16; 256]) -> u8 {
        let residue = offset % self.period;
        if self.voted & (1 << residue) == 0 {
            self.key[residue] =
                vote_at(self.candidates, self.pe_offset, residue, self.period, tally);
            self.voted |= 1 << residue;
        }
        self.key[residue]
    }

    fn complete(mut self, tally: &mut [u16; 256]) -> RepeatingXorKey {
        for residue in 0..self.period {
            self.at(residue, tally);
        }
        RepeatingXorKey {
            key: self.key,
            // `period <= MAX_KEY_LEN`, which fits.
            period: u8::try_from(self.period).unwrap_or(u8::MAX),
            pe_offset: u8::try_from(self.pe_offset).unwrap_or(u8::MAX),
        }
    }
}

/// Weighted vote for `key[residue]` over the template positions congruent to
/// `residue` mod `period` (`period >= 1`). A tie goes to the candidate seen
/// first, i.e. the one from the more reliable header bytes. Every residue
/// below `MAX_KEY_LEN` has a weighted position (`e_lfanew`'s residues reach
/// the padding at `0x7c..0x80`), so the vote is never empty.
///
/// `tally` is all zero on entry and on return: only the entries this vote
/// touched are reset, so one table serves a whole recovery.
#[cfg(test)]
fn vote(
    candidates: &[u8; TEMPLATE_LEN],
    residue: usize,
    period: usize,
    tally: &mut [u16; 256],
) -> u8 {
    vote_at(candidates, 0, residue, period, tally)
}

fn vote_at(
    candidates: &[u8; TEMPLATE_LEN],
    pe_offset: usize,
    residue: usize,
    period: usize,
    tally: &mut [u16; 256],
) -> u8 {
    // The weight-0 `e_lfanew` bytes carry no evidence and must not decide
    // which candidate counts as seen first. Residues are file-relative because
    // the repeating key is aligned to the start of the encoded file.
    let positions = || {
        (0..TEMPLATE_LEN)
            .filter(|&pos| (pe_offset + pos) % period == residue && TEMPLATE[pos].1 > 0)
    };
    for pos in positions() {
        tally[usize::from(candidates[pos])] += u16::from(TEMPLATE[pos].1);
    }
    // In order of first appearance; a candidate's total is read at its first
    // position and cleared, so repeats score 0 and never displace it.
    let mut best = (0u8, 0u16);
    for pos in positions() {
        let candidate = candidates[pos];
        let total = &mut tally[usize::from(candidate)];
        if *total > best.1 {
            best = (candidate, *total);
        }
        *total = 0;
    }
    best.0
}

/// Decode `N` bytes at `offset`, or `None` past the end.
fn decoded<const N: usize>(
    data: &[u8],
    offset: usize,
    key: &mut impl FnMut(usize) -> u8,
) -> Option<[u8; N]> {
    let src = data.get(offset..offset.checked_add(N)?)?;
    let mut out = [0u8; N];
    for (i, (o, b)) in out.iter_mut().zip(src).enumerate() {
        *o = b ^ key(offset + i);
    }
    Some(out)
}

/// Whether `data` decoded with `key` (the key byte for each file offset) has
/// the structure the vote did not see: `MZ`, then `e_lfanew` pointing inside
/// the file at `PE\0\0`, a known COFF machine and an optional-header magic.
///
/// The `e_lfanew` range is checked first: it rejects almost all opaque data
/// and needs the fewest key bytes.
fn is_pe_under(data: &[u8], pe_offset: usize, mut key: impl FnMut(usize) -> u8) -> bool {
    let Some(header_offset) = pe_offset.checked_add(0x3c) else {
        return false;
    };
    let Some(lfanew) = decoded(data, header_offset, &mut key)
        .map(u32::from_le_bytes)
        .and_then(|v| usize::try_from(v).ok())
    else {
        return false;
    };
    let Some(pe_header) = pe_offset.checked_add(lfanew) else {
        return false;
    };
    // The optional-header magic at `lfanew + 24` is the last byte read.
    if lfanew < MIN_LFANEW || pe_header.checked_add(26).is_none_or(|end| end > data.len()) {
        return false;
    }
    if decoded(data, pe_offset, &mut key) != Some(*b"MZ")
        || decoded(data, pe_header, &mut key) != Some(*b"PE\0\0")
    {
        return false;
    }
    let mut word = |offset: usize| decoded(data, offset, &mut key).map(u16::from_le_bytes);
    pe_header
        .checked_add(4)
        .and_then(&mut word)
        .is_some_and(|m| KNOWN_MACHINES.contains(&m))
        && pe_header
            .checked_add(24)
            .and_then(&mut word)
            .is_some_and(|m| OPTIONAL_MAGICS.contains(&m))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A candidate first seen at the weight-0 `e_lfanew` bytes is not "seen
    /// first" there: on a tie, the one first seen at a weighted byte wins.
    #[test]
    fn e_lfanew_bytes_do_not_break_ties() {
        // Period 2, residue 0: every other byte. Give each weighted byte a
        // distinct candidate except for two runs of equal length after 0x40:
        // `a` (also at e_lfanew, 0x3c) and `b`, with `b` first at 0x40.
        let mut candidates = [0u8; TEMPLATE_LEN];
        for (i, c) in candidates.iter_mut().enumerate() {
            *c = u8::try_from(i).unwrap_or(0) | 0x80;
        }
        let (a, b) = (1, 2);
        candidates[0x3c] = a;
        for (n, pos) in (0x40..TEMPLATE_LEN).step_by(2).enumerate() {
            if n < 20 {
                candidates[pos] = if n % 2 == 0 { b } else { a };
            }
        }
        let mut tally = [0u16; 256];
        assert_eq!(vote(&candidates, 0, 2, &mut tally), b);
    }

    /// `vote` against the obvious version: a first-seen-ordered tally over
    /// the weighted positions, highest total winning, earliest on a tie.
    #[test]
    fn vote_matches_a_first_seen_tally() {
        let mut s = 0x9e37_79b9_7f4a_7c15_u64;
        let mut tally = [0u16; 256];
        for case in 0..20_000 {
            // A 3-symbol alphabet makes ties the common case.
            let mut candidates = [0u8; TEMPLATE_LEN];
            for c in &mut candidates {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *c = (s % 3) as u8;
            }
            let period = 1 + case % MAX_KEY_LEN;
            for residue in 0..period {
                let mut order: Vec<(u8, u16)> = Vec::new();
                for pos in (residue..TEMPLATE_LEN).step_by(period) {
                    let weight = u16::from(TEMPLATE[pos].1);
                    if weight == 0 {
                        continue;
                    }
                    match order.iter_mut().find(|(k, _)| *k == candidates[pos]) {
                        Some(entry) => entry.1 += weight,
                        None => order.push((candidates[pos], weight)),
                    }
                }
                let top = order.iter().map(|&(_, w)| w).max().unwrap_or(0);
                let expected = order
                    .iter()
                    .find(|&&(_, w)| w == top)
                    .map_or(0, |&(k, _)| k);
                assert_eq!(vote(&candidates, residue, period, &mut tally), expected);
                assert!(tally.iter().all(|&t| t == 0), "tally left dirty");
            }
        }
    }
}
