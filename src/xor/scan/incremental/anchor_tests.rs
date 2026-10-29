use super::{MIN_ANCHOR_LEN, XOR_PATTERNS, find_incremental_anchors};

/// The original pattern-major, offset-ascending brute-force scan that
/// [`find_incremental_anchors`] replaces. Kept here as the oracle: the
/// Aho-Corasick inversion is only worth having if it is exactly equal.
fn reference_anchors(data: &[u8]) -> Vec<(usize, usize, u8)> {
    let mut out = Vec::new();
    for (pattern_idx, pattern) in XOR_PATTERNS.iter().enumerate() {
        if pattern.len() < MIN_ANCHOR_LEN {
            continue;
        }
        // Inclusive: a pattern may end at the last byte.
        let Some(max_offset) = data.len().checked_sub(pattern.len()) else {
            continue;
        };
        for offset in 0..=max_offset {
            let seed = data[offset] ^ pattern[0];
            if seed == 0 {
                continue;
            }
            let valid = (1..pattern.len())
                .all(|i| (data[offset + i] ^ seed.wrapping_add(i as u8)) == pattern[i]);
            if valid {
                out.push((pattern_idx, offset, seed));
            }
        }
    }
    out
}

fn assert_agrees(data: &[u8], label: &str) {
    let mut got = find_incremental_anchors(data);
    got.sort_unstable();
    let mut want = reference_anchors(data);
    want.sort_unstable();
    assert_eq!(got, want, "anchor mismatch on {label}");
}

/// `data[offset + i] = pattern[i] ^ (seed + i)` — what the scan looks for.
fn encode(pattern: &[u8], seed: u8) -> Vec<u8> {
    pattern
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ seed.wrapping_add(i as u8))
        .collect()
}

#[test]
fn matches_reference_on_planted_anchors() {
    // Every eligible pattern, at a spread of seeds including the wrapping
    // edges, planted in filler that must not itself anchor.
    for (idx, pattern) in XOR_PATTERNS.iter().enumerate() {
        if pattern.len() < MIN_ANCHOR_LEN {
            continue;
        }
        for seed in [1u8, 7, 128, 200, 255] {
            let mut data = vec![0u8; 32];
            data.extend(encode(pattern, seed));
            data.extend(vec![0u8; 32]);
            let anchors = find_incremental_anchors(&data);
            assert!(
                anchors.contains(&(idx, 32, seed)),
                "planted pattern {pattern:?} seed {seed} not found"
            );
            assert_agrees(&data, "planted");
            // Ending at the last byte of the input.
            let tail: Vec<u8> = vec![0u8; 8]
                .into_iter()
                .chain(encode(pattern, seed))
                .collect();
            assert!(find_incremental_anchors(&tail).contains(&(idx, 8, seed)));
            assert_agrees(&tail, "planted at end");
        }
    }
}

#[test]
fn matches_reference_on_pseudorandom_and_degenerate_input() {
    // Deterministic LCG: dense enough to produce chance anchors, which is
    // where an off-by-one in the inversion would show up.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut data: Vec<u8> = Vec::with_capacity(64 * 1024);
    for _ in 0..64 * 1024 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        data.push((state >> 33) as u8);
    }
    assert_agrees(&data, "pseudorandom");

    assert_agrees(b"", "empty");
    assert_agrees(b"abc", "shorter than any pattern");
    assert_agrees(&vec![0u8; 4096], "all zeroes");
    assert_agrees(&vec![0xFFu8; 4096], "all ones");
    // Plain text: seed 0 is excluded, so unobfuscated patterns must not anchor.
    assert_agrees(b"https://example.com/bin/sh .exe .dll passw", "plaintext");
}
