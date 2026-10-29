use super::shape::*;
use super::*;

#[test]
fn test_dotnet_garbage_strings() {
    // These garbage strings from .NET native images should be filtered
    assert!(
        is_garbage("omor"),
        "omor should be garbage (nonsense 4-char)"
    );
    assert!(
        is_garbage("uDuntßñ6OlÇÕ"),
        "non-ASCII garbage should be filtered"
    );
    assert!(
        is_garbage("ððððೳóóóóࣵ"),
        "Unicode garbage should be filtered"
    );

    // Note: Short numeric strings with multiple unique digits (like "3343") could be
    // valid port numbers, IDs, etc. Only reject single-digit repeats like "3333"
    assert!(
        !is_garbage("3343"),
        "3343 has multiple unique digits - could be valid"
    );
    assert!(
        is_garbage("3333"),
        "3333 is all same digit - likely garbage"
    );

    // Note: "poe" and "pot" are valid 3-char English words, so they shouldn't be filtered
    // 3-char strings aren't automatically garbage
    assert!(!is_garbage("poe"), "poe is a valid word");
    assert!(!is_garbage("pot"), "pot is a valid word");
}

#[test]
fn test_repetitive_nonascii_patterns() {
    // Repetitive single-char patterns with non-ASCII are misaligned binary data
    // These come from .NET native images and have one letter repeated many times
    assert!(
        is_garbage("zçz&zÇzÌzhzµzyz½z{zHz}zQz\\zYz0z8z"),
        "z-pattern garbage"
    );
    // These patterns are harder to catch because they have fewer non-ASCII chars
    // or different char distributions. Skip for now as main garbage is filtered.
}

#[test]
fn test_reloc_section_patterns() {
    // PE .reloc section patterns - single letter repeated with non-ASCII/special chars
    // These patterns have a dominant lowercase letter with non-ASCII mixed in
    assert!(
        is_garbage("x xçx&xìxÇxqxµxyx^x½x{xHx\\xYx0x8x"),
        "reloc x-pattern 1"
    );
    assert!(
        is_garbage("xhx°xqxµxyx^x½x{xHx}xQx\\xYx0x8x"),
        "reloc x-pattern 2"
    );
    assert!(is_garbage("yhyµyHy}yQy\\yYy0y8y"), "reloc y-pattern");
    assert!(is_garbage("w wçw&wÇwØwhw°wqwµwyw^wHw"), "reloc w-pattern");
    assert!(is_garbage("sµsys^sHsYs0s8s"), "reloc s-pattern");
    // All-ASCII reloc patterns
    assert!(is_garbage("uHu}uQu\\uYu0u"), "reloc u-pattern (all ASCII)");
    assert!(is_garbage("w{wQw\\wYw0w8w"), "reloc w-pattern (all ASCII)");
    assert!(is_garbage("t{t\\tYt0t8t"), "reloc t-pattern (all ASCII)");
}

#[test]
fn test_short_digit_nonascii_garbage() {
    // Short strings starting with digit followed by non-ASCII
    // These are random bytes decoded as UTF-8
    assert!(is_garbage("7üĐō"), "7üĐō");
    assert!(is_garbage("4ÛŷƮ"), "4ÛŷƮ");
    assert!(is_garbage("6Æťƒ"), "6Æťƒ");
    assert!(is_garbage("2µßĎ"), "2µßĎ");
}

// ─── x86-64 register save/restore fragments ──────────────────────
//
// These are bytes leaked from `.text` of any non-trivial binary —
// function prologues / epilogues that save callee-saved regs
// r12-r15 emit byte sequences which decode as printable ASCII
// dominated by `A` (REX.B prefix 0x41) and push/pop opcode bytes
// (0x50-0x5F).  The diff of `liblzma 5.4.5 → 5.6.0` surfaced ~18
// such fragments per file before this filter landed.

#[test]
fn test_is_garbage_x86_multi_pair_save_sequences() {
    // Multi-pair (≥2 `A`+pushpop) fragments — the smoking gun.
    // Each is a real string extracted from a `.text` section.
    let cases = [
        // r14 r13 r12 + push rbx + REX.W
        "AVAUATSH",
        // r15 r14 r13 r12 + push rbx + REX.W (full callee-saved set)
        "AWAVAUATSH",
        // r15 r14 r13 r12 + REX.W (truncated at boundary)
        "AWAVAUATL",
        // r14 r13 r12 + REX.WRX + XOR
        "AVAUATE1",
        // r13 r12 + REX.W
        "AUATH",
        // r14 r13 r12 + push rbp + push rbx
        "AVAUATUS",
        // r13 r12 + REX.WRX + XOR
        "AUATE1",
        // pop r8 + pop r9
        "AXAY",
        // r12 + push rbp + push rbx + push r8 + REX.W
        "ATUSAPH",
    ];
    for s in cases {
        assert!(
            is_garbage(s),
            "expected '{s}' to be filtered as asm fragment"
        );
    }
}

#[test]
fn test_is_garbage_x86_single_pair_with_digit() {
    // Length-4 fragments with one REX-pair + a digit — the
    // medium-confidence branch.  These leak from short
    // instruction-boundary alignments.
    assert!(is_garbage("AWE1"), "push r15 + REX.WRX + XOR");
    assert!(is_garbage("7ARI"), "XOR opcode + REX.B + push rdx + REX.WX");
}

#[test]
fn test_x86_filter_does_not_match_magic_numbers() {
    // Comprehensive negative coverage at the filter level. These
    // are the magic numbers / format signatures that we MUST not
    // misclassify as asm fragments — none have ≥2 REX-pairs, and
    // none meet the length-4-with-digit single-pair branch.
    // Some are also filtered by *other* stng rules at the
    // `is_garbage` integration level (e.g. consonant-only
    // patterns) — that's a separate decision and not this
    // filter's concern.
    let magics = [
        "BSJB", "RIFF", "RSDS", "8BIM", "MSCF", "IHDR", "IDAT", "IEND", "COFF", "EXIF", "DICM",
        "CAFE", "BEEF", "DEAD", "FEED", "BABE",
    ];
    for s in magics {
        let stats = CharStats::from_str(s);
        assert!(
            !is_x86_save_sequence_fragment(
                s,
                s.len(),
                &stats,
                &crate::types::StringContext::empty()
            ),
            "magic '{s}' wrongly matched as asm fragment"
        );
    }
}

#[test]
fn test_x86_filter_does_not_match_identifiers() {
    // English words / arch identifiers / protocol tokens that
    // happen to start with `A` followed by a push/pop letter or
    // contain a single REX-pair — must not be caught by the asm
    // filter.  Tested at the filter level; some may still be
    // flagged by other is_garbage rules unrelated to asm bytes.
    let ids = [
        // Architectures with version digit (length 5+)
        "ARM64", "ARM32", "AMD64", "X8664",
        // English words with one REX-pair (single A+pushpop) — safe
        "ATOMIC", "ATTACK", "ASTRA", "ASCII", "AUSTIN", "AVOID", "AWAKE", "APPLE",
        // Encodings / formats
        "UTF8", "UTF16", "UTF32", // Protocol versions
        "TLS12", "TLS13", "HTTP1", "HTTP2", "HTTP3",
    ];
    for s in ids {
        let stats = CharStats::from_str(s);
        assert!(
            !is_x86_save_sequence_fragment(
                s,
                s.len(),
                &stats,
                &crate::types::StringContext::empty()
            ),
            "identifier '{s}' wrongly matched as asm fragment"
        );
    }
}

#[test]
fn test_x86_filter_known_false_positives() {
    // Documented false positives: rare English words / proper
    // nouns that happen to decode as multiple REX-pairs.  These
    // are accepted as the cost of a byte-level heuristic — see
    // the docstring of `is_x86_save_sequence_fragment`.
    //
    // Pinning them in a test means future tightening of the rule
    // (e.g. requiring 3+ pairs or extra structure) is a deliberate
    // change rather than an accidental shift.
    for s in ["ATLAS", "AVATAR"] {
        let stats = CharStats::from_str(s);
        assert!(
            is_x86_save_sequence_fragment(
                s,
                s.len(),
                &stats,
                &crate::types::StringContext::empty()
            ),
            "expected known FP '{s}' to match (docstring contract)"
        );
    }
}

#[test]
fn test_is_garbage_x86_filter_skips_lowercase_and_whitespace() {
    // The filter intentionally only fires on pure
    // uppercase+digit strings — lowercase or whitespace presence
    // means the bytes weren't a clean REX/push-opcode run.
    // (These cases are caught by other filters or are real text.)
    let stats = CharStats::from_str("teAVAUA");
    assert!(
        !is_x86_save_sequence_fragment(
            "teAVAUA",
            "teAVAUA".len(),
            &stats,
            &crate::types::StringContext::empty()
        ),
        "lowercase prefix must skip the asm filter"
    );

    let stats = CharStats::from_str("S I9");
    assert!(
        !is_x86_save_sequence_fragment(
            "S I9",
            "S I9".len(),
            &stats,
            &crate::types::StringContext::empty()
        ),
        "whitespace must skip the asm filter"
    );
}

#[test]
fn test_is_garbage_x86_filter_skips_short_and_long() {
    // Length boundaries: <4 too short to be confidently an asm
    // fragment (would catch real 2-3 char identifiers); >12 is
    // too long (real strings dominate that length range).
    let stats = CharStats::from_str("AT");
    assert!(
        !is_x86_save_sequence_fragment("AT", 2, &stats, &crate::types::StringContext::empty()),
        "len <4 must skip the asm filter"
    );

    // 13 chars, plenty of REX-pairs, but length-gated out.
    let s = "AVAUATAVAUATA";
    let stats = CharStats::from_str(s);
    assert!(
        !is_x86_save_sequence_fragment(s, s.len(), &stats, &crate::types::StringContext::empty()),
        "len >12 must skip the asm filter"
    );
}

#[test]
fn test_x86_filter_unit_multi_pair() {
    // Direct unit test of the filter function (not via is_garbage),
    // so the rule's behavior is pinned even if upstream changes.
    for s in ["AVAUATSH", "AWAVAUATSH", "AVAUATUS", "AXAY", "AUATE1"] {
        let stats = CharStats::from_str(s);
        assert!(
            is_x86_save_sequence_fragment(
                s,
                s.len(),
                &stats,
                &crate::types::StringContext::empty()
            ),
            "expected '{s}' to match the asm filter"
        );
    }
}

#[test]
fn test_x86_filter_unit_single_pair_digit() {
    for s in ["AWE1", "7ARI"] {
        let stats = CharStats::from_str(s);
        assert!(
            is_x86_save_sequence_fragment(
                s,
                s.len(),
                &stats,
                &crate::types::StringContext::empty()
            ),
            "expected '{s}' (single REX-pair + digit) to match"
        );
    }

    // `ARM64` looks similar but length 5 — must not match the
    // length-4 single-pair branch.
    let stats = CharStats::from_str("ARM64");
    assert!(
        !is_x86_save_sequence_fragment("ARM64", 5, &stats, &crate::types::StringContext::empty()),
        "ARM64 (len 5) must not match single-pair branch"
    );
}

#[test]
fn test_x86_filter_unit_no_pairs_passes() {
    // Strings with zero REX-pairs are out of scope; other filters
    // handle their classification.
    for s in ["BSJB", "RIFF", "RSDS", "8BIM", "MSCF", "IHDR"] {
        let stats = CharStats::from_str(s);
        assert!(
            !is_x86_save_sequence_fragment(
                s,
                s.len(),
                &stats,
                &crate::types::StringContext::empty()
            ),
            "magic '{s}' (0 REX-pairs) wrongly matched"
        );
    }
}

#[test]
fn test_x86_filter_unit_idat_ends_with_pair_but_not_start() {
    // `IDAT` is a PNG chunk type that happens to end with `AT` (a
    // REX-pair).  The filter must not catch it — the rule requires
    // ≥2 pairs for high confidence; one trailing pair isn't enough.
    let stats = CharStats::from_str("IDAT");
    assert!(
        !is_x86_save_sequence_fragment("IDAT", 4, &stats, &crate::types::StringContext::empty()),
        "IDAT has 1 trailing REX-pair but no digit — must not match"
    );
}

// ─── architecture scoping ────────────────────────────────────────

#[test]
fn test_x86_filter_skipped_for_non_x86_arch() {
    // ARM / Aarch64 / MIPS / PowerPC don't use REX prefix bytes —
    // a string that LOOKS like an asm fragment in those binaries
    // must not be filtered (it's almost certainly real text).
    use crate::types::{Arch, StringContext};

    let s = "AVAUATSH";
    let stats = CharStats::from_str(s);

    for arch in [
        Arch::Aarch64,
        Arch::Arm,
        Arch::Mips,
        Arch::PowerPc,
        Arch::RiscV64,
    ] {
        let ctx = StringContext {
            arch: Some(arch),
            ..StringContext::default()
        };
        assert!(
            !is_x86_save_sequence_fragment(s, s.len(), &stats, &ctx),
            "filter must skip when arch is {arch:?} (non-x86)"
        );
    }
}

#[test]
fn test_x86_filter_runs_for_x86_arch() {
    use crate::types::{Arch, StringContext};

    let s = "AVAUATSH";
    let stats = CharStats::from_str(s);

    for arch in [Arch::X86, Arch::X86_64] {
        let ctx = StringContext {
            arch: Some(arch),
            ..StringContext::default()
        };
        assert!(
            is_x86_save_sequence_fragment(s, s.len(), &stats, &ctx),
            "filter must run when arch is {arch:?} (x86 family)"
        );
    }
}

// ─── section scoping ─────────────────────────────────────────────

#[test]
fn test_x86_filter_skipped_for_non_code_section() {
    // Asm fragments only leak from `.text`-like sections. A
    // string from `.rodata` / `.data` / `.symtab` that happens to
    // match the byte pattern is real text and must be preserved.
    use crate::types::StringContext;

    let s = "AVAUATSH";
    let stats = CharStats::from_str(s);

    let ctx = StringContext {
        in_code_section: Some(false),
        ..StringContext::default()
    };
    assert!(
        !is_x86_save_sequence_fragment(s, s.len(), &stats, &ctx),
        "filter must skip in a non-code section"
    );
}

#[test]
fn test_x86_filter_runs_for_code_section() {
    use crate::types::StringContext;

    let s = "AVAUATSH";
    let stats = CharStats::from_str(s);

    let ctx = StringContext {
        in_code_section: Some(true),
        ..StringContext::default()
    };
    assert!(
        is_x86_save_sequence_fragment(s, s.len(), &stats, &ctx),
        "filter must run in a code section"
    );
}

#[test]
fn test_x86_filter_runs_for_unknown_context() {
    // Empty context (no arch, no section, no kind) — the legacy
    // behavior — keeps the filter active. Callers that haven't
    // wired context yet still see the diff cleanup.
    use crate::types::StringContext;

    let s = "AVAUATSH";
    let stats = CharStats::from_str(s);
    assert!(
        is_x86_save_sequence_fragment(s, s.len(), &stats, &StringContext::empty()),
        "empty context must keep the filter active (legacy behavior)"
    );
}

#[test]
fn test_x86_filter_skipped_when_arch_or_section_excludes() {
    // Either signal alone is enough to skip — the rule needs
    // BOTH conditions (x86-or-unknown arch, code-or-unknown
    // section) to fire. Confirms the AND-of-OR semantics.
    use crate::types::{Arch, StringContext};

    let s = "AVAUATSH";
    let stats = CharStats::from_str(s);

    // x86 arch + non-code section → skip
    let ctx = StringContext {
        arch: Some(Arch::X86_64),
        in_code_section: Some(false),
        ..StringContext::default()
    };
    assert!(
        !is_x86_save_sequence_fragment(s, s.len(), &stats, &ctx),
        "non-code section must override x86 arch"
    );

    // Non-x86 arch + code section → skip
    let ctx = StringContext {
        arch: Some(Arch::Aarch64),
        in_code_section: Some(true),
        ..StringContext::default()
    };
    assert!(
        !is_x86_save_sequence_fragment(s, s.len(), &stats, &ctx),
        "non-x86 arch must override code section"
    );
}
