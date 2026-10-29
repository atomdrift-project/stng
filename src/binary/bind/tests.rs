use super::*;

/// A forged repeat count is counted, not replayed: symbol `_a`, then
/// `DO_BIND_ULEB_TIMES_SKIPPING_ULEB` with a count of 2^32 - 1, which
/// goblin's interpreter would turn into that many `Import`s.
#[test]
fn a_forged_bind_repeat_count_passes_the_cap() {
    let stream = [
        0x11, 0x40, b'_', b'a', 0x00, 0x70, 0x00, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00, 0x00,
    ];
    assert!(bind_stream_count(&stream, 0) > MAX_MACHO_BIND_IMPORTS);
}

/// Ordinary binds are counted one by one, across operand-bearing opcodes.
#[test]
fn ordinary_binds_are_counted() {
    let stream = [
        0x11, // SET_DYLIB_ORDINAL_IMM 1
        0x40, b'_', b'a', 0x00, // SET_SYMBOL_TRAILING_FLAGS_IMM "_a"
        0x72, 0x10, // SET_SEGMENT_AND_OFFSET_ULEB seg 2, offset 16
        0x90, // DO_BIND
        0xA0, 0x08, // DO_BIND_ADD_ADDR_ULEB 8
        0xB1, // DO_BIND_ADD_ADDR_IMM_SCALED
        0xC0, 0x03, 0x08, // DO_BIND_ULEB_TIMES_SKIPPING_ULEB 3, skip 8
        0x00, // DONE
    ];
    assert_eq!(bind_stream_count(&stream, 0), 6);
    // A truncated operand ends the walk, as it ends goblin's.
    assert_eq!(bind_stream_count(&stream[..9], 0), 2);
}
