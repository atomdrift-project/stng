use super::decode_call_push_length;
#[test]
fn positive_lengths_and_extended_registers_with_optional_stack_output() {
    for n in 1..=127 {
        assert_eq!(
            decode_call_push_length(&[0x6a, n, 0x59], 0, 3, 2),
            Some((1, u64::from(n)))
        );
        assert_eq!(
            decode_call_push_length(&[0x6a, n, 0x41, 0x59], 0, 4, 2),
            Some((9, u64::from(n)))
        );
        let b = [0x48, 0x8d, 0x7d, 0x80, 0x6a, n, 0x59];
        assert_eq!(
            decode_call_push_length(&b, 0, b.len(), 2),
            Some((1, u64::from(n)))
        );
    }
}
#[test]
fn invalid_lengths_clobbers_gaps_and_truncation_are_rejected() {
    for n in [0, 128, 255] {
        assert!(decode_call_push_length(&[0x6a, n, 0x59], 0, 3, 2).is_none());
    }
    for b in [
        vec![0x6a, 62, 0x5a],
        vec![0x6a, 62, 0x5c],
        vec![0x6a, 62, 0x59, 0x90],
        vec![0x48, 0x8d, 0x55, 0x80, 0x6a, 62, 0x59],
        vec![0x48, 0x8d, 0x4d, 0x80, 0x6a, 62, 0x59],
        vec![0x48, 0x8d, 0x3b, 0x6a, 62, 0x59],
    ] {
        assert!(decode_call_push_length(&b, 0, b.len(), 2).is_none());
    }
    let good = [0x48, 0x8d, 0x7d, 0x80, 0x6a, 62, 0x59];
    for end in 0..good.len() {
        assert!(decode_call_push_length(&good[..end], 0, end, 2).is_none());
    }
    assert!(decode_call_push_length(&good, usize::MAX, good.len(), 2).is_none());
    assert!(decode_call_push_length(&good, 0, usize::MAX, 2).is_none());
}
