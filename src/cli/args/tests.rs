use super::*;

#[test]
fn xor_keys_are_hex_only_with_a_prefix() {
    assert_eq!(parse_xor_key("0xAB01").unwrap().0, [0xab, 0x01]);
    assert_eq!(parse_xor_key("hex:beef").unwrap().0, [0xbe, 0xef]);
    assert_eq!(parse_xor_key("beef").unwrap().0, b"beef");
    assert!(parse_xor_key("0xZZ").is_err());
    assert!(parse_xor_key("0xabc").is_err());
    assert!(parse_xor_key("0x").is_err());
    assert!(parse_xor_key("").is_err());
    assert!(parse_xor_key("0xé1").is_err());
}

#[test]
fn lcg_parameters_parse_and_bound() {
    let LcgRange(lcg, range) = parse_lcg("0x10001, 0x3785, 0xffff, 7, 0x40, 16").unwrap();
    assert_eq!(
        (lcg.seed, lcg.multiplier, lcg.modulus, lcg.mask),
        (0x10001, 0x3785, 0xffff, 7)
    );
    assert_eq!(range, 0x40..0x50);
    assert!(parse_lcg("1,2,3,4,5").is_err());
    assert!(parse_lcg("1,0,3,4,5,6").is_err());
    assert!(parse_lcg("1,2,3,256,5,6").is_err());
    assert!(parse_lcg(&format!("1,2,3,4,{},2", usize::MAX)).is_err());
}
