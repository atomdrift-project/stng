#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
//! Independent native-analysis offsets and digests, through the filtered public
//! pipeline, with external disassembly and caching disabled.
mod common;

use sha2::{Digest, Sha256};
use stng::{ExtractOptions, StringMethod, extract_strings_with_options};

#[test]
fn both_native_go_architectures_keep_exact_tags_and_multiline_plist() {
    let opts = ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    for (name, sha, iv, ciphertext, plist) in [
        (
            "go_reflection_tags_minirat.macho",
            "0b028b781950641818800fee2b4bf68e4ef2bcee53fe71a21755275ba108783d",
            0x33aaeb,
            0x34551b,
            0x2cc5d4,
        ),
        (
            "go_reflection_tags_minirat_arm64.macho",
            "0a8ab3d16b12d3a453ee5a3208fe04744ad54514ef8ea27bb8fe32679efad270",
            0x2dfab7,
            0x2ea4ac,
            0x2717e3,
        ),
    ] {
        let data = crate::common::bytes(&format!("testdata/macho/{name}"));
        assert_eq!(hex::encode(Sha256::digest(&data)), sha);
        let strings = extract_strings_with_options(&data, &opts);
        for (value, offset) in [("json:\"iv\"", iv), ("json:\"ciphertext\"", ciphertext)] {
            let found: Vec<_> = strings
                .iter()
                .filter(|s| s.value == value && s.data_offset == offset)
                .collect();
            assert!(!found.is_empty(), "{name}: missing {value}");
            assert!(
                found
                    .iter()
                    .any(|s| s.method == StringMethod::Structure
                        && s.data_len as usize == value.len())
            );
            assert_eq!(
                &data[offset as usize..offset as usize + value.len()],
                value.as_bytes()
            );
        }
        let found: Vec<_> = strings
            .iter()
            .filter(|s| {
                s.data_offset == plist
                    && s.value.len() == 415
                    && s.method == StringMethod::InstructionPattern
            })
            .collect();
        assert_eq!(
            found.len(),
            1,
            "{name}: complete instruction-referenced XML"
        );
        let s = found[0];
        assert_eq!(s.source_spans().collect::<Vec<_>>(), vec![(plist, 415)]);
        assert_eq!(
            hex::encode(Sha256::digest(s.value.as_bytes())),
            "1205faad2dd8e307d0b7f91aa3f996115f21e09435e941ab692ba568e73f8c90"
        );
        assert_eq!(
            &data[plist as usize..plist as usize + 415],
            s.value.as_bytes()
        );
    }
}
