//! Every extraction path stng offers, over arbitrary bytes: none may panic,
//! overflow or hang. The first byte picks the options, so one corpus covers
//! the library default, the CLI's filtered auto-XOR run, a forced XOR scan
//! and an explicit key.
#![no_main]

use libfuzzer_sys::fuzz_target;
use stng::{ExtractOptions, XorMode, extract_iocs, extract_strings_with_options};

fuzz_target!(|data: &[u8]| {
    let Some((&choice, input)) = data.split_first() else {
        return;
    };
    let opts = match choice % 4 {
        0 => ExtractOptions::new(4),
        1 => ExtractOptions::new(4)
            .with_garbage_filter(true)
            .with_xor(XorMode::Auto),
        2 => ExtractOptions::new(6).with_xor(XorMode::Scan),
        _ => ExtractOptions::new(4).with_xor(XorMode::Key(vec![0x5a, 0x13])),
    };
    let strings = extract_strings_with_options(input, &opts);
    let _ = extract_iocs(&strings);
});
