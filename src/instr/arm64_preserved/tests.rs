#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use goblin::{Object, mach::Mach};
static FILE: std::sync::LazyLock<&[u8]> = std::sync::LazyLock::new(|| {
    crate::test_fixture("testdata/macho/rust_heap_xor_installer_universal.macho")
});
fn sample() -> (&'static [u8], u64, u64, &'static [u8], u64) {
    let Object::Mach(Mach::Fat(fat)) = Object::parse(*FILE).unwrap() else {
        panic!("fat")
    };
    let a = fat
        .iter_arches()
        .map(Result::unwrap)
        .find(|a| a.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64)
        .unwrap();
    let b = &FILE[a.offset as usize..(a.offset + a.size) as usize];
    let Object::Mach(Mach::Binary(m)) = Object::parse(b).unwrap() else {
        panic!("arm")
    };
    let sections: Vec<_> = m
        .segments
        .iter()
        .flat_map(|s| s.sections().unwrap())
        .collect();
    let (text, tb) = sections
        .iter()
        .find(|(s, _)| s.name().ok() == Some("__text"))
        .unwrap();
    let (data, db) = sections
        .iter()
        .find(|(s, _)| {
            s.name().ok() == Some("__const")
                && s.addr < 0x1002aadfb
                && s.addr + s.size > 0x1002aadfb
        })
        .unwrap();
    (*tb, text.addr, data.addr, *db, a.offset.into())
}
#[test]
fn original_salt_and_full_pipeline_thin_fat_spans() {
    let (code, base, data_addr, data, slice) = sample();
    let call = (0x100015cb0 - base) as usize;
    assert_eq!(
        Context::new(code, base).recover(call, data, data_addr, 4),
        Some(("saltysalt".into(), 0x1002aadfb))
    );
    let Object::Mach(Mach::Fat(fat)) = Object::parse(*FILE).unwrap() else {
        panic!("fat")
    };
    let a = fat
        .iter_arches()
        .map(Result::unwrap)
        .find(|a| u64::from(a.offset) == slice)
        .unwrap();
    let bytes = &FILE[a.offset as usize..(a.offset + a.size) as usize];
    let Object::Mach(Mach::Binary(m)) = Object::parse(bytes).unwrap() else {
        panic!("arm")
    };
    for outer in [0, slice] {
        let out = crate::rust::RustStringExtractor::new(4).extract_macho(&m, outer);
        let s = out
            .iter()
            .find(|s| s.value == "saltysalt" && s.method == crate::StringMethod::InstructionPattern)
            .unwrap();
        assert_eq!(
            s.source_spans().collect::<Vec<_>>(),
            [(outer + 0x2aadfb, 9)]
        );
    }
    let opts = crate::ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    assert!(
        crate::extract_strings_with_options(bytes, &opts)
            .iter()
            .any(|s| s.value == "saltysalt" && s.data_offset == 0x2aadfb)
    );
}
#[test]
fn original_interval_and_called_helpers_reject_unknown_instructions() {
    let (code, base, data_addr, data, _) = sample();
    let mut bytes = code.to_vec();
    let call = (0x100015cb0 - base) as usize;
    let ranges = [
        (0x100015c6c, 0x100015cb4),
        (0x1001bab9c, 0x1001baba8),
        (0x100012f14, 0x100012fb0),
        (0x1001ae5dc, 0x1001ae5e8),
        (0x1001b6cf8, 0x1001b6d04),
        (0x1001abdc0, 0x1001abdc8),
    ];
    for (start, end) in ranges {
        for pc in (start..end).step_by(4) {
            let at = (pc - base) as usize;
            bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(
                Context::new(&bytes, base)
                    .recover(call, data, data_addr, 4)
                    .is_none(),
                "{pc:x}"
            );
            bytes[at..at + 4].copy_from_slice(&code[at..at + 4]);
        }
    }
}
fn synthetic() -> Vec<u32> {
    let mut words = vec![0xd65f03c0; 160];
    words[..5].copy_from_slice(&[0xb0000015, 0x910002b5, 0xaa1503e1, 0x528000a2, 0x94000000]);
    words
}
fn recover(words: &[u32], call: usize) -> Option<(String, u64)> {
    let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    Context::new(&bytes, 0x1000).recover(call, b"helloworld", 0x2000, 4)
}
#[test]
fn register_arguments_clobbers_and_calls_are_checked() {
    let words = synthetic();
    assert_eq!(recover(&words, 16), Some(("hello".into(), 0x2000)));
    for (at, w) in [
        (1, 0x914002b5),
        (2, 0x2a1503e1),
        (3, 0x528000a1),
        (3, 0x52c000a2),
        (4, 0xd65f03c0),
    ] {
        let mut b = words.clone();
        b[at] = w;
        assert!(recover(&b, 16).is_none());
    }
    let mut b = words.clone();
    b.copy_within(2..5, 3);
    b[2] = 0x94000020;
    assert!(recover(&b, 20).is_some()); // mapped RET helper
    b[34] = 0xaa0003f5; // helper writes X21 then returns
    assert!(recover(&b, 20).is_none());
    b[34] = 0xd61f0000; // unknown indirect branch
    assert!(recover(&b, 20).is_none());
}
#[test]
fn cache_attempt_work_and_recursion_limits() {
    let words = synthetic();
    let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut ctx = Context::new(&bytes, 0x1000);
    for _ in 0..MAX_CANDIDATES {
        assert!(ctx.recover(16, b"helloworld", 0x2000, 4).is_some());
    }
    assert!(ctx.recover(16, b"helloworld", 0x2000, 4).is_none());
    for i in 0..MAX_HELPERS {
        assert!(ctx.helper((i + 8) * 4).is_some());
    }
    assert!(ctx.helper((MAX_HELPERS + 8) * 4).is_none());
    assert!(ctx.helper(32).is_some()); // cached hit after saturation
    let mut looped = words.clone();
    looped[32] = 0x94000000;
    let b: Vec<_> = looped.iter().flat_map(|w| w.to_le_bytes()).collect();
    assert!(Context::new(&b, 0x1000).helper(128).is_none());
    let mut budget = 0;
    assert!(ctx.summarize(32, 0, &mut budget).is_none());
    let mut budget = 1;
    assert_eq!(ctx.summarize(32, 0, &mut budget), Some(0));
}
#[test]
fn bounds_and_missing_or_malformed_literal_reject() {
    let words = synthetic();
    let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    for len in 0..20 {
        assert!(
            Context::new(&bytes[..len], 0x1000)
                .recover(16, b"hello", 0x2000, 4)
                .is_none()
        );
    }
    for call in [0, 1, 4, 8, 15, 17, usize::MAX] {
        assert!(
            Context::new(&bytes, 0x1000)
                .recover(call, b"hello", 0x2000, 4)
                .is_none()
        );
    }
    assert!(
        Context::new(&bytes, u64::MAX - 3)
            .recover(16, b"hello", 0x2000, 4)
            .is_none()
    );
    assert!(
        Context::new(&bytes, 0x1000)
            .recover(16, b"hell", 0x2000, 4)
            .is_none()
    );
    assert!(
        Context::new(&bytes, 0x1000)
            .recover(16, b"hello", 0x2000, 6)
            .is_none()
    );
    assert!(
        Context::new(&bytes, 0x1000)
            .recover(16, b"\xffello", 0x2000, 4)
            .is_none()
    );
}

#[test]
fn exact_window_code_and_helper_branch_limits() {
    // The ADD can be exactly WINDOW words before the argument copy.
    let mut words = synthetic();
    let args = words[2..5].to_vec();
    words[2..].fill(0xd503201f);
    words[WINDOW + 1..WINDOW + 4].copy_from_slice(&args);
    assert!(recover(&words, (WINDOW + 3) * 4).is_some());
    words[WINDOW + 1] = 0xd503201f;
    words[WINDOW + 2..WINDOW + 5].copy_from_slice(&args);
    assert!(recover(&words, (WINDOW + 4) * 4).is_none());

    let mut bytes: Vec<_> = synthetic().iter().flat_map(|w| w.to_le_bytes()).collect();
    bytes.resize(MAX_CODE, 0);
    assert!(
        Context::new(&bytes, 0x1000)
            .recover(16, b"hello", 0x2000, 4)
            .is_some()
    );
    bytes.push(0);
    assert!(
        Context::new(&bytes, 0x1000)
            .recover(16, b"hello", 0x2000, 4)
            .is_none()
    );

    // Both conditional successors are checked, including a clobber on the taken path.
    let mut words = vec![0xd65f03c0u32; MAX_WORDS + 2];
    words[0] = 0x54000040; // B.EQ +8
    words[2] = 0xaa0003f5;
    let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    assert_eq!(Context::new(&bytes, 0x1000).helper(0), Some(1 << 21));
    words[2] = u32::MAX;
    let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    assert!(Context::new(&bytes, 0x1000).helper(0).is_none());
    for count in [MAX_BRANCHES, MAX_BRANCHES + 1] {
        words.fill(0xd65f03c0);
        words[..count].fill(0x14000001); // local forward B
        let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(
            Context::new(&bytes, 0x1000).helper(0).is_some(),
            count == MAX_BRANCHES
        );
    }
    for count in [MAX_WORDS, MAX_WORDS + 1] {
        words.fill(0xd65f03c0);
        words[..count - 1].fill(0xd503201f);
        let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(
            Context::new(&bytes, 0x1000).helper(0).is_some(),
            count == MAX_WORDS
        );
    }
}

#[test]
fn framed_leaf_preservation_enables_literal_and_rejects_stack_corruption() {
    let mut words = synthetic();
    words.copy_within(2..5, 3);
    words[2] = 0x94000020; // call helper at word 34
    words[34..38].copy_from_slice(&[
        0xa9bf7bf5, // STP X21,X30,[SP,#-16]!
        0xaa0003f5, // MOV X21,X0
        0xa8c17bf5, // LDP X21,X30,[SP],#16
        0xd65f03c0,
    ]);
    assert_eq!(recover(&words, 20), Some(("hello".into(), 0x2000)));
    words[35] = 0x390003ff; // partial overwrite of saved X21
    assert!(recover(&words, 20).is_none());
    words[35] = 0x3d8003e0; // Q store overwrites both saved registers
    assert!(recover(&words, 20).is_none());
    words[35] = 0x94000000; // recursive call exhausts the checked depth budget
    assert!(recover(&words, 20).is_none());
}

#[test]
fn nested_framed_helper_preserves_literal_only_with_intact_saved_pointer() {
    let mut words = synthetic();
    words.copy_within(2..5, 3);
    words[2] = 0x94000020;
    words[34..40].copy_from_slice(&[
        0xa9bf7bf5, 0x94000003, 0xa8c17bf5, 0xd65f03c0, 0xaa0003f5, 0xd65f03c0,
    ]);
    assert_eq!(recover(&words, 20), Some(("hello".into(), 0x2000)));
    words[38] = 0x390003ff;
    assert!(recover(&words, 20).is_none());
}
