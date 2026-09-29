#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
fn pair(load: bool, pre: bool, a: u32, b: u32) -> u32 {
    // STP [SP,#-16]! / LDP [SP],#16.
    (if load { 0xa8c00000 } else { 0xa9800000 })
        | ((if pre { 126 } else { 2 }) << 15)
        | (b << 10)
        | (31 << 5)
        | a
}
fn run(words: &[u32]) -> Option<u32> {
    let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    clobbers(&bytes, 0x1000, 0x1000)
}
#[test]
fn saved_values_restore_and_clobbers_remain_visible() {
    for r in 0..30 {
        assert_eq!(
            run(&[
                pair(false, true, r, 30),
                0xaa1f03e0 | r,
                pair(true, false, r, 30),
                0xd65f03c0
            ]),
            Some(0)
        );
    }
    assert_eq!(
        run(&[
            pair(false, true, 21, 30),
            0xaa0003f5,
            0xaa0003f6,
            pair(true, false, 21, 30),
            0xd65f03c0
        ]),
        Some(1 << 22)
    );
    assert_eq!(run(&[0xaa0003fe, 0xd65f03c0]), None); // bad return token
    assert_eq!(run(&[0xd10043ff, 0xd65f03c0]), None); // unbalanced SP
}
#[test]
fn partial_and_vector_stores_invalidate_saved_tokens() {
    for store in [0x390003ff, 0x790003ff, 0xb90003ff, 0xf90003ff, 0x3d8003e0] {
        assert_eq!(
            run(&[
                pair(false, true, 21, 30),
                store,
                pair(true, false, 21, 30),
                0xd65f03c0
            ]),
            if store == 0x3d8003e0 {
                None
            } else {
                Some(1 << 21)
            }
        );
    }
    let mut state = State::new();
    state
        .store(Value::Stack(-16), 8, Value::Initial(21))
        .unwrap();
    assert_eq!(state.load(Value::Stack(-16), 8), Some(Value::Initial(21)));
    state
        .store(Value::Stack(-13), 1, Value::Constant(0))
        .unwrap();
    assert_eq!(state.load(Value::Stack(-16), 8), Some(Value::Unknown));
    assert_eq!(state.load(Value::Stack(-13), 1), Some(Value::Constant(0)));
    assert_eq!(state.load(Value::Stack(-13), 2), Some(Value::Unknown));
}
#[test]
fn both_paths_must_restore_stack_and_return_address() {
    let prefix = pair(false, true, 21, 30);
    let restore = pair(true, false, 21, 30);
    assert_eq!(
        run(&[
            prefix, 0x54000060, 0xaa0003f5, 0x14000002, 0xaa0103f5, restore, 0xd65f03c0
        ]),
        Some(0)
    );
    for bad in [u32::MAX, 0x94000000, 0xd63f0000, 0xd61f0000, 0xd65f03c0] {
        assert_eq!(
            run(&[
                prefix, 0x54000060, bad, 0x14000002, 0xaa0103f5, restore, 0xd65f03c0
            ]),
            None
        );
    }
    assert_eq!(run(&[0x14000000]), None);
}
#[test]
fn memory_encodings_widths_aliases_and_unmapped_stores() {
    let mut s = State::new();
    s.step(0xd10083ff).unwrap(); // SUB SP,SP,#32
    s.step(0x910043e8).unwrap(); // ADD X8,SP,#16
    s.step(0xf9000115).unwrap(); // STR X21,[X8]
    s.step(0xaa0003f5).unwrap();
    s.step(0xf9400115).unwrap();
    assert_eq!(s.registers[21], Value::Initial(21));
    s.step(0x910083ff).unwrap();
    assert_eq!(s.returned_clobbers(), Some(1 << 8));
    for invalid in [
        0xf9000015,             // Unknown X0 destination may alias any saved slot.
        0xf8206800,             // Register-offset form unsupported by this model.
        0xf8000800,             // Unprivileged store.
        0x3dc00400 | (1 << 30), // Reserved Q load size.
    ] {
        assert!(State::new().step(invalid).is_none(), "{invalid:08x}");
    }
    // Constrained-unpredictable writeback overlap, duplicate pair destinations.
    assert!(State::new().step(0xf8408400).is_none());
    assert!(State::new().step(0xa94003e0).is_none());
    let mut s = State::new();
    s.store(Value::Stack(0), 4, Value::Initial(21)).unwrap();
    s.step(0xb94003f5).unwrap();
    assert_eq!(s.registers[21], Value::Unknown); // W load cannot restore a full X token.
}
#[test]
fn exact_bounds_and_cache_independent_work_limits() {
    let mut s = State::new();
    for i in 0..MAX_SLOTS {
        s.store(Value::Stack(i as i32 * 8), 8, Value::Initial(0))
            .unwrap();
    }
    assert!(s.store(Value::Stack(512), 8, Value::Initial(0)).is_none());
    assert!(s.store(Value::Stack(0), 8, Value::Initial(1)).is_some());
    assert!(s.store(Value::Stack(-1024), 8, Value::Unknown).is_some());
    assert!(s.store(Value::Stack(-1025), 8, Value::Unknown).is_none());
    assert!(s.store(Value::Stack(1023), 2, Value::Unknown).is_none());
    for n in [128, 129] {
        let mut words = vec![0xd503201f; n - 1];
        words.push(0xd65f03c0);
        assert_eq!(run(&words).is_some(), n == 128);
    }
    for n in [8, 9] {
        let mut words = vec![0x14000001; n];
        words.push(0xd65f03c0);
        assert_eq!(run(&words).is_some(), n == 8);
    }
    let ret = 0xd65f03c0u32.to_le_bytes();
    for len in 0..4 {
        assert!(clobbers(&ret[..len], 0x1000, 0x1000).is_none());
    }
    for at in [0, 0xffc, 0x1001, 0x1004, u64::MAX] {
        assert!(clobbers(&ret, 0x1000, at).is_none());
    }
    assert!(clobbers(&ret, u64::MAX - 3, u64::MAX - 3).is_some());
    assert!(clobbers(&vec![0; 8 * 1024 * 1024 + 1], 0, 0).is_none());
}
#[test]
fn original_conversion_and_append_frame_pairs() {
    use goblin::{Object, mach::Mach};
    let file = include_bytes!("../../testdata/macho/rust_heap_xor_installer_universal.macho");
    let Object::Mach(Mach::Fat(fat)) = Object::parse(file).unwrap() else {
        panic!("fat")
    };
    let arch = fat
        .iter_arches()
        .map(Result::unwrap)
        .find(|a| a.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64)
        .unwrap();
    let bytes = &file[arch.offset as usize..(arch.offset + arch.size) as usize];
    let word = |pc: u64| {
        u32::from_le_bytes(
            bytes[(pc - 0x100000000) as usize..(pc - 0x100000000) as usize + 4]
                .try_into()
                .unwrap(),
        )
    };
    // Only the original save/restore sequences are modeled here, not the bodies.
    for (prologue, epilogue, restore_lr, count) in [
        (0x100012fb0, 0x1001a71b4, 0x100012fe0, 4),
        (0x10000a534, 0x1001a7e34, 0x10000a56c, 3),
    ] {
        let mut s = State::new();
        for i in 0..count {
            s.step(word(prologue + i * 4)).unwrap();
        }
        for r in 19..=24 {
            s.registers[r] = Value::Unknown;
        }
        // The append frame saves only X19..X22.
        if count == 3 {
            s.registers[23] = Value::Initial(23);
            s.registers[24] = Value::Initial(24);
        }
        s.registers[29] = Value::Unknown;
        s.registers[30] = Value::Unknown;
        let restores: Vec<_> = std::iter::once(restore_lr)
            .chain((0..count - 1).map(|i| epilogue + i * 4))
            .collect();
        for skip in 0..=restores.len() {
            let mut state = s.clone();
            for (i, &pc) in restores.iter().enumerate() {
                if i != skip {
                    state.step(word(pc)).unwrap();
                }
            }
            assert_eq!(state.returned_clobbers() == Some(0), skip == restores.len());
        }
    }
}

#[test]
fn nested_calls_share_saved_slots_and_check_each_return() {
    let save = pair(false, true, 21, 30);
    let restore = pair(true, false, 21, 30);
    // Root saves X21/LR, then child changes X21. The caller restores both.
    let mut words = vec![
        save, 0x94000003, restore, 0xd65f03c0, 0xaa0003f5, 0xd65f03c0,
    ];
    assert_eq!(run(&words), Some(0));
    words[4] = 0x390003ff; // child corrupts caller's saved X21
    assert_eq!(run(&words), Some(1 << 21));
    words[4] = 0x390023ff; // child corrupts caller's saved LR
    assert_eq!(run(&words), None);
    words[4] = 0xaa0003fe; // child fails to return to the recorded address
    assert_eq!(run(&words), None);
    words[4] = 0xd10043ff; // child changes the call-entry SP
    assert_eq!(run(&words), None);
    words[4] = 0x94000000; // recursive calls hit the depth budget
    assert_eq!(run(&words), None);
    words[4] = 0x94001000; // unmapped callee
    assert_eq!(run(&words), None);
}
#[test]
fn nested_branch_paths_and_exact_depth_limit() {
    for depth in [4, 5] {
        let mut words = Vec::new();
        // Each frame saves LR, calls the next four-word frame and restores it.
        for _ in 0..depth {
            words.extend([
                pair(false, true, 21, 30),
                0x94000003,
                pair(true, false, 21, 30),
                0xd65f03c0,
            ]);
        }
        words.push(0xd65f03c0);
        assert_eq!(run(&words).is_some(), depth == 4);
    }
    let words = [
        pair(false, true, 21, 30),
        0x94000003,
        pair(true, false, 21, 30),
        0xd65f03c0,
        0x54000040,
        0xd65f03c0,
        0x390023ff,
        0xd65f03c0,
    ];
    assert_eq!(run(&words), None); // alternate callee path corrupts caller LR
}
