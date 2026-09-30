//! Register-write footprints for the bounded caller-state recognizer.
//! This does not infer register preservation, values, or control-flow reachability.

fn reg(index: u32) -> u32 {
    if index == 31 { 0 } else { 1 << index }
}

/// Bit 31 denotes SP, while XZR/WZR never produces a write bit.
/// Unsupported instruction families fail closed instead of assuming no writes.
#[allow(dead_code)] // Connected with caller-state analysis.
pub(crate) fn writes(inst: u32) -> Option<u32> {
    let rd = inst & 31;
    let rn = (inst >> 5) & 31;
    if matches!(inst, 0xd65f03c0 | 0xd503201f) {
        return Some(0);
    }
    if inst & 0x7c000000 == 0x14000000 {
        return Some(if inst & 0x80000000 != 0 { 1 << 30 } else { 0 });
    }
    if inst & 0xff000010 == 0x54000000 || matches!(inst & 0x7e000000, 0x34000000 | 0x36000000) {
        return Some(0);
    }
    if inst & 0x1f000000 == 0x10000000 {
        return Some(reg(rd));
    } // ADR/ADRP
    if inst & 0x1f800000 == 0x11000000 {
        return Some(if rd == 31 && inst & (1 << 29) == 0 {
            1 << 31
        } else {
            reg(rd)
        });
    }
    if inst & 0x1f800000 == 0x12800000 {
        if (inst >> 29) & 3 == 1 || (inst >> 31 == 0 && inst & (1 << 22) != 0) {
            return None;
        }
        return Some(reg(rd));
    }
    if inst & 0x1f800000 == 0x12000000 {
        // Reserved logical-immediate encodings cannot establish preserved state.
        let n = (inst >> 22) & 1;
        let s = (inst >> 10) & 63;
        if inst >> 31 == 0 && n != 0 {
            return None;
        }
        let discriminator = (n << 6) | ((!s) & 63);
        let len = 31u32.checked_sub(discriminator.leading_zeros())?;
        if len < 1 {
            return None;
        }
        let levels = (1 << len) - 1;
        if s & levels == levels {
            return None;
        }
        return Some(reg(rd));
    }
    if inst & 0x1f800000 == 0x13000000 {
        if (inst >> 29) & 3 == 3 || (inst >> 22) & 1 != inst >> 31 {
            return None;
        }
        if inst >> 31 == 0 && (inst & 0x00208000) != 0 {
            return None;
        }
        return Some(reg(rd));
    }
    if inst & 0x7fa00000 == 0x13800000 {
        if (inst >> 22) & 1 != inst >> 31 || (inst >> 31 == 0 && inst & (1 << 15) != 0) {
            return None;
        }
        return Some(reg(rd));
    }
    if inst & 0x1f200000 == 0x0b000000 {
        if (inst >> 22) & 3 == 3 || (inst >> 31 == 0 && inst & (1 << 15) != 0) {
            return None;
        }
        return Some(reg(rd));
    }
    if inst & 0x1f000000 == 0x0a000000 {
        if inst >> 31 == 0 && inst & (1 << 15) != 0 {
            return None;
        }
        return Some(reg(rd));
    }
    if inst & 0x7fe00000 == 0x1b000000 {
        return Some(reg(rd));
    } // MADD/MSUB, MUL/MNEG aliases
    // CSEL/CSINC/CSINV/CSNEG and their aliases only write the destination.
    if inst & 0x3fe00800 == 0x1a800000 {
        return Some(reg(rd));
    }
    // UMULH writes the high half of a 64x64 product to one GPR. Its
    // fixed Ra/opcode bits distinguish it from MADD and reserved encodings.
    if inst & 0xffe0fc00 == 0x9bc07c00 {
        return Some(reg(rd));
    }
    // Integer and vector loads/stores with unsigned immediate offsets.
    if inst & 0x3b000000 == 0x39000000 {
        let vector = inst & (1 << 26) != 0;
        let opc = (inst >> 22) & 3;
        if !vector && opc > 1 {
            return None;
        }
        return Some(if !vector && opc == 1 { reg(rd) } else { 0 });
    }
    // Unscaled, pre/post-indexed and register-offset loads/stores.
    if inst & 0x3b000000 == 0x38000000 {
        let vector = inst & (1 << 26) != 0;
        let opc = (inst >> 22) & 3;
        if !vector && opc > 1 {
            return None;
        }
        let indexed = inst & (1 << 21) != 0;
        let mode = (inst >> 10) & 3;
        if indexed && mode != 2 {
            return None;
        }
        if indexed && !matches!((inst >> 13) & 7, 2 | 3 | 6 | 7) {
            return None;
        }
        let writeback = !indexed && matches!(mode, 1 | 3);
        return Some(
            (if !vector && opc == 1 { reg(rd) } else { 0 }) | (if writeback { 1 << rn } else { 0 }),
        );
    }
    // Paired loads/stores, including non-temporal and pre/post-indexed forms.
    if inst & 0x3a000000 == 0x28000000 {
        let vector = inst & (1 << 26) != 0;
        let opc = inst >> 30;
        if opc == 3 || (!vector && opc == 1) {
            return None;
        }
        let load = inst & (1 << 22) != 0;
        let mode = (inst >> 23) & 3;
        let loaded = if load && !vector {
            reg(rd) | reg((inst >> 10) & 31)
        } else {
            0
        };
        return Some(loaded | if matches!(mode, 1 | 3) { 1 << rn } else { 0 });
    }
    // Reviewed compiler zero-vector initialization; other SIMD instructions
    // (some of which move data into GPRs) deliberately remain unsupported.
    if inst & !31 == 0x6f00e400 {
        return Some(0);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_independent_disassembly_write_mask_matches() {
        let rows = include_bytes!("../testdata/macho/rust_arm64_register_writes.bin");
        assert_eq!(rows.len(), 13064 * 8);
        for row in rows.as_chunks::<8>().0 {
            let word = u32::from_le_bytes([row[0], row[1], row[2], row[3]]);
            let expected = u32::from_le_bytes([row[4], row[5], row[6], row[7]]);
            assert_eq!(writes(word), Some(expected), "instruction {word:08x}");
        }
    }
    #[test]
    fn stack_zero_register_and_vector_registers_are_distinct() {
        for (word, expected) in [
            (0x910043ff, 1 << 31),                           // ADD SP,SP,#16
            (0xf100043f, 0),                                 // CMP X1,#1 (SUBS XZR)
            (0x8b01001f, 0),                                 // ADD XZR,X0,X1
            (0xf8408408, (1 << 0) | (1 << 8)),               // LDR X8,[X0],#8
            (0xa8c357f6, (1 << 21) | (1 << 22) | (1 << 31)), // LDP X22,X21,[SP],#48
            (0x3dc003ff, 0),                                 // LDR Q31,[SP]
            (0x6f00e41f, 0),                                 // MOVI V31.2D,#0
            (0x94000000, 1 << 30),
            (0x14000000, 0),
        ] {
            assert_eq!(writes(word), Some(expected), "{word:08x}");
        }
    }
    #[test]
    fn unknown_families_and_reserved_encodings_are_not_preservation_evidence() {
        assert_eq!(writes(0xd503201f), Some(0)); // Exact NOP only.
        for word in [
            0,
            u32::MAX,
            0xd4000001,
            0xd61f0000,
            0xd63f0000,
            0x4e083c00,
            0xd503203f, // Other system hints remain unsupported.
            0x32800000,
            0x52c00000,
            0x12400000,
            0x1200fc00,
            0x53400000,
            0x53008000,
            0x13c00000,
            0x13808000,
            0x0bc00000,
            0x0b008000,
            0x0a008000,
            0xb9800000,
            0xf8200000,
            0xf8200800,
            0xe9000000,
        ] {
            assert_eq!(writes(word), None, "{word:08x}");
        }
    }
    #[test]
    fn register_fields_are_not_tied_to_specimen_allocations() {
        for rd in 0..32 {
            for rn in 0..32 {
                let expected = if rd == 31 { 0 } else { 1 << rd };
                // EOR Xd,Xn,X8, ADRP Xd and scalar LDR Xd,[Xn].
                assert_eq!(writes(0xca080000 | (rn << 5) | rd), Some(expected));
                assert_eq!(writes(0x90000000 | rd), Some(expected));
                assert_eq!(writes(0xf9400000 | (rn << 5) | rd), Some(expected));
                // Indexed addressing updates the base as well, including SP.
                assert_eq!(
                    writes(0xf8408400 | (rn << 5) | rd),
                    Some(expected | (1 << rn))
                );
                assert_eq!(writes(0xf8008400 | (rn << 5) | rd), Some(1 << rn));
                // Ordinary stores do not write their value register or base.
                assert_eq!(writes(0xf9000000 | (rn << 5) | rd), Some(0));
            }
        }
    }
    #[test]
    fn addressing_modes_and_pair_loads_report_every_written_register() {
        for rt in 0..32 {
            for rt2 in 0..32 {
                let loaded = reg(rt) | reg(rt2);
                assert_eq!(writes(0xa94003e0 | (rt2 << 10) | rt), Some(loaded));
                assert_eq!(
                    writes(0xa8c103e0 | (rt2 << 10) | rt),
                    Some(loaded | (1 << 31))
                );
                assert_eq!(writes(0xa98103e0 | (rt2 << 10) | rt), Some(1 << 31));
            }
        }
        // LDR with register offset does not write back its base.
        assert_eq!(writes(0xf8686bff), Some(0));
        assert_eq!(writes(0xf8686bf3), Some(1 << 19));
        // SIMD loads/stores only affect GPRs when they update an address base.
        assert_eq!(writes(0x3cc107e0), Some(1 << 31));
        assert_eq!(writes(0xad8107e0), Some(1 << 31));
    }
    #[test]
    fn framed_callee_words_and_unsigned_multiply_high_are_covered() {
        let rows = include_bytes!("../testdata/macho/rust_arm64_framed_register_writes.bin");
        assert!(rows.len() > 100 * 8);
        assert_eq!(rows.len() % 8, 0);
        for row in rows.as_chunks::<8>().0 {
            let word = u32::from_le_bytes([row[0], row[1], row[2], row[3]]);
            let expected = u32::from_le_bytes([row[4], row[5], row[6], row[7]]);
            assert_eq!(writes(word), Some(expected), "{word:08x}");
        }
        for rd in 0..32 {
            for rn in 0..32 {
                for rm in 0..32 {
                    assert_eq!(
                        writes(0x9bc07c00 | (rm << 16) | (rn << 5) | rd),
                        Some(reg(rd))
                    );
                }
            }
        }
        for invalid in [0x1bc17d09, 0x9bc17909, 0x9bc1fd09] {
            assert_eq!(writes(invalid), None, "{invalid:08x}");
        }
    }
    #[test]
    fn conditional_selects_write_only_the_destination() {
        for opcode in [
            0x1a800000u32,
            0x1a800400,
            0x5a800000,
            0x5a800400,
            0x9a800000,
            0xda800400,
        ] {
            for rd in 0..32 {
                for condition in 0..16 {
                    assert_eq!(
                        writes(opcode | (7 << 16) | (condition << 12) | (22 << 5) | rd),
                        Some(reg(rd))
                    );
                }
            }
        }
        assert_eq!(writes(0x3a800000), None); // reserved S bit
        assert_eq!(writes(0x1a800800), None); // reserved op2 bit
        assert_eq!(writes(0xab02003f), Some(0)); // CMN X1,X2 writes flags, not SP
    }
}
