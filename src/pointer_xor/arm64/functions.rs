//! Bounded Mach-O function ranges for shared caller-state analysis.
//! Only ranges containing requested call sites are retained.
use super::Region;
use goblin::mach::{MachO, load_command::CommandVariant};
use std::ops::Range;

const MAX_TABLE: usize = 256 * 1024;
const MAX_FUNCTIONS: usize = 65536;
pub(super) const MAX_CALLER_BYTES: u64 = 64 * 1024;

fn uleb(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let mut value = 0;
    for index in 0..10 {
        let byte = *bytes.get(*cursor)?;
        *cursor = cursor.checked_add(1)?;
        let payload = u64::from(byte & 127);
        if index == 9 && payload > 1 {
            return None;
        }
        value |= payload << (index * 7);
        if byte & 128 == 0 {
            // Reject non-minimal encodings instead of treating zero padding as data.
            if index > 0 && payload == 0 {
                return None;
            }
            return Some(value);
        }
    }
    None
}

fn decode(bytes: &[u8], base: u64, code: &Region<'_>, sites: &[u64]) -> Option<Vec<Range<u64>>> {
    if bytes.len() > MAX_TABLE || sites.len() > super::super::MAX_CANDIDATES {
        return None;
    }
    let end = code.addr.checked_add(code.bytes.len() as u64)?;
    if sites
        .iter()
        .any(|&pc| pc & 3 != 0 || pc < code.addr || pc >= end)
        || sites.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return None;
    }
    let mut cursor = 0;
    let mut current = base;
    let mut previous = None;
    let mut site = 0;
    let mut output = Vec::new();
    let mut terminated = false;
    for _ in 0..=MAX_FUNCTIONS {
        let delta = uleb(bytes, &mut cursor)?;
        if delta == 0 {
            if bytes.get(cursor..)?.iter().any(|b| *b != 0) {
                return None;
            }
            if let Some(start) = previous {
                retain(start, end, sites, &mut site, &mut output)?;
            }
            terminated = true;
            break;
        }
        current = current.checked_add(delta)?;
        if current & 3 != 0 || current < code.addr || current >= end {
            return None;
        }
        if let Some(start) = previous {
            retain(start, current, sites, &mut site, &mut output)?;
        }
        previous = Some(current);
    }
    if !terminated || site != sites.len() {
        return None;
    }
    Some(output)
}
fn retain(
    start: u64,
    end: u64,
    sites: &[u64],
    site: &mut usize,
    out: &mut Vec<Range<u64>>,
) -> Option<()> {
    if let Some(&pc) = sites.get(*site) {
        if pc < start {
            return None;
        }
        if pc < end {
            if end.checked_sub(start)? > MAX_CALLER_BYTES {
                return None;
            }
            out.push(start..end);
            while sites.get(*site).is_some_and(|pc| *pc < end) {
                *site += 1;
            }
        }
    }
    Some(())
}

/// Load command offsets are slice-relative, including for universal files.
/// No function table is read until a caller requests validated setup sites.
#[allow(dead_code)] // Used when caller-state proofs are connected to extraction.
pub(super) fn ranges(
    macho: &MachO<'_>,
    code: &Region<'_>,
    sites: &[u64],
) -> Option<Vec<Range<u64>>> {
    if sites.is_empty() {
        return Some(Vec::new());
    }
    let mut command = None;
    for load in &macho.load_commands {
        if let CommandVariant::FunctionStarts(value) = &load.command {
            if command.replace(value).is_some() {
                return None;
            }
        }
    }
    let command = command?;
    if command.datasize as usize > MAX_TABLE {
        return None;
    }
    let base = macho
        .segments
        .iter()
        .find(|s| s.name().ok() == Some("__TEXT"))?
        .vmaddr;
    let offset = u64::from(command.dataoff);
    let length = command.datasize as usize;
    let bytes = macho.segments.iter().find_map(|segment| {
        let start = usize::try_from(offset.checked_sub(segment.fileoff)?).ok()?;
        segment.data.get(start..start.checked_add(length)?)
    })?;
    decode(bytes, base, code, sites)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn all_reviewed_sites_share_the_complete_table_builder_range() {
        let (bytes, _) = super::super::tests::arm_slice();
        let goblin::Object::Mach(goblin::mach::Mach::Binary(m)) =
            goblin::Object::parse(bytes).unwrap()
        else {
            panic!("arm")
        };
        let code = super::super::tests::code();
        let rows = super::super::tests::rows();
        let sites: Vec<_> = rows
            .iter()
            .map(|r| super::super::tests::num(r, "call"))
            .collect();
        assert_eq!(
            ranges(&m, &code, &sites),
            Some(vec![0x100019084..0x100028efc])
        );
        assert_eq!(ranges(&m, &code, &[]), Some(Vec::new()));
    }
    #[test]
    fn varints_reject_truncation_overflow_and_nonminimal_encodings() {
        for bytes in [&[][..], &[0x80], &[0x80, 0], &[0xff; 10], &[0x80; 11]] {
            assert!(uleb(bytes, &mut 0).is_none());
        }
        let mut maximum = [0xff; 10];
        maximum[9] = 1;
        assert_eq!(uleb(&maximum, &mut 0), Some(u64::MAX));
        maximum[9] = 2;
        assert!(uleb(&maximum, &mut 0).is_none());
    }
    #[test]
    fn ranges_require_sorted_mapped_sites_and_valid_terminated_table() {
        let data = [0; 64];
        let code = Region {
            addr: 0x1000,
            offset: 0,
            bytes: &data,
        };
        assert_eq!(
            decode(&[4, 16, 0, 0], 0xffc, &code, &[0x1000, 0x100c, 0x1010]),
            Some(vec![0x1000..0x1010, 0x1010..0x1040])
        );
        for table in [
            &[4, 16][..],
            &[4, 16, 0, 1],
            &[3, 0],
            &[0x80, 0],
            &[4, 64, 0],
        ] {
            assert!(decode(table, 0xffc, &code, &[0x1000]).is_none());
        }
        for sites in [
            &[0xffc][..],
            &[0x1040],
            &[0x1001],
            &[0x1010, 0x1000],
            &[0x1000, 0x1000],
        ] {
            assert!(decode(&[4, 0], 0xffc, &code, sites).is_none());
        }
        assert!(decode(&[4, 0], u64::MAX - 3, &code, &[0x1000]).is_none());
    }
    #[test]
    fn table_function_caller_and_site_budgets_are_enforced() {
        let bytes = vec![0; MAX_CALLER_BYTES as usize + 4];
        let code = Region {
            addr: 0x1000,
            offset: 0,
            bytes: &bytes,
        };
        assert!(decode(&[4, 0], 0xffc, &code, &[0x1000]).is_none());
        assert!(decode(&vec![0; MAX_TABLE + 1], 0xffc, &code, &[]).is_none());
        assert!(
            decode(
                &[4, 0],
                0xffc,
                &code,
                &vec![0x1000; super::super::super::MAX_CANDIDATES + 1]
            )
            .is_none()
        );
        let bytes = vec![0; 4 * (MAX_FUNCTIONS + 2)];
        let code = Region {
            addr: 0x1000,
            offset: 0,
            bytes: &bytes,
        };
        let mut table = vec![4; MAX_FUNCTIONS + 1];
        table.push(0);
        assert!(decode(&table, 0xffc, &code, &[]).is_none());
    }
    #[test]
    fn load_command_ranges_reject_missing_and_unmapped_tables() {
        let (bytes, _) = super::super::tests::arm_slice();
        let code = super::super::tests::code();
        for (offset, length) in [(u32::MAX, 1), (0, 0), (0, (MAX_TABLE + 1) as u32)] {
            let goblin::Object::Mach(goblin::mach::Mach::Binary(mut m)) =
                goblin::Object::parse(bytes).unwrap()
            else {
                panic!("arm")
            };
            for load in &mut m.load_commands {
                if let CommandVariant::FunctionStarts(value) = &mut load.command {
                    value.dataoff = offset;
                    value.datasize = length;
                }
            }
            assert!(ranges(&m, &code, &[0x1000190cc]).is_none());
        }
        let goblin::Object::Mach(goblin::mach::Mach::Binary(mut m)) =
            goblin::Object::parse(bytes).unwrap()
        else {
            panic!("arm")
        };
        m.load_commands
            .retain(|load| !matches!(load.command, CommandVariant::FunctionStarts(_)));
        assert!(ranges(&m, &code, &[0x1000190cc]).is_none());
    }

    #[test]
    fn exact_work_limits_remain_accepted() {
        let bytes = vec![0; MAX_CALLER_BYTES as usize];
        let code = Region {
            addr: 0x1000,
            offset: 0,
            bytes: &bytes,
        };
        let sites: Vec<_> = (0..super::super::super::MAX_CANDIDATES)
            .map(|i| 0x1000 + 4 * i as u64)
            .collect();
        assert_eq!(
            decode(&[4, 0], 0xffc, &code, &sites),
            Some(vec![0x1000..0x11000])
        );
        let bytes = vec![0; 4 * (MAX_FUNCTIONS + 1)];
        let code = Region {
            addr: 0x1000,
            offset: 0,
            bytes: &bytes,
        };
        let mut table = vec![4; MAX_FUNCTIONS];
        table.push(0);
        assert_eq!(decode(&table, 0xffc, &code, &[]), Some(Vec::new()));
        table.resize(MAX_TABLE, 0);
        assert_eq!(decode(&table, 0xffc, &code, &[]), Some(Vec::new()));
    }
}
