//! Mach-O dyld bind streams: imported symbols, counted before they are
//! parsed so hostile streams cannot inflate the work.

use super::{contain, file_range_clamped};
use goblin::mach::MachO;

/// The most imports a Mach-O's bind streams may declare before
/// [`macho_imports`] declines to hand them to goblin.
pub(super) const MAX_MACHO_BIND_IMPORTS: u64 = 256 * 1024;

/// `macho.imports()`, contained like [`contain`] -- unless the bind streams
/// in `slice`, the bytes `macho` was parsed from, would have goblin build more
/// than [`MAX_MACHO_BIND_IMPORTS`] imports. goblin builds one `Import` per
/// binding, and a single `DO_BIND_ULEB_TIMES_SKIPPING_ULEB` with a forged
/// repeat count asks for billions: gigabytes in seconds, which no panic guard
/// stops.
pub(crate) fn macho_imports<'m>(
    macho: &'m MachO<'_>,
    slice: &[u8],
) -> Option<Vec<goblin::mach::imports::Import<'m>>> {
    if macho_bind_count(macho, slice) > MAX_MACHO_BIND_IMPORTS {
        tracing::debug!(
            MAX_MACHO_BIND_IMPORTS,
            "Mach-O imports skipped: too many bindings"
        );
        return None;
    }
    contain(|| macho.imports())
}

/// The bindings `macho`'s bind and lazy-bind streams declare, as goblin's
/// interpreter would count them, up to just past [`MAX_MACHO_BIND_IMPORTS`].
pub(super) fn macho_bind_count(macho: &MachO<'_>, slice: &[u8]) -> u64 {
    use goblin::mach::load_command::CommandVariant;

    let mut count = 0u64;
    for lc in &macho.load_commands {
        let (CommandVariant::DyldInfo(info) | CommandVariant::DyldInfoOnly(info)) = &lc.command
        else {
            continue;
        };
        let streams = [
            (info.bind_off, info.bind_size),
            (info.lazy_bind_off, info.lazy_bind_size),
        ];
        for (off, size) in streams {
            let stream = file_range_clamped(slice, off.into(), size.into()).unwrap_or_default();
            count = bind_stream_count(stream, count);
            if count > MAX_MACHO_BIND_IMPORTS {
                return count;
            }
        }
    }
    count
}

/// `count` plus the bindings one bind-opcode `stream` declares, stopping
/// once the total passes [`MAX_MACHO_BIND_IMPORTS`].
pub(super) fn bind_stream_count(stream: &[u8], mut count: u64) -> u64 {
    use goblin::mach::bind_opcodes::{
        BIND_OPCODE_ADD_ADDR_ULEB, BIND_OPCODE_DO_BIND, BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED,
        BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB, BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB,
        BIND_OPCODE_MASK, BIND_OPCODE_SET_ADDEND_SLEB, BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,
        BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
    };
    let mut at = 0;
    while let Some(&opcode) = stream.get(at) {
        at += 1;
        let read = match opcode & BIND_OPCODE_MASK {
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
            | BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
            | BIND_OPCODE_ADD_ADDR_ULEB
            | BIND_OPCODE_SET_ADDEND_SLEB => leb128(stream, &mut at).map(|_| ()),
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => stream
                .get(at..)
                .and_then(|rest| rest.iter().position(|&b| b == 0))
                .map(|len| at += len + 1),
            BIND_OPCODE_DO_BIND | BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                count += 1;
                Some(())
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                count += 1;
                leb128(stream, &mut at).map(|_| ())
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                leb128(stream, &mut at).and_then(|times| {
                    leb128(stream, &mut at)?;
                    count = count.saturating_add(times);
                    Some(())
                })
            }
            _ => Some(()),
        };
        // A truncated operand ends goblin's walk too.
        if read.is_none() || count > MAX_MACHO_BIND_IMPORTS {
            break;
        }
    }
    count
}

/// A LEB128 value at `*at`, advancing past it. Signed and unsigned values
/// share the framing; bits past 64 are dropped, as goblin's reader drops them.
pub(super) fn leb128(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(*at)?;
        *at += 1;
        if shift < 64 {
            value |= u64::from(byte & 0x7f) << shift;
        }
        shift = shift.saturating_add(7);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
}

#[cfg(test)]
mod tests;
