//! Import and export symbol extraction: the tables binform reads from a
//! binary's headers, and the Mach-O symbol table.

use crate::binary::macho_vaddr_to_file_offset;
use crate::types::{ExtractedString, StringKind, StringMethod};
use goblin::mach::MachO;
use std::collections::HashSet;

/// A name a binary's structures hold, at `data_offset`.
fn structure(value: String, data_offset: u64, kind: StringKind) -> ExtractedString {
    ExtractedString::new(value, data_offset, StringMethod::Structure).with_kind(kind)
}

/// The imports, then the exports, `layout` read from a binary's headers,
/// each name once and only names `seen` does not already hold. Each sits at
/// the file offset of its slot or its code, zero when the file holds no byte
/// there. `base` is where the bytes `layout` was read from start in the file.
///
/// A PE import by ordinal only is named `ORDINAL n`, as the import tables
/// spell it elsewhere; a PE export by ordinal only has no name and is left
/// out.
fn table_strings(
    layout: &binform::Binary<'_>,
    base: u64,
    min_length: usize,
    seen: &mut HashSet<String>,
) -> Vec<ExtractedString> {
    let pe = layout.format() == binform::Format::Pe;
    let at = |addr: Option<u64>| {
        addr.and_then(|addr| layout.offset(addr))
            .map_or(0, |offset| offset.saturating_add(base))
    };
    let mut strings = Vec::new();
    for import in layout.imports() {
        let name = match import.ordinal {
            Some(ordinal) if pe => format!("ORDINAL {ordinal}"),
            _ => import.name.clone(),
        };
        if name.len() >= min_length && seen.insert(name.clone()) {
            strings.push(structure(name, at(import.slot), StringKind::Import));
        }
    }
    for export in layout.exports() {
        let name = &export.name;
        if pe && is_ordinal_placeholder(name) {
            continue;
        }
        if name.len() >= min_length && seen.insert(name.clone()) {
            // A Mach-O re-export has no address of its own.
            strings.push(structure(name.clone(), at(export.addr), StringKind::Export));
        }
    }
    strings
}

/// binform's name for a PE export by ordinal only: `Ordinal_n`.
fn is_ordinal_placeholder(name: &str) -> bool {
    name.strip_prefix("Ordinal_")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Imports and exports of a Mach-O, by its bind information, export trie and
/// symbol table. `layout` is what binform read from `slice`, the bytes
/// `macho` was parsed from: the whole file, or the architecture's slice of a
/// universal binary starting `base` bytes into it.
pub(crate) fn extract_macho_imports(
    macho: &MachO<'_>,
    layout: Option<&binform::Binary<'_>>,
    slice: &[u8],
    base: u64,
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut strings = layout
        .map(|layout| table_strings(layout, base, min_length, &mut seen))
        .unwrap_or_default();

    // Walk the static symbol table (nlist). The bind information and the
    // export trie above miss what the symbol table additionally carries:
    // undefined externals (`_popen`), Objective-C class references
    // (`_OBJC_CLASS_$_…`) and local stub helpers (`_objc_msgSend$…`) that a
    // disassembler surfaces. Without this they appear only as untyped
    // raw-scan hits in the __LINKEDIT string table; classifying them by
    // nlist type lets `merge_imports` retag those hits with a proper kind.
    //
    // goblin trusts the header's `nsyms`, and past the end of the file its
    // iterator stops advancing while `flatten` drops each error: a forged
    // count spun four billion times. No entry is under 12 bytes (32-bit
    // nlist), so a real table has at most `slice.len() / 12` of them.
    for (name, nlist) in macho.symbols().take(slice.len() / 12).flatten() {
        // Skip debug (STABS) entries — source paths and line info, not symbols.
        if name.len() < min_length || nlist.is_stab() || !seen.insert(name.to_string()) {
            continue;
        }
        let kind = if nlist.is_undefined() {
            StringKind::Import
        } else if nlist.is_global() {
            StringKind::Export
        } else {
            StringKind::FuncName
        };
        // Undefined symbols have n_value == 0; merge_imports retags the located
        // raw-scan hit and keeps its real offset, so the address here only
        // matters for the rare symbol absent from the strtab scan.
        let file_offset = macho_vaddr_to_file_offset(macho, nlist.n_value)
            .unwrap_or(nlist.n_value)
            .saturating_add(base);
        strings.push(structure(name.to_string(), file_offset, kind));
    }

    strings
}

/// Imports and exports of a PE or ELF binary, from the tables `layout` read:
/// the PE import, delay-load and export directories, whose names sit behind
/// RVA tables a raw byte scan cannot follow, or the ELF dynamic symbol table.
pub(crate) fn extract_layout_imports(
    layout: Option<&binform::Binary<'_>>,
    min_length: usize,
) -> Vec<ExtractedString> {
    layout
        .map(|layout| table_strings(layout, 0, min_length, &mut HashSet::new()))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::is_ordinal_placeholder;

    #[test]
    fn only_binforms_ordinal_spelling_is_a_placeholder() {
        assert!(is_ordinal_placeholder("Ordinal_12"));
        assert!(!is_ordinal_placeholder("Ordinal_"));
        assert!(!is_ordinal_placeholder("Ordinal_x"));
        assert!(!is_ordinal_placeholder("GetOrdinal_1"));
    }
}
