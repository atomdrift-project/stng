//! Import and export symbol extraction.

use crate::binary::{find_macho_section, macho_vaddr_to_file_offset};
use crate::types::{ExtractedString, StringKind, StringMethod};
use goblin::mach::MachO;
use std::collections::HashSet;

pub(crate) fn extract_macho_imports(macho: &MachO<'_>, min_length: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Extract imports with their source library
    if let Ok(imports) = macho.imports() {
        for import in imports {
            if import.name.len() >= min_length && seen.insert(import.name.to_string()) {
                let section = find_macho_section(macho, import.address);
                // Convert virtual address to file offset
                let file_offset = macho_vaddr_to_file_offset(macho, import.address);
                strings.push(ExtractedString {
                    value: import.name.to_string(),
                    data_offset: file_offset,
                    section,
                    method: StringMethod::Structure,
                    kind: Some(StringKind::Import),
                    ..Default::default()
                });
            }
        }
    }

    // Extract exports
    if let Ok(exports) = macho.exports() {
        for export in exports {
            if export.name.len() >= min_length && seen.insert(export.name.clone()) {
                // Convert virtual address to file offset
                let file_offset = macho_vaddr_to_file_offset(macho, export.offset);
                let section = find_macho_section(macho, export.offset);
                strings.push(ExtractedString {
                    value: export.name.clone(),
                    data_offset: file_offset,
                    section,
                    method: StringMethod::Structure,
                    kind: Some(StringKind::Export),
                    ..Default::default()
                });
            }
        }
    }

    // Walk the static symbol table (nlist). imports()/exports() above only see
    // dyld bind info and the export trie; the symbol table additionally carries
    // undefined externals (`_popen`), Objective-C class references
    // (`_OBJC_CLASS_$_…`) and local stub helpers (`_objc_msgSend$…`) that radare2
    // surfaces but those two views miss. Without this they appear only as
    // untyped raw-scan hits in the __LINKEDIT string table; classifying them by
    // nlist type lets `merge_imports` retag those hits with a proper kind.
    for (name, nlist) in macho.symbols().flatten() {
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
        let section = find_macho_section(macho, nlist.n_value);
        let file_offset = macho_vaddr_to_file_offset(macho, nlist.n_value);
        strings.push(ExtractedString {
            value: name.to_string(),
            data_offset: file_offset,
            section,
            method: StringMethod::Structure,
            kind: Some(kind),
            ..Default::default()
        });
    }

    strings
}

/// Extract imports and exports from a PE binary.
///
/// goblin resolves the import directory (and bound imports) to `(name, dll)`
/// pairs and the export directory to named exports; neither is recoverable by a
/// raw byte scan when the names live behind RVA tables rather than as inline
/// literals, which is why PE import names were previously absent without
/// radare2. Each entry carries the resolving DLL as its source.
pub(crate) fn extract_pe_imports(
    pe: &goblin::pe::PE<'_>,
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for import in &pe.imports {
        if import.name.len() >= min_length && seen.insert(import.name.to_string()) {
            strings.push(ExtractedString {
                value: import.name.to_string(),
                // u64 from usize: lossless on 64-bit hosts (this tool is 64-bit only).
                data_offset: import.offset as u64,
                section: None,
                method: StringMethod::Structure,
                kind: Some(StringKind::Import),
                ..Default::default()
            });
        }
    }

    for export in &pe.exports {
        if let Some(name) = export.name
            && name.len() >= min_length
            && seen.insert(name.to_string())
        {
            strings.push(ExtractedString {
                value: name.to_string(),
                data_offset: export.offset.unwrap_or(0) as u64,
                section: None,
                method: StringMethod::Structure,
                kind: Some(StringKind::Export),
                ..Default::default()
            });
        }
    }

    strings
}

/// Extract imports from an ELF binary.
pub(crate) fn extract_elf_imports(
    elf: &goblin::elf::Elf<'_>,
    min_length: usize,
) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Extract dynamic symbols (imports/exports)
    for sym in &elf.dynsyms {
        let name = match elf.dynstrtab.get_at(sym.st_name) {
            Some(n) if n.len() >= min_length => n,
            _ => continue,
        };

        if !seen.insert(name.to_string()) {
            continue;
        }

        // UNDEF symbols with non-zero st_value or GLOBAL binding are imports
        // GLOBAL/WEAK symbols with defined section are exports
        let kind = if sym.st_shndx == 0 {
            // Undefined - this is an import
            Some(StringKind::Import)
        } else if sym.st_bind() == goblin::elf::sym::STB_GLOBAL
            || sym.st_bind() == goblin::elf::sym::STB_WEAK
        {
            // Defined global/weak symbol - this is an export
            Some(StringKind::Export)
        } else {
            continue;
        };

        // Look up the actual section name from the section index
        let section = if sym.st_shndx > 0 && sym.st_shndx < elf.section_headers.len() {
            elf.shdr_strtab
                .get_at(elf.section_headers[sym.st_shndx].sh_name)
                .map(std::string::ToString::to_string)
        } else {
            None
        };
        strings.push(ExtractedString {
            value: name.to_string(),
            data_offset: sym.st_value,
            section,
            method: StringMethod::Structure,
            kind,
            ..Default::default()
        });
    }

    strings
}
