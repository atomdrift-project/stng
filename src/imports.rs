//! Import and export symbol extraction.

use crate::binary::{find_macho_section, macho_vaddr_to_file_offset};
use crate::types::{ExtractedString, StringKind, StringMethod};
use goblin::mach::MachO;
use std::collections::HashSet;

pub fn extract_macho_imports(macho: &MachO<'_>, min_length: usize) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Extract imports with their source library
    if let Ok(imports) = macho.imports() {
        for import in imports {
            if import.name.len() >= min_length && seen.insert(import.name.to_string()) {
                // Strip the leading path from dylib, e.g., "/usr/lib/libSystem.B.dylib" -> "libSystem.B.dylib"
                let lib = import.dylib.rsplit('/').next().unwrap_or(import.dylib);
                let section = find_macho_section(macho, import.address);
                // Convert virtual address to file offset
                let file_offset = macho_vaddr_to_file_offset(macho, import.address);
                strings.push(ExtractedString {
                    value: import.name.to_string(),
                    data_offset: file_offset,
                    section,
                    method: StringMethod::Structure,
                    kind: StringKind::Import,
                    library: Some(lib.to_string()),
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
                    kind: StringKind::Export,
                    ..Default::default()
                });
            }
        }
    }

    strings
}

/// Extract imports from an ELF binary.
pub fn extract_elf_imports(elf: &goblin::elf::Elf<'_>, min_length: usize) -> Vec<ExtractedString> {
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
        let (kind, library) = if sym.st_shndx == 0 {
            // Undefined - this is an import
            // Try to find the library from verneed
            let lib = elf
                .verneed
                .iter()
                .flat_map(goblin::elf::VerneedSection::iter)
                .find(|vn| {
                    vn.iter()
                        .any(|aux| elf.dynstrtab.get_at(aux.vna_name) == Some(name))
                })
                .and_then(|vn| elf.dynstrtab.get_at(vn.vn_file))
                .map(std::string::ToString::to_string);
            (StringKind::Import, lib)
        } else if sym.st_bind() == goblin::elf::sym::STB_GLOBAL
            || sym.st_bind() == goblin::elf::sym::STB_WEAK
        {
            // Defined global/weak symbol - this is an export
            (StringKind::Export, None)
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
            library,
            ..Default::default()
        });
    }

    strings
}
