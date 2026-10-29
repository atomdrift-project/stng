//! Test samples. Executables and malware live in git gzip-compressed, so no
//! checkout carries them raw and no test binary embeds them. A sample is
//! inflated on first use into `target/testdata/`, mirroring its path under the
//! crate root, because some consumers (the CLI, rizin) need a real file.
#![allow(dead_code, clippy::panic, clippy::expect_used, clippy::unwrap_used)] // Each test crate uses a different subset.

use flate2::read::GzDecoder;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Absolute path of the sample at `rel` (relative to the crate root, without
/// `.gz`), inflating it on first use. Plain files that were never compressed
/// resolve to themselves. A missing sample panics: every fixture is tracked,
/// so absence is a broken test, never a reason to skip.
pub(crate) fn path(rel: &str) -> &'static str {
    let plain = Path::new(ROOT).join(rel);
    let packed = Path::new(ROOT).join(format!("{rel}.gz"));
    let resolved = if packed.is_file() {
        inflate(
            rel,
            &packed,
            &Path::new(ROOT).join("target/testdata").join(rel),
        )
    } else if plain.exists() {
        plain
    } else {
        panic!("missing test fixture: {rel}");
    };
    Box::leak(resolved.to_string_lossy().into_owned().into_boxed_str())
}

/// Writes `contents` to a file private to this test process and returns its
/// path. Files live under the target directory and are removed by
/// `cargo clean`.
pub(crate) fn temp_file(name: &str, contents: impl AsRef<[u8]>) -> &'static str {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = scratch_dir().join(format!(
        "{}-{}-{name}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, contents).expect("write temp file");
    Box::leak(path.to_string_lossy().into_owned().into_boxed_str())
}

/// A directory under `target/` for files tests create.
pub(crate) fn scratch_dir() -> PathBuf {
    let dir = Path::new(ROOT).join("target/tmp/stng-tests");
    std::fs::create_dir_all(&dir).expect("create test scratch directory");
    dir
}

/// Every sample under `testdata/`, relative to the crate root and without
/// any `.gz` suffix, sorted. Provenance notes, expected-output files and the
/// sources the samples were built from are not samples.
pub(crate) fn fixtures() -> Vec<String> {
    fn is_sample(rel: &str) -> bool {
        !(rel.ends_with(".md")
            || rel.ends_with("_expected.json")
            || rel.ends_with(".go")
            || rel.ends_with("/go.mod")
            || rel.contains("/src/")
            || rel.contains("/build/"))
    }
    fn walk(dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("read testdata") {
            let path = entry.expect("testdata entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                let rel = path.strip_prefix(ROOT).expect("under crate root");
                let rel = rel.to_str().expect("UTF-8 fixture path");
                let rel = rel.strip_suffix(".gz").unwrap_or(rel);
                if is_sample(rel) {
                    out.push(rel.to_owned());
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(ROOT).join("testdata"), &mut out);
    out.sort();
    out
}

/// A 512-byte 64-bit little-endian x86-64 ELF header with no sections.
pub(crate) fn minimal_elf_header() -> Vec<u8> {
    let mut data = vec![0u8; 512];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = 2; // 64-bit
    data[5] = 1; // little-endian
    data[6] = 1; // version
    data[16..18].copy_from_slice(&[2, 0]); // ET_EXEC
    data[18..20].copy_from_slice(&[0x3E, 0]); // EM_X86_64
    data[20..24].copy_from_slice(&[1, 0, 0, 0]); // EV_CURRENT
    data
}

/// Bytes as lowercase hex, for comparing digests.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Contents of the sample at `rel`, inflated in memory.
pub(crate) fn bytes(rel: &str) -> Vec<u8> {
    let packed = Path::new(ROOT).join(format!("{rel}.gz"));
    let Ok(file) = std::fs::File::open(&packed) else {
        let plain = Path::new(ROOT).join(rel);
        return std::fs::read(&plain).unwrap_or_else(|e| panic!("{}: {e}", plain.display()));
    };
    let mut out = Vec::new();
    GzDecoder::new(file)
        .read_to_end(&mut out)
        .unwrap_or_else(|e| panic!("{}: {e}", packed.display()));
    out
}

/// Inflates `packed` (the sample `rel`) to `dest` unless an up-to-date copy is already there.
/// Test threads and nextest processes race here, so each writes a private
/// temporary and renames it into place; the rename is atomic.
fn inflate(rel: &str, packed: &Path, dest: &Path) -> PathBuf {
    let fresh = |d: &Path| {
        let (Ok(d), Ok(p)) = (d.metadata(), packed.metadata()) else {
            return false;
        };
        d.modified().ok() >= p.modified().ok()
    };
    if fresh(dest) {
        return dest.to_owned();
    }
    let data = bytes(rel);
    std::fs::create_dir_all(dest.parent().expect("sample has a parent directory"))
        .expect("create target/testdata");
    let tmp = dest.with_extension(format!(
        "tmp{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&tmp, data).expect("write inflated sample");
    std::fs::rename(&tmp, dest).expect("move inflated sample into place");
    dest.to_owned()
}

/// Build a minimal but valid 64-bit little-endian ELF with custom sections.
///
/// Each entry in `sections` is (name, file_offset, vaddr, data, flags).
/// The builder places section headers at a fixed offset and creates a proper
/// .shstrtab so goblin can resolve section names.
pub(crate) fn build_elf_with_sections(sections: &[(&str, u64, u64, &[u8], u32)]) -> Vec<u8> {
    // Layout:
    //   0x0000 - ELF header (64 bytes)
    //   0x0040 - Program header (56 bytes) — single PT_LOAD covering everything
    //   0x1000..  Section data (placed at specified offsets)
    //   shstrtab_offset - .shstrtab section data
    //   shdr_offset - section headers (null + sections + .shstrtab)
    //
    // We allocate a large enough buffer and fill it in.

    let shstrtab_offset: usize = 0x8000;
    // Build .shstrtab content: "\0" + each section name + "\0" + ".shstrtab\0"
    let mut shstrtab = vec![0u8]; // null entry
    let mut name_offsets: Vec<usize> = Vec::new();
    for (name, _, _, _, _) in sections {
        name_offsets.push(shstrtab.len());
        shstrtab.extend_from_slice(name.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_name_offset = shstrtab.len();
    shstrtab.extend_from_slice(b".shstrtab\0");

    let shstrtab_size = shstrtab.len();
    let shdr_offset = shstrtab_offset + shstrtab_size;
    // Align to 8 bytes
    let shdr_offset = (shdr_offset + 7) & !7;

    // Section header count: null + user sections + .shstrtab
    let num_sections = 1 + sections.len() + 1;
    let shdr_entry_size: usize = 64; // sizeof(Elf64_Shdr)
    let total_size = shdr_offset + num_sections * shdr_entry_size;

    let mut data = vec![0u8; total_size];

    // --- ELF header (64 bytes) ---
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    data[4] = 2; // ELFCLASS64
    data[5] = 1; // ELFDATA2LSB
    data[6] = 1; // EV_CURRENT
    data[7] = 0; // ELFOSABI_NONE
    // e_type = ET_DYN (shared object, like .so)
    data[16..18].copy_from_slice(&3u16.to_le_bytes());
    // e_machine = EM_X86_64
    data[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
    // e_version
    data[20..24].copy_from_slice(&1u32.to_le_bytes());
    // e_entry = 0
    data[24..32].copy_from_slice(&0u64.to_le_bytes());
    // e_phoff = 0x40 (right after ELF header)
    data[32..40].copy_from_slice(&0x40u64.to_le_bytes());
    // e_shoff
    data[40..48].copy_from_slice(&(shdr_offset as u64).to_le_bytes());
    // e_flags = 0
    data[48..52].copy_from_slice(&0u32.to_le_bytes());
    // e_ehsize = 64
    data[52..54].copy_from_slice(&64u16.to_le_bytes());
    // e_phentsize = 56
    data[54..56].copy_from_slice(&56u16.to_le_bytes());
    // e_phnum = 1
    data[56..58].copy_from_slice(&1u16.to_le_bytes());
    // e_shentsize = 64
    data[58..60].copy_from_slice(&u16::try_from(shdr_entry_size).unwrap().to_le_bytes());
    // e_shnum
    data[60..62].copy_from_slice(&u16::try_from(num_sections).unwrap().to_le_bytes());
    // e_shstrndx = last section index
    data[62..64].copy_from_slice(&u16::try_from(num_sections - 1).unwrap().to_le_bytes());

    // --- Program header (single PT_LOAD at offset 0x40) ---
    let phdr_off = 0x40usize;
    // p_type = PT_LOAD (1)
    data[phdr_off..phdr_off + 4].copy_from_slice(&1u32.to_le_bytes());
    // p_flags = PF_R | PF_X (5)
    data[phdr_off + 4..phdr_off + 8].copy_from_slice(&5u32.to_le_bytes());
    // p_offset = 0
    data[phdr_off + 8..phdr_off + 16].copy_from_slice(&0u64.to_le_bytes());
    // p_vaddr = 0
    data[phdr_off + 16..phdr_off + 24].copy_from_slice(&0u64.to_le_bytes());
    // p_paddr = 0
    data[phdr_off + 24..phdr_off + 32].copy_from_slice(&0u64.to_le_bytes());
    // p_filesz = total_size
    data[phdr_off + 32..phdr_off + 40].copy_from_slice(&(total_size as u64).to_le_bytes());
    // p_memsz = total_size
    data[phdr_off + 40..phdr_off + 48].copy_from_slice(&(total_size as u64).to_le_bytes());
    // p_align = 0x1000
    data[phdr_off + 48..phdr_off + 56].copy_from_slice(&0x1000u64.to_le_bytes());

    // --- Place section data ---
    for (_, file_offset, _, section_data, _) in sections {
        let off = usize::try_from(*file_offset).unwrap();
        let end = off + section_data.len();
        assert!(
            end <= shstrtab_offset,
            "section data at {off:#x} overlaps shstrtab at {shstrtab_offset:#x}"
        );
        data[off..end].copy_from_slice(section_data);
    }

    // Place .shstrtab data
    data[shstrtab_offset..shstrtab_offset + shstrtab_size].copy_from_slice(&shstrtab);

    // --- Section headers ---
    // Entry 0: null (already zeroed)
    // Entries 1..N: user sections
    for (i, (_, file_offset, vaddr, section_data, flags)) in sections.iter().enumerate() {
        let off = shdr_offset + (i + 1) * shdr_entry_size;
        // sh_name
        data[off..off + 4].copy_from_slice(&u32::try_from(name_offsets[i]).unwrap().to_le_bytes());
        // sh_type = SHT_PROGBITS (1)
        data[off + 4..off + 8].copy_from_slice(&1u32.to_le_bytes());
        // sh_flags
        data[off + 8..off + 16].copy_from_slice(&u64::from(*flags).to_le_bytes());
        // sh_addr (virtual address)
        data[off + 16..off + 24].copy_from_slice(&vaddr.to_le_bytes());
        // sh_offset (file offset)
        data[off + 24..off + 32].copy_from_slice(&file_offset.to_le_bytes());
        // sh_size
        data[off + 32..off + 40].copy_from_slice(&(section_data.len() as u64).to_le_bytes());
        // sh_link, sh_info = 0
        // sh_addralign = 1
        data[off + 48..off + 56].copy_from_slice(&1u64.to_le_bytes());
        // sh_entsize = 0
    }

    // .shstrtab section header (last entry)
    {
        let idx = num_sections - 1;
        let off = shdr_offset + idx * shdr_entry_size;
        // sh_name
        data[off..off + 4]
            .copy_from_slice(&u32::try_from(shstrtab_name_offset).unwrap().to_le_bytes());
        // sh_type = SHT_STRTAB (3)
        data[off + 4..off + 8].copy_from_slice(&3u32.to_le_bytes());
        // sh_flags = 0
        // sh_addr = 0
        // sh_offset
        data[off + 24..off + 32].copy_from_slice(&(shstrtab_offset as u64).to_le_bytes());
        // sh_size
        data[off + 32..off + 40].copy_from_slice(&(shstrtab_size as u64).to_le_bytes());
        // sh_addralign = 1
        data[off + 48..off + 56].copy_from_slice(&1u64.to_le_bytes());
    }

    data
}
