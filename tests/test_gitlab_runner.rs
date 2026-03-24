#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Test garble extraction on real gitlab-runner sample.

use std::path::Path;

/// Test gopclntab parsing on gitlab-runner sample.
#[test]
fn test_gitlab_runner_gopclntab() {
    let path = Path::new("/Users/t/data/dissect/malware/elf_linux/2026.gitlab_runner/gitlab-runner-01_1771942130_elf_sol.upx_decoded");
    if !path.exists() {
        eprintln!("Skipping: gitlab-runner sample not found");
        return;
    }

    let data = std::fs::read(path).unwrap();
    let elf = goblin::elf::Elf::parse(&data).expect("Failed to parse ELF");

    // Find .gopclntab section
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if name == ".gopclntab" {
            let start = sh.sh_offset as usize;
            let end = start + sh.sh_size as usize;
            let pclntab_data = &data[start..end];

            eprintln!("gopclntab size: {} bytes", pclntab_data.len());
            eprintln!("First 16 bytes: {:02x?}", &pclntab_data[..16]);

            let magic = u32::from_le_bytes([
                pclntab_data[0],
                pclntab_data[1],
                pclntab_data[2],
                pclntab_data[3],
            ]);
            eprintln!("Magic: {:#010x}", magic);

            use stng::garble::Pclntab;
            if let Some(pclntab) = Pclntab::parse(pclntab_data, sh.sh_addr) {
                eprintln!("Go version: {:?}", pclntab.go_version);
                eprintln!("Total functions: {}", pclntab.functions.len());

                let decrypt_funcs = pclntab.find_decrypt_functions();
                eprintln!("Decrypt functions: {}", decrypt_funcs.len());

                for func in &decrypt_funcs {
                    eprintln!("  {} @ {:#x}", func.name, func.entry_pc);
                }

                // Should find the 5 Decrypt functions
                assert!(
                    decrypt_funcs.len() >= 5,
                    "Expected at least 5 Decrypt functions, found {}",
                    decrypt_funcs.len()
                );

                // Check specific function names
                let names: Vec<&str> = decrypt_funcs.iter().map(|f| f.name.as_str()).collect();
                assert!(
                    names.iter().any(|n| n.contains("A6tobd9AfDd")),
                    "Expected to find A6tobd9AfDd.*.Decrypt"
                );
            } else {
                unreachable!("Failed to parse gopclntab");
            }
            return;
        }
    }

    unreachable!("No .gopclntab section found");
}
