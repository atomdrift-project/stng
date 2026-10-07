//! The integration tests, as one binary: every file here is a module, so the
//! crate links once rather than once per file. `hostile_input` and
//! `test_rayon_saturation` stay separate: one installs a process-wide panic
//! hook, the other times itself against an otherwise idle machine.

#[path = "../common/mod.rs"]
mod common;

mod base64_zlib;
mod byte_offsets;
mod classifier_security;
mod clean_binaries;
mod cli;
mod codesig_precision;
mod crypto_wallet_extraction;
mod debug_extraction;
mod detect;
mod does_nothing_windows;
mod double_obfuscation;
mod dynamichub_arm64_xor;
mod elf_rootkit_xor;
mod fuzzy_base64;
mod gitlab_runner;
mod go_raw_fallback;
mod go_reflection_tags;
mod go_stored_string_table;
mod golden;
mod goodboy_loader;
mod imports;
mod integration;
mod ioc_corpus;
mod ioc_extraction;
mod java_class_magic;
mod kworker_obfuscation;
mod libffmpeg_3cx_xor;
mod macho_clock_lcg;
mod macho_codesig;
mod macho_go_pclntab;
mod macho_objc_strings;
mod multibyte_xor;
mod overlay;
mod pascalcase_identifiers;
mod passwd_classification;
mod pe_imports;
mod pe_inline_strings;
mod pe_xor_dll_detection;
mod polyglot_decoding;
mod repeating_xor_pe;
mod rust_elf_detection;
mod sample_stealer;
mod script_deobfuscation;
mod short_base64;
mod sockaddr_endianness;
mod stack_strings_poolrat;
mod stack_strings_realworld;
mod stack_strings_vget;
mod text_decoding_improved;
mod text_file_decoding;
mod threadracer;
mod types;
mod validation_extended;
mod validation_special_cases;
mod wazero_png_poster;
mod wizardnet_downloader;
mod wrapping_and_sorting;
mod xor_extraction;
mod xor_fat_macho;
mod xor_filtering;
mod xor_no_overlaps;
mod xor_realworld;
mod zyravpn_tun2socks;
