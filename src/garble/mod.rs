//! Garble string deobfuscation module.
//!
//! This module provides tools for extracting obfuscated strings from binaries
//! compiled with [garble](https://github.com/burrowers/garble), a Go build
//! tool that obfuscates package names, variable names, and string literals.
//!
//! # Garble Transformation Modes
//!
//! Garble uses one of five transformation modes for string obfuscation:
//!
//! | Mode    | Description | Detection Method |
//! |---------|-------------|------------------|
//! | simple  | XOR/ADD/SUB with key array | Rodata byte-pair scanning |
//! | split   | Fragment and concatenate | Emulation |
//! | shuffle | Permute byte order | Emulation |
//! | seed    | LFSR-based XOR | Emulation |
//! | swap    | Swap byte pairs | Emulation |
//!
//! # Module Structure
//!
//! - [`ops`]: Garble transformation operators (XOR, ADD, SUB)
//! - [`rodata`]: Static rodata byte-pair scanner for "simple" mode
//! - [`gopclntab`]: Go pclntab parser for finding Decrypt functions
//! - [`emulator`]: Lightweight x86-64 emulator for all modes
//! - [`decrypt`]: Orchestration of emulation-based extraction

mod decrypt;
mod emulator;
mod func_finder;
mod gopclntab;
mod ops;
mod rodata;

// Re-export public API
pub use decrypt::{
    emulate_decrypt_function, extract_garble_strings, extract_garble_strings_v2,
    GarbleExtractResult, SectionData,
};
pub use emulator::{CpuState, EmulationResult, Emulator, Memory};
pub use func_finder::{
    find_call_targets, find_decrypt_candidates, find_init_functions, FuncCandidate,
};
pub use gopclntab::{FuncEntry, GoVersion, Pclntab};
pub use ops::GarbleOp;
pub use rodata::{
    check_printable, extract_garble_rodata_strings, find_nonprintable_blobs, is_printable_byte,
    score_decoded_string,
};
