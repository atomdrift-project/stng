//! Go string extraction.
//!
//! Go strings are represented as `{ptr: *byte, len: int}` structures (16 bytes on 64-bit).
//! The string data is typically stored in `.rodata` (ELF) or `__rodata` (Mach-O) sections,
//! while the pointer+length structures are scattered throughout data sections.
//!
//! For inline literals (function arguments, map keys/values), we also perform
//! instruction pattern analysis to extract strings that don't have stored structures.

mod extractor;

// Re-export the main extractor
pub(crate) use extractor::{
    extract_null_separated_strings, extract_varint_prefixed_strings, GoStringExtractor,
};
