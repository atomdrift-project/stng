//! Parts of the stng command-line tool that the library does not need.

pub(crate) mod rizin;

/// Bytes as lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
