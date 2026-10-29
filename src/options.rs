//! What to extract and how: [`ExtractOptions`] and [`FormatHint`].

use crate::{ExtractedString, StringBoundary, xor};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Hint about the input shape so stng can skip pointless work.
///
/// `Auto` (default) lets stng decide from the bytes. A caller that already knows
/// the input is text can pass `Text` to suppress expensive binary-only analyses
/// (XOR scan, stack strings) that produce nothing on text input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FormatHint {
    /// Let stng detect.
    #[default]
    Auto,
    /// Text / script — skip XOR scan and binary-only analyses.
    Text,
}

/// How to extract strings. Start from [`ExtractOptions::new`] and adjust with
/// the `with_*` builders.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Minimum string length to extract
    pub min_length: usize,
    /// Filter out garbage strings (default: false for library, true for CLI)
    pub filter_garbage: bool,
    /// Enable XOR strings (single-byte scanning and bounded x86 PE decoder recovery). Default: false.
    pub xor_scan: bool,
    /// Custom XOR key for decoding (overrides auto-detection if set).
    pub xor_key: Option<Vec<u8>>,
    /// Minimum length for XOR-decoded strings (default: 10).
    pub xor_min_length: usize,
    /// Skip stng's native import/export/symbol extraction. Default: false.
    ///
    /// Set this when the caller already parses the binary's symbol tables
    /// itself (e.g. filefacts' `extract_symbols`) so the work isn't done
    /// twice. Symbol names still surface as raw `__LINKEDIT` / `.rdata` scan
    /// hits; only the structured, typed import/export pass is skipped.
    pub caller_provides_symbols: bool,
    /// Cancellation flag checked at phase boundaries (start of extraction,
    /// before XOR scan, between decoder passes).  When the flag becomes
    /// `true`, extraction returns whatever it has so far.
    pub cancel: Option<Arc<AtomicBool>>,
    /// Hint about the input so stng can skip analyses that will produce
    /// nothing on that shape of input.  See `FormatHint` for the semantics.
    pub format_hint: FormatHint,
    /// Strings an external disassembler (rizin/radare2) found, merged into
    /// the output. stng runs no subprocesses; the stng CLI runs rizin and
    /// passes its results through these `rizin_*` / `r2_*` fields.
    pub r2_strings: Option<Vec<ExtractedString>>,
    /// String extents from an external disassembler, used to aim XOR
    /// decoding.
    pub rizin_boundaries: Option<Vec<StringBoundary>>,
    /// `sockaddr_in` addresses an external disassembler recovered from
    /// `connect()` call sites, merged into the output.
    pub rizin_connect_addrs: Option<Vec<ExtractedString>>,
    /// File offsets where an external disassembler found code loading an XOR
    /// key. Each is tried as a 16-, 32- and 8-byte repeating key.
    pub xor_key_offsets: Option<Vec<u64>>,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self::new(4)
    }
}

impl ExtractOptions {
    /// Options for strings of at least `min_length` bytes, with every optional
    /// pass (garbage filter, XOR scan) off.
    #[must_use]
    pub fn new(min_length: usize) -> Self {
        Self {
            min_length,
            filter_garbage: false,
            xor_scan: false,
            xor_key: None,
            xor_min_length: xor::DEFAULT_XOR_MIN_LENGTH,
            caller_provides_symbols: false,
            cancel: None,
            format_hint: FormatHint::Auto,
            r2_strings: None,
            rizin_boundaries: None,
            rizin_connect_addrs: None,
            xor_key_offsets: None,
        }
    }

    /// Supply strings an external rizin/radare2 run found.
    #[must_use]
    pub fn with_r2_strings(mut self, strings: Vec<ExtractedString>) -> Self {
        self.r2_strings = Some(strings);
        self
    }

    /// Supply string extents from an external rizin run (`izzj`).
    #[must_use]
    pub fn with_rizin_boundaries(mut self, b: Vec<StringBoundary>) -> Self {
        self.rizin_boundaries = Some(b);
        self
    }

    /// Supply connect-address strings from an external rizin run.
    #[must_use]
    pub fn with_rizin_connect_addrs(mut self, c: Vec<ExtractedString>) -> Self {
        self.rizin_connect_addrs = Some(c);
        self
    }

    /// Supply file offsets of XOR keys found by an external disassembler.
    #[must_use]
    pub fn with_xor_key_offsets(mut self, offsets: Vec<u64>) -> Self {
        self.xor_key_offsets = Some(offsets);
        self
    }

    /// Enable garbage filtering to remove noise strings.
    /// Default is false for library use to give clients full control.
    #[must_use]
    pub fn with_garbage_filter(mut self, enable: bool) -> Self {
        self.filter_garbage = enable;
        self
    }

    /// Enable XOR string detection with optional custom minimum length.
    /// Scans single-byte XOR keys and recovers bounded, instruction-proven
    /// repeating-key XOR buffers in x86 PEs without a subprocess.
    /// Default minimum length is 10 characters.
    #[must_use]
    pub fn with_xor(mut self, min_length: Option<usize>) -> Self {
        self.xor_scan = true;
        if let Some(len) = min_length {
            self.xor_min_length = len;
        }
        self
    }

    /// Specify a custom XOR key for decoding.
    /// The key can be single-byte or multi-byte and will be applied to all byte streams.
    /// This overrides automatic XOR detection when set.
    #[must_use]
    pub fn with_xor_key(mut self, key: Vec<u8>) -> Self {
        self.xor_key = Some(key);
        self
    }

    /// Skip native import/export/symbol extraction because the caller already
    /// parses the symbol tables itself. See [`ExtractOptions::caller_provides_symbols`].
    #[must_use]
    pub fn with_caller_provides_symbols(mut self, provided: bool) -> Self {
        self.caller_provides_symbols = provided;
        self
    }

    /// Install a cancellation flag.
    ///
    /// stng checks the flag at phase boundaries (start of extraction, before
    /// XOR scan, between decoder passes).  When the flag flips to `true`,
    /// extraction returns whatever has been produced so far.
    #[must_use]
    pub fn with_cancellation(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Supply a hint about the input shape.
    ///
    /// `FormatHint::Text` skips the XOR scan and other binary-only analyses,
    /// which is a large win for callers that run stng over directories of
    /// scripts / minified JS / office documents.
    #[must_use]
    pub fn with_format_hint(mut self, hint: FormatHint) -> Self {
        self.format_hint = hint;
        self
    }

    /// Returns true if a cancellation flag was installed and has flipped.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Relaxed))
    }
}
