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

/// Which XOR passes run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum XorMode {
    /// No XOR decoding.
    #[default]
    Off,
    /// Single-byte scanning, auto-detected keys and x86 PE decoder recovery.
    /// Skipped for Go binaries and platform-signed binaries, where XOR
    /// obfuscation does not occur in practice.
    Auto,
    /// Everything `Auto` does, without those skips, plus decoding at the key
    /// locations in [`ExternalHints::xor_key_offsets`].
    Scan,
    /// Decode with this key only (single- or multi-byte).
    Key(Vec<u8>),
}

/// What an external disassembler (rizin) found, for stng to merge or aim at.
/// stng runs no subprocesses; the `stng` command runs rizin and passes its
/// results through these.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ExternalHints {
    /// Strings the disassembler found, merged into the output.
    pub strings: Vec<ExtractedString>,
    /// String extents, used to aim XOR decoding.
    pub boundaries: Vec<StringBoundary>,
    /// `sockaddr_in` addresses recovered from `connect()` call sites.
    pub connect_addrs: Vec<ExtractedString>,
    /// File offsets of code that loads an XOR key; with [`XorMode::Scan`],
    /// each is tried as a 16-, 32- and 8-byte repeating key.
    pub xor_key_offsets: Vec<u64>,
}

/// How to extract strings. Start from [`ExtractOptions::new`] and adjust with
/// the `with_*` builders.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub(crate) min_length: usize,
    pub(crate) filter_garbage: bool,
    pub(crate) xor: XorMode,
    pub(crate) xor_min_length: usize,
    pub(crate) caller_provides_symbols: bool,
    pub(crate) cancel: Option<Arc<AtomicBool>>,
    pub(crate) format_hint: FormatHint,
    pub(crate) hints: ExternalHints,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self::new(4)
    }
}

impl ExtractOptions {
    /// Options for strings of at least `min_length` bytes, with every optional
    /// pass (garbage filter, XOR) off.
    #[must_use]
    pub fn new(min_length: usize) -> Self {
        Self {
            min_length,
            filter_garbage: false,
            xor: XorMode::Off,
            xor_min_length: xor::DEFAULT_XOR_MIN_LENGTH,
            caller_provides_symbols: false,
            cancel: None,
            format_hint: FormatHint::Auto,
            hints: ExternalHints::default(),
        }
    }

    /// Drop strings the garbage filter judges to be noise. Off by default for
    /// library use; the `stng` command turns it on.
    #[must_use]
    pub fn with_garbage_filter(mut self, enable: bool) -> Self {
        self.filter_garbage = enable;
        self
    }

    /// Choose the XOR passes. See [`XorMode`].
    #[must_use]
    pub fn with_xor(mut self, mode: XorMode) -> Self {
        self.xor = mode;
        self
    }

    /// The shortest XOR-decoded string reported (default 10).
    #[must_use]
    pub fn with_xor_min_length(mut self, min_length: usize) -> Self {
        self.xor_min_length = min_length;
        self
    }

    /// Skip stng's own import/export/symbol extraction because the caller
    /// already parses the symbol tables. Symbol names still surface as raw
    /// scan hits; only the structured, typed pass is skipped.
    #[must_use]
    pub fn with_caller_provides_symbols(mut self, provided: bool) -> Self {
        self.caller_provides_symbols = provided;
        self
    }

    /// Install a cancellation flag. stng checks it at phase boundaries (start
    /// of extraction, before the XOR passes, between decoder passes) and
    /// returns what it has so far once it is set.
    #[must_use]
    pub fn with_cancellation(mut self, cancel: Arc<AtomicBool>) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Say what the input is. [`FormatHint::Text`] skips the XOR passes and
    /// other binary-only analyses, a large saving over directories of scripts.
    #[must_use]
    pub fn with_format_hint(mut self, hint: FormatHint) -> Self {
        self.format_hint = hint;
        self
    }

    /// Supply what an external disassembler found. See [`ExternalHints`].
    #[must_use]
    pub fn with_hints(mut self, hints: ExternalHints) -> Self {
        self.hints = hints;
        self
    }

    /// The shortest string reported.
    #[must_use]
    pub fn min_length(&self) -> usize {
        self.min_length
    }

    /// Whether the garbage filter runs.
    #[must_use]
    pub fn filter_garbage(&self) -> bool {
        self.filter_garbage
    }

    /// The XOR passes that run.
    #[must_use]
    pub fn xor(&self) -> &XorMode {
        &self.xor
    }

    /// Whether a cancellation flag was installed and has been set.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Relaxed))
    }

    /// The single-byte and auto-detected passes run (`Auto` or `Scan`).
    pub(crate) fn xor_scans(&self) -> bool {
        matches!(self.xor, XorMode::Auto | XorMode::Scan)
    }

    /// XOR was asked for explicitly (`Scan` or `Key`), so it also runs where
    /// `Auto` skips it: Go and platform-signed binaries.
    pub(crate) fn xor_explicit(&self) -> bool {
        matches!(self.xor, XorMode::Scan | XorMode::Key(_))
    }

    /// The user's key, in [`XorMode::Key`].
    pub(crate) fn xor_key(&self) -> Option<&[u8]> {
        match &self.xor {
            XorMode::Key(key) => Some(key),
            _ => None,
        }
    }
}
