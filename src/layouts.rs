//! The binform layouts of the binary being scanned: the caller's, or read
//! once on first use.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

/// A layout binform read from the bytes stng scans, and where in them.
#[derive(Debug, Clone, Copy)]
pub struct Layout<'l, 'd> {
    /// File offset of the bytes it was read from: zero for a whole binary,
    /// a slice's offset for one architecture of a universal binary.
    pub offset: u64,
    /// What binform read.
    pub binary: &'l binform::Binary<'d>,
}

impl<'l, 'd> Layout<'l, 'd> {
    /// `binary`, read from the bytes at file offset `offset`.
    #[must_use]
    pub fn new(offset: u64, binary: &'l binform::Binary<'d>) -> Self {
        Self { offset, binary }
    }
}

/// The layouts of one scan's binary, by where each was read from.
pub(crate) struct Layouts<'l, 'd> {
    given: &'l [Layout<'l, 'd>],
    /// Read here, for bytes `given` has no layout of; `None` for bytes
    /// binform cannot read.
    read: Mutex<HashMap<u64, Arc<Option<binform::Binary<'d>>>>>,
}

impl<'l, 'd> Layouts<'l, 'd> {
    /// The caller's layouts, `given`; any other is read when first asked for.
    pub(crate) fn new(given: &'l [Layout<'l, 'd>]) -> Self {
        Self {
            given,
            read: Mutex::default(),
        }
    }

    /// `f` of the layout of `bytes`, which start `base` bytes into the
    /// file: the caller's, else read from `bytes` once and kept for the rest
    /// of this scan. `None` when binform cannot read them.
    pub(crate) fn with<R>(
        &self,
        base: u64,
        bytes: &'d [u8],
        f: impl FnOnce(Option<&binform::Binary<'d>>) -> R,
    ) -> R {
        if let Some(layout) = self.given.iter().find(|layout| layout.offset == base) {
            return f(Some(layout.binary));
        }
        let layout = Arc::clone(
            self.read
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(base)
                .or_insert_with(|| Arc::new(binform::parse(bytes).ok())),
        );
        f(layout.as_ref().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::Layouts;

    #[test]
    fn a_layout_is_read_once_and_the_callers_is_preferred() {
        let elf = crate::test_fixture("testdata/elf/hello_linux_amd64");
        let layouts = Layouts::new(&[]);
        let first = layouts.with(0, elf, |l| l.map(|l| l.sections().len()));
        assert!(first.is_some_and(|n| n > 0));
        assert_eq!(layouts.read.lock().unwrap().len(), 1);
        assert_eq!(
            layouts.with(0, elf, |l| l.map(|l| l.sections().len())),
            first
        );
        assert_eq!(layouts.read.lock().unwrap().len(), 1);

        let given = binform::parse(elf).unwrap();
        let given = [super::Layout::new(0, &given)];
        let layouts = Layouts::new(&given);
        layouts.with(0, &[], |l| assert!(l.is_some()));
        assert!(layouts.read.lock().unwrap().is_empty());
        layouts.with(8, &[], |l| assert!(l.is_none()));
    }
}
