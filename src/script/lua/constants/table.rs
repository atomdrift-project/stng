use super::{Key, Value};
use std::collections::BTreeMap;
use std::rc::Rc;

// Nearby integer keys share a page. A snapshot copies page handles and a
// write detaches only the page it changes. The folder iterates integer keys
// in ascending order followed by byte-string keys, including for table.concat.
const PAGE_SIZE: i64 = 32;

#[derive(Clone, Default)]
pub(super) struct Table<'t> {
    integer_pages: BTreeMap<i64, Rc<BTreeMap<i64, Value<'t>>>>,
    strings: Rc<BTreeMap<Vec<u8>, Value<'t>>>,
    length: usize,
    /// Number of consecutive keys starting at one, used by # and table.insert.
    sequence: usize,
}

impl<'t> Table<'t> {
    pub(super) fn len(&self) -> usize {
        self.length
    }

    pub(super) fn sequence_len(&self) -> usize {
        self.sequence
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &Value<'t>> {
        self.integer_pages
            .values()
            .flat_map(|page| page.values())
            .chain(self.strings.values())
    }

    pub(super) fn get(&self, key: &Key) -> Option<&Value<'t>> {
        match key {
            Key::Number(n) => self.integer_pages.get(&n.div_euclid(PAGE_SIZE))?.get(n),
            Key::Bytes(s) => self.strings.get(s),
        }
    }

    pub(super) fn contains_key(&self, key: &Key) -> bool {
        self.get(key).is_some()
    }

    pub(super) fn insert(&mut self, key: Key, value: Value<'t>) {
        let previous = match key {
            Key::Number(n) => {
                let page = self
                    .integer_pages
                    .entry(n.div_euclid(PAGE_SIZE))
                    .or_default();
                let previous = Rc::make_mut(page).insert(n, value);
                if usize::try_from(n) == Ok(self.sequence + 1) {
                    self.sequence += 1;
                    while self.contains_key(&Key::Number(self.sequence as i64 + 1)) {
                        self.sequence += 1;
                    }
                }
                previous
            }
            Key::Bytes(s) => Rc::make_mut(&mut self.strings).insert(s, value),
        };
        self.length += usize::from(previous.is_none());
    }

    pub(super) fn remove(&mut self, key: &Key) {
        let previous = match key {
            Key::Number(n) => {
                let id = n.div_euclid(PAGE_SIZE);
                let Some(page) = self.integer_pages.get_mut(&id) else {
                    return;
                };
                let previous = Rc::make_mut(page).remove(n);
                if page.is_empty() {
                    self.integer_pages.remove(&id);
                }
                if let Ok(index) = usize::try_from(*n)
                    && index > 0
                    && index <= self.sequence
                {
                    self.sequence = index - 1;
                }
                previous
            }
            Key::Bytes(s) => Rc::make_mut(&mut self.strings).remove(s),
        };
        self.length -= usize::from(previous.is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::{Key, Table, Value};

    #[test]
    fn snapshots_preserve_order_and_the_first_hole() {
        let mut table = Table::default();
        for key in (-2..=34).rev().filter(|key| *key != 6) {
            table.insert(Key::Number(key), Value::Number(key as f64));
        }
        table.insert(Key::Bytes(b"key".to_vec()), Value::Number(77.0));
        let mut branch = table.clone();
        branch.insert(Key::Number(6), Value::Nil);
        assert_eq!(branch.sequence_len(), 34);
        assert_eq!(table.sequence_len(), 5);
        branch.remove(&Key::Number(32));
        branch.remove(&Key::Number(32));
        branch.remove(&Key::Bytes(b"key".to_vec()));
        assert_eq!(branch.len() + 1, table.len());
        assert_eq!(branch.sequence_len(), 31);
        assert!(table.contains_key(&Key::Number(32)));
        let numbers: Vec<_> = table
            .values()
            .filter_map(|v| match v {
                Value::Number(n) => Some(*n),
                _ => None,
            })
            .collect();
        let expected: Vec<_> = (-2..=34)
            .filter(|n| *n != 6)
            .map(f64::from)
            .chain([77.0])
            .collect();
        assert_eq!(numbers, expected);
    }
}
