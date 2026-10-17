use crate::TrieError;

/// Owned ordered set whose construction enforces uniqueness.
///
/// The immutable interface preserves the preconditions of trie construction.
#[derive(Debug, Clone)]
pub struct SortedKeySet {
    keys: Vec<Vec<u8>>,
}

impl SortedKeySet {
    pub fn from_unsorted(mut keys: Vec<Vec<u8>>) -> Self {
        keys.sort_unstable();
        keys.dedup();
        Self { keys }
    }

    pub fn try_from_sorted(keys: Vec<Vec<u8>>) -> Result<Self, TrieError> {
        for (index, pair) in keys.windows(2).enumerate() {
            match pair[0].cmp(&pair[1]) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Err(TrieError::Duplicate { index: index + 1 }),
                std::cmp::Ordering::Greater => {
                    return Err(TrieError::NotSorted { index: index + 1 });
                }
            }
        }
        Ok(Self { keys })
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.keys.iter().map(Vec::as_slice)
    }

    pub const fn len(&self) -> usize {
        self.keys.len()
    }
    pub const fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}
