use crate::bits::WordIndex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildResult {
    /// Next-level node coordinate, counting both internal and leaf children.
    Internal(u64),
    Leaf(u64),
}

pub struct DenseLevel {
    d_labels: WordIndex,
    d_has_child: Option<WordIndex>,
    d_terminal: WordIndex,
    node_count: u64,
}

pub struct DenseRawBytes {
    pub node_count: u64,
    pub labels_bits: Vec<bool>,
    pub child_indicator_bits: Vec<bool>,
    pub terminal_bits: Vec<bool>,
}

impl DenseLevel {
    /// Construct a level from consistent bit vectors.
    ///
    /// # Panics
    /// Panics if label or terminal dimensions disagree with `node_count`.
    pub fn new(
        labels_bits: &[bool],
        has_child_bits: &[bool],
        terminal_bits: &[bool],
        node_count: u64,
    ) -> Self {
        assert_eq!(
            (labels_bits.len() / 256) as u64,
            node_count,
            "labels_bits length {} does not match node_count {} * 256",
            labels_bits.len(),
            node_count,
        );
        assert_eq!(labels_bits.len() % 256, 0, "incomplete dense node bitmap");
        assert_eq!(
            terminal_bits.len() as u64,
            node_count,
            "terminal_bits length {} does not match node_count {}",
            terminal_bits.len(),
            node_count,
        );
        Self {
            d_labels: WordIndex::from(labels_bits),
            d_has_child: (!has_child_bits.is_empty()).then(|| WordIndex::from(has_child_bits)),
            d_terminal: WordIndex::from(terminal_bits),
            node_count,
        }
    }

    pub fn from_raw(raw: &DenseRawBytes) -> Self {
        Self::new(
            &raw.labels_bits,
            &raw.child_indicator_bits,
            &raw.terminal_bits,
            raw.node_count,
        )
    }

    pub fn child_lookup(&self, node: u64, byte: u8) -> Option<ChildResult> {
        let pos = node.checked_mul(256)?.checked_add(u64::from(byte))?;
        if pos >= self.d_labels.len() {
            return None;
        }
        if !self.d_labels[pos] {
            return None;
        }
        let child_rank_all = self.d_labels.rank(pos);
        let ci_idx = child_rank_all - 1;
        let children = self.d_has_child.as_ref()?;
        if children[ci_idx] {
            Some(ChildResult::Internal(child_rank_all - 1))
        } else {
            Some(ChildResult::Leaf(child_rank_all - 1))
        }
    }

    pub fn child_rank_all(&self, node: u64, byte: u8) -> u64 {
        let pos = node * 256 + u64::from(byte);
        self.d_labels.rank(pos) - 1
    }

    pub fn is_terminal(&self, node: u64) -> bool {
        self.d_terminal[node]
    }

    pub fn terminal_rank(&self, node: u64) -> u64 {
        self.d_terminal.rank(node)
    }

    pub fn terminal_count(&self) -> u64 {
        self.d_terminal.rank(self.node_count - 1)
    }

    pub fn terminal_select(&self, i: u64) -> Option<u64> {
        i.checked_add(1)
            .filter(|&rank| rank <= self.node_count)
            .and_then(|rank| self.d_terminal.select(rank))
    }

    pub fn internal_child_count(&self) -> u64 {
        self.d_has_child
            .as_ref()
            .map_or(0, |children| children.rank(children.len() - 1))
    }

    pub const fn node_count(&self) -> u64 {
        self.node_count
    }

    pub fn next_label_pos(&self, node: u64, start_byte: u8) -> Option<u8> {
        let start = node.checked_mul(256)?;
        if start >= self.d_labels.len() {
            return None;
        }
        (start_byte..=u8::MAX).find(|&byte| self.d_labels[start + u64::from(byte)])
    }

    pub fn next_label_after(&self, node: u64, after_byte: u8) -> Option<u8> {
        if after_byte == 255 {
            return None;
        }
        self.next_label_pos(node, after_byte + 1)
    }

    pub fn to_raw_bytes(&self) -> DenseRawBytes {
        let labels_bits = (0..self.d_labels.len()).map(|i| self.d_labels[i]).collect();
        let child_indicator_bits = self.d_has_child.as_ref().map_or_else(Vec::new, |children| {
            (0..children.len()).map(|i| children[i]).collect()
        });
        let terminal_bits = (0..self.node_count).map(|i| self.d_terminal[i]).collect();
        DenseRawBytes {
            node_count: self.node_count,
            labels_bits,
            child_indicator_bits,
            terminal_bits,
        }
    }

    pub(crate) fn serialization_bits(&self) -> [(u64, impl Iterator<Item = bool> + '_); 3] {
        let labels = self.node_count * 256;
        let children = self.d_has_child.as_ref().map_or(0, WordIndex::len);
        [(0, labels), (1, children), (2, self.node_count)].map(|(field, length)| {
            (
                length,
                (0..length).map(move |position| self.serialization_bit(field, position)),
            )
        })
    }

    fn serialization_bit(&self, field: u8, position: u64) -> bool {
        match field {
            0 => self.d_labels[position],
            1 => self
                .d_has_child
                .as_ref()
                .is_some_and(|children| children[position]),
            _ => self.d_terminal[position],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_label_and_last_terminal_use_inclusive_rank() {
        let level = build_single_node(&[255], &[true], true);
        assert_eq!(level.child_lookup(0, 255), Some(ChildResult::Internal(0)));
        assert_eq!(level.child_rank_all(0, 255), 0);
        assert_eq!(level.internal_child_count(), 1);
        assert_eq!(level.terminal_rank(0), 1);
        assert_eq!(level.terminal_select(0), Some(0));
        assert_eq!(level.terminal_select(1), None);
        assert_eq!(level.terminal_select(u64::MAX), None);
    }

    fn build_single_node(labels: &[u8], internal: &[bool], terminal: bool) -> DenseLevel {
        let mut label_bits = vec![false; 256];
        for &l in labels {
            label_bits[l as usize] = true;
        }
        DenseLevel::new(&label_bits, internal, &[terminal], 1)
    }

    #[test]
    fn no_children() {
        let level = DenseLevel::new(&vec![false; 256], &[], &[false], 1);
        assert_eq!(level.child_lookup(0, 42), None);
        assert!(!level.is_terminal(0));
    }

    #[test]
    fn single_internal_child() {
        let level = build_single_node(&[42], &[true], false);
        assert!(matches!(
            level.child_lookup(0, 42),
            Some(ChildResult::Internal(0))
        ));
        assert_eq!(level.child_lookup(0, 41), None);
    }

    #[test]
    fn single_leaf_child() {
        let level = build_single_node(&[42], &[false], false);
        assert!(matches!(
            level.child_lookup(0, 42),
            Some(ChildResult::Leaf(0))
        ));
    }

    #[test]
    fn terminal_node() {
        let level = build_single_node(&[5], &[true], true);
        assert!(level.is_terminal(0));
        assert_eq!(level.terminal_count(), 1);
        assert_eq!(level.terminal_rank(0), 1);
    }

    #[test]
    fn multiple_children_rank() {
        let level = build_single_node(&[1, 2, 3, 4, 5], &[true, false, true, false, true], false);
        assert_eq!(level.internal_child_count(), 3);
        assert!(matches!(
            level.child_lookup(0, 1),
            Some(ChildResult::Internal(0))
        ));
        assert!(matches!(
            level.child_lookup(0, 2),
            Some(ChildResult::Leaf(1))
        ));
        assert!(matches!(
            level.child_lookup(0, 3),
            Some(ChildResult::Internal(2))
        ));
    }

    #[test]
    fn child_rank_all_counts_all() {
        let level = build_single_node(&[1, 2, 3], &[true, false, true], false);
        assert_eq!(level.child_rank_all(0, 1), 0);
        assert_eq!(level.child_rank_all(0, 2), 1);
        assert_eq!(level.child_rank_all(0, 3), 2);
    }

    #[test]
    fn next_label() {
        let level = build_single_node(&[50, 100, 200], &[true, true, true], false);
        assert_eq!(level.next_label_pos(0, 0), Some(50));
        assert_eq!(level.next_label_after(0, 50), Some(100));
        assert_eq!(level.next_label_after(0, 200), None);
    }

    #[test]
    fn raw_roundtrip() {
        let level = build_single_node(&[3, 7, 255], &[true, false, true], true);
        let raw = level.to_raw_bytes();
        let restored = DenseLevel::new(
            &raw.labels_bits,
            &raw.child_indicator_bits,
            &raw.terminal_bits,
            raw.node_count,
        );
        assert_eq!(restored.node_count(), 1);
        assert!(restored.is_terminal(0));
        assert!(matches!(
            restored.child_lookup(0, 3),
            Some(ChildResult::Internal(_))
        ));
        assert!(matches!(
            restored.child_lookup(0, 7),
            Some(ChildResult::Leaf(_))
        ));
    }

    #[test]
    fn streaming_fields_match_canonical_raw_arrays_across_word_boundaries() {
        let mut labels = vec![false; 3 * 256];
        for position in [0, 63, 64, 255, 256, 511, 512, 767] {
            labels[position] = true;
        }
        let level = DenseLevel::new(
            &labels,
            &[true, false, true, false, false, true, false, true],
            &[true, false, true],
            3,
        );
        let raw = level.to_raw_bytes();
        for ((length, stream), expected) in level.serialization_bits().into_iter().zip([
            raw.labels_bits,
            raw.child_indicator_bits,
            raw.terminal_bits,
        ]) {
            assert_eq!(length, expected.len() as u64);
            assert!(stream.eq(expected));
        }
        let empty_children = DenseLevel::new(&[false; 256], &[], &[false], 1);
        let [(labels, _), (children, stream), (terminals, _)] = empty_children.serialization_bits();
        assert_eq!((labels, children, terminals), (256, 0, 1));
        assert_eq!(stream.count(), 0);
    }
}
