use crate::bits::WordIndex;

pub struct SparseLevel {
    labels: Vec<u8>,
    has_child: WordIndex,
    louds: WordIndex,
    terminal: WordIndex,
}

pub struct SparseRawBytes {
    pub labels: Vec<u8>,
    pub child_indicator_bits: Vec<bool>,
    pub louds_bits: Vec<bool>,
    pub terminal_bits: Vec<bool>,
}

impl SparseLevel {
    /// Construct a sparse level from equally sized label and bit vectors.
    ///
    /// # Panics
    /// Panics if any bit vector has a different length from the labels.
    pub fn new(
        labels: Vec<u8>,
        has_child_bits: &[bool],
        louds_bits: &[bool],
        terminal_bits: &[bool],
    ) -> Self {
        let n = labels.len();
        assert_eq!(
            has_child_bits.len(),
            n,
            "s_has_child length {} does not match labels length {}",
            has_child_bits.len(),
            n,
        );
        assert_eq!(
            louds_bits.len(),
            n,
            "s_louds length {} does not match labels length {}",
            louds_bits.len(),
            n,
        );
        assert_eq!(
            terminal_bits.len(),
            n,
            "s_terminal length {} does not match labels length {}",
            terminal_bits.len(),
            n,
        );
        Self {
            labels,
            has_child: WordIndex::from(has_child_bits),
            louds: WordIndex::from(louds_bits),
            terminal: WordIndex::from(terminal_bits),
        }
    }

    pub fn from_raw(raw: &SparseRawBytes) -> Self {
        Self::new(
            raw.labels.clone(),
            &raw.child_indicator_bits,
            &raw.louds_bits,
            &raw.terminal_bits,
        )
    }

    pub fn first_label_pos(&self, node: u64, node_count_dense: u64) -> Option<u64> {
        self.first_label_pos_by_rank(node.checked_sub(node_count_dense)?)
    }

    pub fn first_label_pos_by_rank(&self, child_rank: u64) -> Option<u64> {
        self.louds.select(child_rank.checked_add(1)?)
    }

    pub fn node_size(&self, start: u64) -> u64 {
        if start >= self.louds.len() {
            return 0;
        }
        let node_rank = self.louds.rank(start);
        self.louds.select(node_rank + 1).map_or_else(
            || self.label_count() - start,
            |next_start| next_start - start,
        )
    }

    pub(crate) fn node_rank(&self, pos: u64) -> u64 {
        self.louds.rank(pos) - 1
    }

    pub fn find_label(&self, start: u64, size: u64, byte: u8) -> Option<u64> {
        let (position, label) = self.label_at_or_after(start, size, byte)?;
        (label == byte).then_some(position)
    }

    /// Search one sorted sibling range, excluding any terminal marker.
    pub(crate) fn label_at_or_after(&self, start: u64, size: u64, byte: u8) -> Option<(u64, u8)> {
        let begin = usize::try_from(start).ok()?;
        let end = usize::try_from(start.checked_add(size)?).ok()?;
        let labels = self.labels.get(begin..end)?;
        let offset = labels.partition_point(|&label| label < byte);
        Some((start + offset as u64, *labels.get(offset)?))
    }

    /// Find the first label strictly greater than `byte` in [start, start+size).
    /// Strictly greater, not greater-or-equal. The cursor's seek uses this
    /// after a failed exact match via `find_label`. If `find_label` returns None
    /// (no exact match), `lower_bound_label` finds the first label AFTER the
    /// target, not equal to it.
    pub fn lower_bound_label(&self, start: u64, size: u64, byte: u8) -> Option<u64> {
        let begin = usize::try_from(start).ok()?;
        let end = usize::try_from(start.checked_add(size)?).ok()?;
        let labels = self.labels.get(begin..end)?;
        let offset = labels.partition_point(|&label| label <= byte);
        (offset < labels.len()).then(|| start + offset as u64)
    }

    pub fn has_child(&self, pos: u64) -> bool {
        self.has_child[pos]
    }

    pub fn is_terminal(&self, pos: u64) -> bool {
        self.terminal[pos]
    }

    pub fn terminal_rank(&self, pos: u64) -> u64 {
        self.terminal.rank(pos)
    }

    pub fn terminal_select(&self, i: u64) -> Option<u64> {
        i.checked_add(1)
            .filter(|&rank| rank <= self.terminal.len())
            .and_then(|rank| self.terminal.select(rank))
    }

    pub fn internal_child_rank(&self, pos: u64) -> u64 {
        self.has_child.rank(pos)
    }

    pub fn child_node_num(&self, pos: u64, child_count_dense: u64) -> u64 {
        let rank = self.has_child.rank(pos);
        child_count_dense + rank - 1
    }

    pub fn is_node_start(&self, pos: u64) -> bool {
        self.louds[pos]
    }

    /// Read an admitted navigation position.
    ///
    /// # Panics
    /// Panics if `pos` is outside this level's label vector.
    pub fn label_at(&self, pos: u64) -> u8 {
        // Navigation positions are bounded by the allocated label vector.
        let position = usize::try_from(pos)
            .unwrap_or_else(|_| unreachable!("admitted label position fits address space"));
        self.labels[position]
    }

    pub const fn label_count(&self) -> u64 {
        self.labels.len() as u64
    }

    pub fn to_raw(&self) -> SparseRawBytes {
        let len = self.labels.len();
        let mut child_indicator_bits = vec![false; len];
        let mut louds_bits = vec![false; len];
        let mut terminal_bits = vec![false; len];
        for i in 0..len {
            child_indicator_bits[i] = self.has_child[i as u64];
            louds_bits[i] = self.louds[i as u64];
            terminal_bits[i] = self.terminal[i as u64];
        }
        SparseRawBytes {
            labels: self.labels.clone(),
            child_indicator_bits,
            louds_bits,
            terminal_bits,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_singleton_node_and_terminal_have_no_successor() {
        let level = SparseLevel::new(
            vec![b'a', b'b'],
            &[true, false],
            &[true, true],
            &[false, true],
        );
        assert_eq!(level.node_size(1), 1);
        assert_eq!(level.terminal_rank(1), 1);
        assert_eq!(level.terminal_select(0), Some(1));
        assert_eq!(level.terminal_select(2), None);
        assert_eq!(level.terminal_select(u64::MAX), None);
        assert_eq!(level.internal_child_rank(1), 1);
    }

    #[test]
    fn single_terminal_leaf() {
        let level = SparseLevel::new(vec![b'a'], &[false], &[true], &[true]);
        assert_eq!(level.label_count(), 1);
        assert!(level.is_terminal(0));
        assert!(!level.has_child(0));
        assert_eq!(level.label_at(0), b'a');
        assert!(level.is_node_start(0));
        assert_eq!(level.terminal_rank(0), 1);
    }

    #[test]
    fn three_children() {
        let level = SparseLevel::new(
            vec![b'a', b'c', b'f'],
            &[false, false, false],
            &[true, false, false],
            &[true, false, true],
        );
        assert_eq!(level.node_size(0), 3);
        assert!(level.is_terminal(0));
        assert!(!level.is_terminal(1));
        assert!(level.is_terminal(2));
        assert_eq!(level.terminal_rank(2), 2);
    }

    #[test]
    fn find_label_in_node() {
        let level = SparseLevel::new(
            vec![b'a', b'c', b'f'],
            &[false, false, false],
            &[true, false, false],
            &[false, false, false],
        );
        assert_eq!(level.find_label(0, 3, b'c'), Some(1));
        assert_eq!(level.find_label(0, 3, b'b'), None);
    }

    #[test]
    fn child_node_num_with_offset() {
        let level = SparseLevel::new(
            vec![b'x', b'y'],
            &[true, false],
            &[true, true],
            &[false, true],
        );
        assert_eq!(level.child_node_num(0, 100), 100);
    }

    #[test]
    fn first_label_pos_with_offset() {
        let level = SparseLevel::new(
            vec![b'a', b'b', b'c'],
            &[false, false, false],
            &[true, false, true],
            &[false, false, false],
        );
        assert_eq!(level.first_label_pos(5, 5), Some(0));
        assert_eq!(level.first_label_pos(6, 5), Some(2));
        assert_eq!(level.first_label_pos(4, 5), None);
        assert_eq!(level.first_label_pos_by_rank(u64::MAX), None);
    }

    #[test]
    fn raw_roundtrip() {
        let level = SparseLevel::new(
            vec![b'x', b'y', b'z'],
            &[true, false, false],
            &[true, false, false],
            &[false, true, false],
        );
        let raw = level.to_raw();
        let restored = SparseLevel::from_raw(&raw);
        assert_eq!(restored.label_count(), 3);
        assert!(restored.is_terminal(1));
        assert!(restored.has_child(0));
    }

    #[test]
    fn lower_bound_is_strictly_greater() {
        let level = SparseLevel::new(
            vec![b'a', b'c', b'f'],
            &[false, false, false],
            &[true, false, false],
            &[false, false, false],
        );
        // Strictly greater than 'a' is 'c' at position 1, not 'a' at position 0
        assert_eq!(level.lower_bound_label(0, 3, b'a'), Some(1));
        // Strictly greater than 'b' is 'c' at position 1
        assert_eq!(level.lower_bound_label(0, 3, b'b'), Some(1));
        // Strictly greater than 'c' is 'f' at position 2
        assert_eq!(level.lower_bound_label(0, 3, b'c'), Some(2));
        // Nothing strictly greater than 'f'
        assert_eq!(level.lower_bound_label(0, 3, b'f'), None);
        // Nothing strictly greater than 'g'
        assert_eq!(level.lower_bound_label(0, 3, b'g'), None);
    }

    #[test]
    fn internal_child_rank_counts_internal() {
        let level = SparseLevel::new(
            vec![b'a', b'b', b'c', b'd'],
            &[true, false, true, false],
            &[true, false, false, false],
            &[false, false, false, false],
        );
        // Position 0: 'a' is internal. rank at pos 0 = 1 internal child.
        assert_eq!(level.internal_child_rank(0), 1);
        // Position 1: 'b' is leaf. rank at pos 1 = still 1 internal child.
        assert_eq!(level.internal_child_rank(1), 1);
        // Position 2: 'c' is internal. rank at pos 2 = 2 internal children.
        assert_eq!(level.internal_child_rank(2), 2);
        // Position 3: 'd' is leaf. rank at pos 3 = still 2 internal children.
        assert_eq!(level.internal_child_rank(3), 2);
    }
}
