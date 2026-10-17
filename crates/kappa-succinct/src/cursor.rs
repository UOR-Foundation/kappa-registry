use kappa_cursor::KappaCursor;

use crate::dense::ChildResult;
use crate::trie::LoudsDsTrie;

// A maximum-length key may also retain one sparse terminal-marker frame.
const MAX_KEY_LEN: usize = 66;
const MAX_DEPTH: usize = 66;

enum TrieOwner<'a> {
    Borrowed(&'a LoudsDsTrie),
    Owned(std::sync::Arc<LoudsDsTrie>),
}

impl std::ops::Deref for TrieOwner<'_> {
    type Target = LoudsDsTrie;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(trie) => trie,
            Self::Owned(trie) => trie,
        }
    }
}

/// Dense and Sparse use different coordinate systems.
/// Dense: level-local node index. Sparse: `s_labels` position.
/// `FramePos` makes passing one to the other's methods a compile error.
#[derive(Clone, Copy)]
enum FramePos {
    Dense { level: usize, node: u64 },
    Sparse { pos: u64, child_range_end: u64 },
}

#[derive(Clone, Copy)]
struct Frame {
    position: FramePos,
    label: u8,
}

/// Stack-based lazy descent cursor over a `LoudsDsTrie`.
///
/// No heap allocation in advance or seek. All state in fixed-size
/// stack-allocated arrays. O(depth) seek, O(1) amortized advance.
pub struct TrieCursor<'a> {
    trie: TrieOwner<'a>,
    stack: [Frame; MAX_DEPTH],
    depth: usize,
    key_buf: [u8; MAX_KEY_LEN],
    key_len: usize,
    exhausted: bool,
    yielded: u64,
}

impl<'a> TrieCursor<'a> {
    pub fn new(trie: &'a LoudsDsTrie) -> Self {
        Self::from_owner(TrieOwner::Borrowed(trie))
    }

    pub fn from_arc(trie: std::sync::Arc<LoudsDsTrie>) -> TrieCursor<'static> {
        TrieCursor::from_owner(TrieOwner::Owned(trie))
    }

    fn from_owner(trie: TrieOwner<'a>) -> Self {
        let mut cursor = Self {
            trie,
            stack: [Frame {
                position: FramePos::Dense { level: 0, node: 0 },
                label: 0,
            }; MAX_DEPTH],
            depth: 0,
            key_buf: [0u8; MAX_KEY_LEN],
            key_len: 0,
            exhausted: false,
            yielded: 0,
        };
        if cursor.trie.key_count() == 0 {
            cursor.exhausted = true;
        } else if cursor.trie.dense_levels().is_empty() {
            cursor.descend_to_leftmost_terminal_sparse(0);
        } else {
            cursor.descend_to_leftmost_terminal_dense(0, 0);
        }
        cursor
    }

    const fn push(&mut self, frame: Frame) {
        if self.depth >= MAX_DEPTH {
            self.exhausted = true;
            return;
        }
        self.stack[self.depth] = frame;
        self.key_buf[self.depth] = frame.label;
        self.depth += 1;
        self.key_len = self.depth;
    }

    fn descend_to_leftmost_terminal_dense(&mut self, level: usize, node: u64) {
        self.descend_dense(level, node, false);
    }

    fn descend_dense(&mut self, level: usize, node: u64, skip_initial_terminal: bool) {
        let cutover = usize::from(self.trie.cutover_depth());
        let mut current_level = level;
        let mut current_node = node;

        loop {
            if current_level >= self.trie.dense_levels().len() {
                self.exhausted = true;
                return;
            }
            let dl = &self.trie.dense_levels()[current_level];

            if dl.is_terminal(current_node) && !(skip_initial_terminal && current_level == level) {
                return;
            }

            if let Some(byte) = dl.next_label_pos(current_node, 0) {
                let child = dl.child_lookup(current_node, byte);
                self.push(Frame {
                    position: FramePos::Dense {
                        level: current_level,
                        node: current_node,
                    },
                    label: byte,
                });
                match child {
                    Some(ChildResult::Internal(child)) => {
                        if current_level + 1 < cutover
                            && current_level + 1 < self.trie.dense_levels().len()
                        {
                            current_level += 1;
                            current_node = child;
                            continue;
                        }
                        self.descend_to_leftmost_terminal_sparse(child);
                        return;
                    }
                    Some(ChildResult::Leaf(_)) => {
                        return;
                    }
                    None => {
                        self.exhausted = true;
                        return;
                    }
                }
            }
            self.exhausted = true;
            return;
        }
    }

    fn descend_to_leftmost_terminal_sparse(&mut self, sparse_node_rank: u64) {
        let ncd = self.trie.node_count_dense();
        let Some(mut s_start) = self.trie.sparse().first_label_pos_by_rank(sparse_node_rank) else {
            self.exhausted = true;
            return;
        };
        let mut s_size = self.trie.sparse().node_size(s_start);

        loop {
            if s_size == 0 {
                self.exhausted = true;
                return;
            }
            let pos = s_start;
            let label = self.trie.sparse().label_at(pos);

            self.push(Frame {
                position: FramePos::Sparse {
                    pos,
                    child_range_end: s_start + s_size,
                },
                label,
            });

            if self.trie.sparse().is_terminal(pos) {
                if self.trie.sparse_is_marker(pos) {
                    self.key_len = self.key_len.saturating_sub(1);
                }
                return;
            }

            if self.trie.sparse().has_child(pos) {
                let child = self.trie.sparse_child_bfs(pos);
                let Some(start) = self.trie.sparse().first_label_pos(child, ncd) else {
                    self.exhausted = true;
                    return;
                };
                s_start = start;
                s_size = self.trie.sparse().node_size(s_start);
                continue;
            }

            self.exhausted = true;
            return;
        }
    }

    fn advance_from_current(&mut self) {
        let cutover = usize::from(self.trie.cutover_depth());

        loop {
            if self.depth == 0 {
                self.exhausted = true;
                return;
            }

            self.depth -= 1;
            self.key_len = self.depth;
            let frame = self.stack[self.depth];

            match frame.position {
                FramePos::Dense { level, node } => {
                    let dl = &self.trie.dense_levels()[level];
                    if let Some(next_byte) = dl.next_label_after(node, frame.label) {
                        match dl.child_lookup(node, next_byte) {
                            Some(ChildResult::Internal(child)) => {
                                self.push(Frame {
                                    position: FramePos::Dense { level, node },
                                    label: next_byte,
                                });
                                if level + 1 < cutover && level + 1 < self.trie.dense_levels().len()
                                {
                                    self.descend_to_leftmost_terminal_dense(level + 1, child);
                                } else {
                                    self.descend_to_leftmost_terminal_sparse(child);
                                }
                                return;
                            }
                            Some(ChildResult::Leaf(_)) => {
                                self.push(Frame {
                                    position: FramePos::Dense { level, node },
                                    label: next_byte,
                                });
                                return;
                            }
                            None => {}
                        }
                    }
                }
                FramePos::Sparse {
                    pos,
                    child_range_end,
                } => {
                    let next_pos = pos + 1;
                    if next_pos < child_range_end && !self.trie.sparse().is_node_start(next_pos) {
                        let next_label = self.trie.sparse().label_at(next_pos);
                        self.push(Frame {
                            position: FramePos::Sparse {
                                pos: next_pos,
                                child_range_end,
                            },
                            label: next_label,
                        });
                        if self.trie.sparse().is_terminal(next_pos) {
                            return;
                        }
                        if self.trie.sparse().has_child(next_pos) {
                            let child = self.trie.sparse_child_bfs(next_pos);
                            self.descend_to_leftmost_terminal_sparse(
                                child - self.trie.node_count_dense(),
                            );
                            return;
                        }
                    }
                }
            }
        }
    }

    fn try_descend_from_current(&mut self) -> bool {
        if self.depth == 0 {
            return false;
        }
        let frame = self.stack[self.depth - 1];
        let cutover = usize::from(self.trie.cutover_depth());

        match frame.position {
            FramePos::Dense { level, node } => {
                let dl = &self.trie.dense_levels()[level];
                match dl.child_lookup(node, frame.label) {
                    Some(ChildResult::Internal(child)) => {
                        if level + 1 < cutover && level + 1 < self.trie.dense_levels().len() {
                            self.descend_dense(level + 1, child, true);
                        } else {
                            self.descend_to_leftmost_terminal_sparse(child);
                        }
                        !self.exhausted
                    }
                    _ => false,
                }
            }
            FramePos::Sparse { pos, .. } => {
                if self.trie.sparse().has_child(pos) {
                    let child = self.trie.sparse_child_bfs(pos);
                    self.descend_to_leftmost_terminal_sparse(child - self.trie.node_count_dense());
                    !self.exhausted
                } else {
                    false
                }
            }
        }
    }
}

impl KappaCursor for TrieCursor<'_> {
    fn key(&self) -> &[u8] {
        if self.exhausted {
            kappa_cursor::TERMINATED
        } else {
            &self.key_buf[..self.key_len]
        }
    }

    fn advance(&mut self) -> &[u8] {
        if self.exhausted {
            return kappa_cursor::TERMINATED;
        }
        self.yielded += 1;

        if self.try_descend_from_current() {
            return self.key();
        }

        self.advance_from_current();
        self.key()
    }

    fn seek(&mut self, target: &[u8]) -> &[u8] {
        if self.exhausted {
            return kappa_cursor::TERMINATED;
        }
        let current = &self.key_buf[..self.key_len];
        if target <= current {
            return self.key();
        }

        self.depth = 0;
        self.key_len = 0;
        self.exhausted = false;

        let cutover = usize::from(self.trie.cutover_depth());
        let mut dense_node: u64 = 0;

        for (d, &byte) in target.iter().enumerate() {
            if d < cutover && d < self.trie.dense_levels().len() {
                let dl = &self.trie.dense_levels()[d];
                match dl.child_lookup(dense_node, byte) {
                    Some(ChildResult::Internal(child)) => {
                        self.push(Frame {
                            position: FramePos::Dense {
                                level: d,
                                node: dense_node,
                            },
                            label: byte,
                        });
                        dense_node = child;
                    }
                    Some(ChildResult::Leaf(_)) => {
                        self.push(Frame {
                            position: FramePos::Dense {
                                level: d,
                                node: dense_node,
                            },
                            label: byte,
                        });
                        if d + 1 < target.len() {
                            self.advance_from_current();
                        }
                        return self.key();
                    }
                    None => {
                        if let Some(next_byte) = dl.next_label_after(dense_node, byte) {
                            let child = dl.child_lookup(dense_node, next_byte);
                            self.push(Frame {
                                position: FramePos::Dense {
                                    level: d,
                                    node: dense_node,
                                },
                                label: next_byte,
                            });
                            match child {
                                Some(ChildResult::Internal(child)) => {
                                    if d + 1 < cutover && d + 1 < self.trie.dense_levels().len() {
                                        self.descend_to_leftmost_terminal_dense(d + 1, child);
                                    } else {
                                        self.descend_to_leftmost_terminal_sparse(child);
                                    }
                                }
                                Some(ChildResult::Leaf(_)) => {}
                                None => {
                                    self.exhausted = true;
                                }
                            }
                        } else {
                            self.advance_from_current();
                        }
                        return self.key();
                    }
                }
            } else {
                return self.seek_sparse(target, d, dense_node);
            }
        }

        let level = target.len();
        if level < cutover && level < self.trie.dense_levels().len() {
            if !self.trie.dense_levels()[level].is_terminal(dense_node) {
                self.descend_to_leftmost_terminal_dense(level, dense_node);
            }
        } else {
            self.descend_to_leftmost_terminal_sparse(dense_node);
        }
        self.key()
    }

    fn size_hint(&self) -> u64 {
        if self.exhausted {
            0
        } else {
            self.trie.key_count().saturating_sub(self.yielded)
        }
    }

    fn cost(&self) -> u64 {
        self.size_hint()
    }
}

impl TrieCursor<'_> {
    fn seek_sparse(&mut self, target: &[u8], depth: usize, dense_node: u64) -> &[u8] {
        let ncd = self.trie.node_count_dense();
        let Some(mut s_start) = self.trie.sparse().first_label_pos_by_rank(dense_node) else {
            self.exhausted = true;
            return self.key();
        };
        let mut s_size = self.trie.sparse().node_size(s_start);

        for s_d in depth..target.len() {
            let t = target[s_d];
            if self.trie.sparse_is_marker(s_start) {
                s_start += 1;
                s_size -= 1;
            }
            let Some((found, label)) = self.trie.sparse().label_at_or_after(s_start, s_size, t)
            else {
                self.advance_from_current();
                return self.key();
            };
            self.push(Frame {
                position: FramePos::Sparse {
                    pos: found,
                    child_range_end: s_start + s_size,
                },
                label,
            });
            if label > t || s_d + 1 == target.len() {
                if !self.trie.sparse().is_terminal(found) {
                    if self.trie.sparse().has_child(found) {
                        let child = self.trie.sparse_child_bfs(found);
                        self.descend_to_leftmost_terminal_sparse(child - ncd);
                    } else {
                        self.advance_from_current();
                    }
                }
                return self.key();
            }
            if !self.trie.sparse().has_child(found) {
                self.advance_from_current();
                return self.key();
            }
            let child = self.trie.sparse_child_bfs(found);
            let Some(start) = self.trie.sparse().first_label_pos(child, ncd) else {
                self.exhausted = true;
                return self.key();
            };
            s_start = start;
            s_size = self.trie.sparse().node_size(s_start);
        }
        self.key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trie::{LoudsDsTrie, TrieConfig};

    fn collect_all(cursor: &mut TrieCursor) -> Vec<Vec<u8>> {
        let mut results = Vec::new();
        while cursor.key() != kappa_cursor::TERMINATED {
            results.push(cursor.key().to_vec());
            cursor.advance();
        }
        results
    }

    #[test]
    fn single_key_iteration() -> Result<(), crate::trie::TrieError> {
        let trie = LoudsDsTrie::build(&TrieConfig::default(), [b"hello".as_slice()])?;
        let mut cursor = TrieCursor::new(&trie);
        let keys = collect_all(&mut cursor);
        assert_eq!(keys, vec![b"hello".to_vec()]);
        Ok(())
    }

    #[test]
    fn sorted_iteration() -> Result<(), crate::trie::TrieError> {
        let input: Vec<&[u8]> = vec![b"aa", b"ab", b"ba", b"bb"];
        let trie = LoudsDsTrie::build(&TrieConfig::default(), input.iter().copied())?;
        let mut cursor = TrieCursor::new(&trie);
        let keys = collect_all(&mut cursor);
        let expected: Vec<Vec<u8>> = input.iter().map(|k| k.to_vec()).collect();
        assert_eq!(keys, expected);
        Ok(())
    }

    #[test]
    fn exhausted_returns_terminated() -> Result<(), crate::trie::TrieError> {
        let trie = LoudsDsTrie::build(&TrieConfig::default(), [b"x".as_slice()])?;
        let mut cursor = TrieCursor::new(&trie);
        cursor.advance();
        assert_eq!(cursor.key(), kappa_cursor::TERMINATED);
        assert_eq!(cursor.advance(), kappa_cursor::TERMINATED);
        Ok(())
    }

    #[test]
    fn seek_to_existing_key() -> Result<(), crate::trie::TrieError> {
        let trie = LoudsDsTrie::build(&TrieConfig::default(), [b"aa".as_slice(), b"bb", b"cc"])?;
        let mut cursor = TrieCursor::new(&trie);
        let result = cursor.seek(b"bb");
        assert_eq!(result, b"bb");
        Ok(())
    }

    #[test]
    fn seek_between_keys() -> Result<(), crate::trie::TrieError> {
        let trie = LoudsDsTrie::build(&TrieConfig::default(), [b"aa".as_slice(), b"cc", b"ee"])?;
        let mut cursor = TrieCursor::new(&trie);
        let result = cursor.seek(b"bb");
        assert_eq!(result, b"cc");
        Ok(())
    }

    #[test]
    fn seek_past_all_keys() -> Result<(), crate::trie::TrieError> {
        let trie = LoudsDsTrie::build(&TrieConfig::default(), [b"aa".as_slice(), b"bb"])?;
        let mut cursor = TrieCursor::new(&trie);
        let result = cursor.seek(b"zz");
        assert_eq!(result, kappa_cursor::TERMINATED);
        Ok(())
    }

    #[test]
    fn seek_backward_is_noop() -> Result<(), crate::trie::TrieError> {
        let trie = LoudsDsTrie::build(&TrieConfig::default(), [b"aa".as_slice(), b"bb", b"cc"])?;
        let mut cursor = TrieCursor::new(&trie);
        cursor.seek(b"bb");
        let result = cursor.seek(b"aa");
        assert_eq!(result, b"bb");
        Ok(())
    }

    #[test]
    fn advance_after_seek() -> Result<(), crate::trie::TrieError> {
        let trie = LoudsDsTrie::build(&TrieConfig::default(), [b"aa".as_slice(), b"bb", b"cc"])?;
        let mut cursor = TrieCursor::new(&trie);
        cursor.seek(b"bb");
        let next = cursor.advance();
        assert_eq!(next, b"cc");
        Ok(())
    }

    #[test]
    fn cursor_matches_sorted_input() -> Result<(), crate::trie::TrieError> {
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for a in 0u8..3 {
            for b in 0u8..5 {
                for c in 0u8..4 {
                    keys.push(vec![a, b, c]);
                }
            }
        }
        keys.sort();
        keys.dedup();
        let trie = LoudsDsTrie::build(
            &TrieConfig {
                cutover_depth: 1,
                ..Default::default()
            },
            keys.iter().map(Vec::as_slice),
        )?;
        let mut cursor = TrieCursor::new(&trie);
        let output = collect_all(&mut cursor);
        assert_eq!(output, keys);
        Ok(())
    }

    #[test]
    fn prefix_key_and_extension() -> Result<(), crate::trie::TrieError> {
        let trie = LoudsDsTrie::build(&TrieConfig::default(), [b"a".as_slice(), b"ab", b"abc"])?;
        let mut cursor = TrieCursor::new(&trie);
        let keys = collect_all(&mut cursor);
        assert_eq!(keys, vec![b"a".to_vec(), b"ab".to_vec(), b"abc".to_vec(),]);
        Ok(())
    }

    #[test]
    fn seek_matches_sorted_lower_bound_across_cutovers() -> Result<(), crate::trie::TrieError> {
        let keys: Vec<Vec<u8>> = vec![
            vec![0],
            vec![0, 0],
            vec![0, 0, 255],
            vec![0, 128],
            vec![1],
            vec![1, 255],
            vec![255],
            vec![255, 0],
            vec![255, 255],
        ];
        let targets: Vec<Vec<u8>> = vec![
            vec![],
            vec![0],
            vec![0, 0, 1],
            vec![0, 0, 255],
            vec![0, 1],
            vec![0, 255],
            vec![1, 0],
            vec![1, 255, 0],
            vec![2],
            vec![255],
            vec![255, 1],
            vec![255, 255, 255],
        ];
        for cutover_depth in 0..=4 {
            let trie = LoudsDsTrie::build(
                &TrieConfig {
                    cutover_depth,
                    ..Default::default()
                },
                keys.iter().map(Vec::as_slice),
            )?;
            for target in &targets {
                let mut cursor = TrieCursor::new(&trie);
                let index = keys.partition_point(|key| key < target);
                let expected = keys
                    .get(index)
                    .map_or(kappa_cursor::TERMINATED, Vec::as_slice);
                assert_eq!(
                    cursor.seek(target),
                    expected,
                    "cutover={cutover_depth}, target={target:?}"
                );
                if index < keys.len() {
                    let next = keys
                        .get(index + 1)
                        .map_or(kappa_cursor::TERMINATED, Vec::as_slice);
                    assert_eq!(
                        cursor.advance(),
                        next,
                        "advance cutover={cutover_depth}, target={target:?}"
                    );
                }
            }
        }
        Ok(())
    }
}
