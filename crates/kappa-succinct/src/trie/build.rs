use super::{DenseLevel, LoudsDsTrie, SparseLevel, TrieConfig, TrieError};

// One range per prefix in the active level, rather than one arena node per
// prefix byte across all levels. Ranges borrow the admitted sorted input.
struct Prefix {
    start: usize,
    end: usize,
    parent: u32,
    label: u8,
}

impl Prefix {
    const fn root(end: usize) -> Self {
        Self {
            start: 0,
            end,
            parent: 0,
            label: 0,
        }
    }
}

struct BuiltLevels {
    parents: Vec<(u32, u8)>,
    dense_levels: Vec<DenseLevel>,
    dense_node_to_bfs: Vec<Vec<u64>>,
    dense_terminal_cumulative: Vec<u64>,
    running_terminals: u64,
    sparse_pos_to_bfs: Vec<u64>,
    labels: Vec<u8>,
    children: Vec<bool>,
    louds: Vec<bool>,
    terminals: Vec<bool>,
}

fn validate_keys(keys: &[&[u8]]) -> Result<(), TrieError> {
    if keys.is_empty() {
        return Err(TrieError::Empty);
    }
    for (index, key) in keys.iter().enumerate() {
        if key.len() > 65 {
            return Err(TrieError::KeyTooLong {
                index,
                length: key.len(),
            });
        }
        if index != 0 {
            match keys[index - 1].cmp(key) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Err(TrieError::Duplicate { index }),
                std::cmp::Ordering::Greater => return Err(TrieError::NotSorted { index }),
            }
        }
    }
    Ok(())
}

fn next_level_base(base: usize, count: usize) -> Result<usize, TrieError> {
    let next = base
        .checked_add(count)
        .ok_or(TrieError::NodeCapacityExceeded)?;
    u32::try_from(next).map_err(|_| TrieError::NodeCapacityExceeded)?;
    Ok(next)
}

fn dense_bit_buffers(dense: bool, count: usize) -> Result<(Vec<bool>, Vec<bool>), TrieError> {
    if !dense {
        return Ok((Vec::new(), Vec::new()));
    }
    let labels = count
        .checked_mul(256)
        .ok_or(TrieError::NodeCapacityExceeded)?;
    Ok((vec![false; labels], vec![false; count]))
}

impl LoudsDsTrie {
    pub fn build<'a, I>(config: &TrieConfig, keys: I) -> Result<Self, TrieError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let keys: Vec<_> = keys.into_iter().collect();
        validate_keys(&keys)?;
        let mut current = vec![Prefix::root(keys.len())];
        let mut parents = Vec::new();
        let mut dense_levels = Vec::new();
        let mut dense_node_to_bfs = Vec::new();
        let mut dense_terminal_cumulative = Vec::new();
        let mut running_terminals = 0;
        let mut sparse_pos_to_bfs = Vec::new();
        let mut labels = Vec::new();
        let mut children = Vec::new();
        let mut louds = Vec::new();
        let mut terminals = Vec::new();
        let mut depth = 0;
        while !current.is_empty() {
            let base = parents.len();
            let next_base = next_level_base(base, current.len())?;
            parents.extend(current.iter().map(|node| (node.parent, node.label)));
            let dense = depth < usize::from(config.cutover_depth);
            let (mut dense_labels, mut dense_terminals) = dense_bit_buffers(dense, current.len())?;
            let mut dense_children = Vec::new();
            let mut next = Vec::new();
            for (ordinal, node) in current.iter().enumerate() {
                let bfs =
                    u32::try_from(base + ordinal).map_err(|_| TrieError::NodeCapacityExceeded)?;
                let terminal = keys[node.start].len() == depth;
                let start = node.start + usize::from(terminal);
                let has_children = start < node.end;
                if dense {
                    dense_terminals[ordinal] = terminal;
                    running_terminals += u64::from(terminal);
                } else if terminal {
                    // Preserve the canonical prefix/leaf marker positions.
                    labels.push(0xff);
                    children.push(false);
                    louds.push(true);
                    terminals.push(has_children || depth == usize::from(config.cutover_depth));
                    sparse_pos_to_bfs.push(u64::from(bfs));
                }
                let mut position = start;
                let mut first = !terminal;
                while position < node.end {
                    let label = keys[position][depth];
                    let mut end = position + 1;
                    while end < node.end && keys[end][depth] == label {
                        end += 1;
                    }
                    let child_terminal = keys[position].len() == depth + 1;
                    let child_internal = !child_terminal || position + 1 < end;
                    let child_bfs = u32::try_from(next_base + next.len())
                        .map_err(|_| TrieError::NodeCapacityExceeded)?;
                    if dense {
                        dense_labels[ordinal * 256 + usize::from(label)] = true;
                        dense_children.push(child_internal);
                    } else {
                        labels.push(label);
                        children.push(child_internal);
                        louds.push(first);
                        terminals.push(child_terminal && !child_internal);
                        sparse_pos_to_bfs.push(u64::from(child_bfs));
                        first = false;
                    }
                    next.push(Prefix {
                        start: position,
                        end,
                        parent: bfs,
                        label,
                    });
                    position = end;
                }
            }
            if dense {
                dense_levels.push(DenseLevel::new(
                    &dense_labels,
                    &dense_children,
                    &dense_terminals,
                    current.len() as u64,
                ));
                dense_node_to_bfs.push((base as u64..next_base as u64).collect());
                dense_terminal_cumulative.push(running_terminals);
            }
            current = next;
            depth += 1;
        }
        BuiltLevels {
            parents,
            dense_levels,
            dense_node_to_bfs,
            dense_terminal_cumulative,
            running_terminals,
            sparse_pos_to_bfs,
            labels,
            children,
            louds,
            terminals,
        }
        .finish(config.cutover_depth, keys.len() as u64)
    }
}

impl BuiltLevels {
    fn finish(self, cutover_depth: u8, key_count: u64) -> Result<LoudsDsTrie, TrieError> {
        let Self {
            parents,
            dense_levels,
            dense_node_to_bfs,
            dense_terminal_cumulative,
            running_terminals,
            mut sparse_pos_to_bfs,
            mut labels,
            mut children,
            mut louds,
            mut terminals,
        } = self;
        if labels.is_empty() {
            labels.push(0);
            children.push(false);
            louds.push(true);
            terminals.push(false);
            sparse_pos_to_bfs.push(0);
        }
        let sparse = SparseLevel::new(labels, &children, &louds, &terminals);
        drop(children);
        drop(louds);
        drop(terminals);
        let total_nodes = parents.len() as u64;
        let node_count_dense = dense_levels.iter().map(DenseLevel::node_count).sum();
        let sparse_child_offset = dense_levels
            .iter()
            .map(DenseLevel::internal_child_count)
            .sum();
        let mut trie = LoudsDsTrie {
            dense_levels,
            sparse,
            cutover_depth,
            key_count,
            digest: [0; 32],
            dense_terminal_cumulative,
            total_dense_terminals: running_terminals,
            sparse_child_offset,
            dense_node_to_bfs,
            sparse_pos_to_bfs,
            parents,
            total_nodes,
            node_count_dense,
        };
        trie.digest = trie
            .serialized_digest()
            .map_err(|error| TrieError::SerializationFailed {
                reason: error.to_string(),
            })?;
        Ok(trie)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trie::sha256_bytes;

    #[test]
    fn level_emission_matches_arena_canonical_bytes() -> Result<(), TrieError> {
        let mut keys = vec![Vec::new(), vec![0], vec![0, 255], vec![255], vec![255, 0]];
        for seed in 0..512u64 {
            let digest = sha256_bytes(&seed.to_be_bytes());
            keys.push(digest.to_vec());
            keys.push(digest[..3].to_vec());
            let mut long = digest.to_vec();
            long.extend_from_slice(&digest);
            long.push(seed.to_le_bytes()[0]);
            keys.push(long);
        }
        keys.sort_unstable();
        keys.dedup();
        for cutover_depth in [0, 1, 2, 3] {
            let config = TrieConfig {
                cutover_depth,
                ..Default::default()
            };
            let expected = LoudsDsTrie::build_reference(&config, keys.iter().map(Vec::as_slice))?;
            let actual = LoudsDsTrie::build(&config, keys.iter().map(Vec::as_slice))?;
            assert_eq!(
                actual.serialize()?,
                expected.serialize()?,
                "cutover {cutover_depth}"
            );
            assert_eq!(actual.digest(), expected.digest());
            for key in &keys {
                assert_eq!(actual.ordinal(key), expected.ordinal(key));
            }
        }
        Ok(())
    }
}
