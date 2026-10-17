use super::{BuildNode, DenseLevel, TrieError};

pub(super) struct DenseEncoding {
    pub levels: Vec<DenseLevel>,
    pub cumulative: Vec<u64>,
    pub mapping: Vec<Vec<u64>>,
    pub terminals: u64,
}

pub(super) fn encode_dense(
    nodes: &[BuildNode],
    order: &[u32],
    ranges: &[std::ops::Range<usize>],
    mapping: &[u32],
) -> Result<DenseEncoding, TrieError> {
    let mut encoded = DenseEncoding {
        levels: Vec::with_capacity(ranges.len()),
        cumulative: Vec::with_capacity(ranges.len()),
        mapping: Vec::with_capacity(ranges.len()),
        terminals: 0,
    };
    for range in ranges {
        let level_nodes = &order[range.clone()];
        let count = level_nodes.len();
        let label_count = count
            .checked_mul(256)
            .ok_or(TrieError::NodeCapacityExceeded)?;
        let mut labels = vec![false; label_count];
        let mut children = Vec::new();
        let mut terminals = vec![false; count];
        let mut bfs = Vec::with_capacity(count);
        for (ordinal, &index) in level_nodes.iter().enumerate() {
            let index = index as usize;
            let node = &nodes[index];
            if node.is_terminal {
                terminals[ordinal] = true;
                encoded.terminals += 1;
            }
            bfs.push(u64::from(mapping[index]));
            for (label, child) in node.children(nodes) {
                labels[ordinal * 256 + usize::from(label)] = true;
                children.push(nodes[child].has_children());
            }
        }
        encoded.levels.push(DenseLevel::new(
            &labels,
            &children,
            &terminals,
            count as u64,
        ));
        encoded.cumulative.push(encoded.terminals);
        encoded.mapping.push(bfs);
    }
    Ok(encoded)
}

pub(super) struct Layout {
    pub bfs_order: Vec<u32>,
    pub level_ranges: Vec<std::ops::Range<usize>>,
    pub naive_to_bfs: Vec<u32>,
    pub parents: Vec<(u32, u8)>,
}

pub(super) fn admit<'a>(
    keys: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(Vec<BuildNode>, u64), TrieError> {
    // Zero is both the root and absent-link sentinel; child coordinates are checked.
    let mut nodes = vec![BuildNode::new(0)];
    let mut key_count = 0;
    let mut prev: Option<&[u8]> = None;
    let mut path = Vec::with_capacity(66);
    path.push(0usize);
    for (i, key) in keys.into_iter().enumerate() {
        if key.len() > 65 {
            return Err(TrieError::KeyTooLong {
                index: i,
                length: key.len(),
            });
        }
        if let Some(p) = prev {
            match key.cmp(p) {
                std::cmp::Ordering::Less => return Err(TrieError::NotSorted { index: i }),
                std::cmp::Ordering::Equal => return Err(TrieError::Duplicate { index: i }),
                std::cmp::Ordering::Greater => {}
            }
        }
        let common = prev.map_or(0, |previous| {
            previous.iter().zip(key).take_while(|(a, b)| a == b).count()
        });
        prev = Some(key);
        key_count += 1;
        path.truncate(common + 1);
        let mut current = path[common];
        for &byte in &key[common..] {
            let new_idx = nodes.len();
            let child = u32::try_from(new_idx).map_err(|_| TrieError::NodeCapacityExceeded)?;
            nodes.push(BuildNode::new(byte));
            let last = nodes[current].last_child;
            if last == 0 {
                nodes[current].first_child = child;
            } else {
                nodes[last as usize].next_sibling = child;
            }
            nodes[current].last_child = child;
            current = new_idx;
            path.push(current);
        }
        nodes[current].is_terminal = true;
    }
    if key_count == 0 {
        return Err(TrieError::Empty);
    }
    Ok((nodes, key_count))
}

pub(super) fn layout(nodes: &[BuildNode]) -> Result<Layout, TrieError> {
    let mut bfs_order = Vec::with_capacity(nodes.len());
    bfs_order.push(0u32);
    let mut level_ranges = Vec::new();
    let mut start = 0;
    let mut end = 1;
    while start < end {
        level_ranges.push(start..end);
        for position in start..end {
            let naive_idx = bfs_order[position] as usize;
            for (_, child_idx) in nodes[naive_idx].children(nodes) {
                bfs_order
                    .push(u32::try_from(child_idx).map_err(|_| TrieError::NodeCapacityExceeded)?);
            }
        }
        start = end;
        end = bfs_order.len();
    }
    let mut naive_to_bfs = vec![0u32; nodes.len()];
    for (bfs_num, &naive_idx) in bfs_order.iter().enumerate() {
        naive_to_bfs[naive_idx as usize] =
            u32::try_from(bfs_num).map_err(|_| TrieError::NodeCapacityExceeded)?;
    }
    let mut parents = vec![(0, 0); bfs_order.len()];
    for &naive_idx in &bfs_order {
        let naive_idx = naive_idx as usize;
        let bfs = naive_to_bfs[naive_idx];
        for (label, child_naive) in nodes[naive_idx].children(nodes) {
            parents[naive_to_bfs[child_naive] as usize] = (bfs, label);
        }
    }
    Ok(Layout {
        bfs_order,
        level_ranges,
        naive_to_bfs,
        parents,
    })
}
