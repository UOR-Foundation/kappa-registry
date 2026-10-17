use fid_rs::Fid;

/// Packed word index. Inclusive rank uses one prefix lookup and popcount;
/// one-based select searches word prefixes, then selects within one word.
/// Neither query allocates or constructs temporary bit vectors.
pub(crate) struct WordIndex {
    words: Vec<u64>,
    prefixes: Vec<u64>,
    len: u64,
}

impl WordIndex {
    pub(crate) fn from(bits: &[bool]) -> Self {
        let mut words = vec![0u64; bits.len().div_ceil(64)];
        for (position, &set) in bits.iter().enumerate() {
            if set {
                words[position / 64] |= 1u64 << (position % 64);
            }
        }
        let mut prefixes = Vec::with_capacity(words.len() + 1);
        prefixes.push(0);
        for &word in &words {
            prefixes.push(prefixes.last().copied().unwrap_or(0) + u64::from(word.count_ones()));
        }
        Self {
            words,
            prefixes,
            len: bits.len() as u64,
        }
    }

    pub(crate) const fn len(&self) -> u64 {
        self.len
    }

    pub(crate) fn rank(&self, position: u64) -> u64 {
        assert!(position < self.len, "rank position outside bit index");
        // position is bounded by a bit slice whose length fits usize.
        let word = usize::try_from(position / 64)
            .unwrap_or_else(|_| unreachable!("word index fits its allocated vector"));
        let shift = 63 - (position % 64);
        self.prefixes[word] + u64::from((self.words[word] << shift).count_ones())
    }

    pub(crate) fn select(&self, rank: u64) -> Option<u64> {
        if rank == 0 || rank > *self.prefixes.last()? {
            return None;
        }
        let word = self.prefixes.partition_point(|&prefix| prefix < rank) - 1;
        let mut bits = self.words[word];
        for _ in 1..rank - self.prefixes[word] {
            bits &= bits - 1;
        }
        Some(word as u64 * 64 + u64::from(bits.trailing_zeros()))
    }
}

impl std::ops::Index<u64> for WordIndex {
    type Output = bool;
    fn index(&self, position: u64) -> &bool {
        assert!(position < self.len, "position outside bit index");
        // position is bounded by the original usize-sized bit slice.
        let word = usize::try_from(position / 64)
            .unwrap_or_else(|_| unreachable!("word index fits its allocated vector"));
        if self.words[word] & (1u64 << (position % 64)) != 0 {
            &true
        } else {
            &false
        }
    }
}

/// select0 via binary search on rank0.
/// rank0(pos) = pos + 1 - rank1(pos).
/// O(log n) per call. No additional memory.
pub fn select0_binary(fid: &Fid, i: u64) -> Option<u64> {
    let n = fid.len();
    if n == 0 {
        return None;
    }
    let mut lo = 0u64;
    let mut hi = n;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let rank0_mid = mid + 1 - fid.rank(mid);
        if rank0_mid <= i {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo >= n {
        return None;
    }
    let rank0_lo = lo + 1 - fid.rank(lo);
    if rank0_lo == i + 1 { Some(lo) } else { None }
}

/// Select0 via a second Fid over the complemented bit vector.
/// fid-rs implements select using binary search, so this is O(log n).
/// Storage includes a second bit vector and its rank metadata.
pub struct ComplementFid {
    complement: Fid,
}

impl ComplementFid {
    pub fn new(original_bits: &[bool]) -> Self {
        let inverted: Vec<bool> = original_bits.iter().map(|b| !b).collect();
        Self {
            complement: Fid::from(inverted.as_slice()),
        }
    }

    /// Position of the i-th 0-bit (0-indexed) in the original.
    pub fn select0(&self, i: u64) -> Option<u64> {
        self.complement.select(i.checked_add(1)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_index_matches_independent_rank_select_oracle() {
        for length in [0, 1, 63, 64, 65, 511, 512, 513, 4097] {
            for stride in [1, 2, 7, 64, 509] {
                let bits: Vec<_> = (0..length).map(|position| position % stride == 0).collect();
                let index = WordIndex::from(&bits);
                let positions: Vec<_> = bits
                    .iter()
                    .enumerate()
                    .filter_map(|(position, &set)| set.then_some(position as u64))
                    .collect();
                for position in 0..length {
                    assert_eq!(index[position as u64], bits[position]);
                    assert_eq!(
                        index.rank(position as u64),
                        positions
                            .iter()
                            .filter(|&&set| set <= position as u64)
                            .count() as u64
                    );
                }
                assert_eq!(index.select(0), None);
                for (rank, &position) in positions.iter().enumerate() {
                    assert_eq!(index.select(rank as u64 + 1), Some(position));
                }
                assert_eq!(index.select(positions.len() as u64 + 1), None);
                assert_eq!(index.select(u64::MAX), None);
            }
        }
    }

    #[test]
    fn select0_binary_finds_zeros() {
        let bits = vec![true, false, true, true, false, true, false];
        let fid = Fid::from(bits.as_slice());
        assert_eq!(select0_binary(&fid, 0), Some(1));
        assert_eq!(select0_binary(&fid, 1), Some(4));
        assert_eq!(select0_binary(&fid, 2), Some(6));
        assert_eq!(select0_binary(&fid, 3), None);
    }

    #[test]
    fn select0_binary_all_ones() {
        let bits = vec![true; 10];
        let fid = Fid::from(bits.as_slice());
        assert_eq!(select0_binary(&fid, 0), None);
    }

    #[test]
    fn select0_binary_all_zeros() {
        let bits = vec![false; 5];
        let fid = Fid::from(bits.as_slice());
        assert_eq!(select0_binary(&fid, 0), Some(0));
        assert_eq!(select0_binary(&fid, 4), Some(4));
        assert_eq!(select0_binary(&fid, 5), None);
    }

    #[test]
    fn complement_fid_matches_binary() {
        let bits = vec![true, false, true, true, false, true, false];
        let fid = Fid::from(bits.as_slice());
        let comp = ComplementFid::new(&bits);
        for i in 0u64..3 {
            assert_eq!(
                select0_binary(&fid, i),
                comp.select0(i),
                "mismatch at i={i}",
            );
        }
    }

    #[test]
    fn complement_fid_large() {
        let mut bits = vec![true; 10_000];
        for i in (0..10_000).step_by(7) {
            bits[i] = false;
        }
        let fid = Fid::from(bits.as_slice());
        let comp = ComplementFid::new(&bits);
        let zero_count = bits.iter().filter(|b| !**b).count() as u64;
        for i in 0..zero_count {
            assert_eq!(
                select0_binary(&fid, i),
                comp.select0(i),
                "mismatch at i={i}",
            );
        }
    }
}
