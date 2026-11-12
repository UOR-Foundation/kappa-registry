//! Per-chunk integrity of external allocations in unencrypted stores,
//! verified at use against the epoch-committed [`ContentCommitment`].
//!
//! The commitment's root is `merkle_root` over the SHA-256 digest of each
//! plaintext chunk. The `.chunks` sidecar of an allocation is the node
//! array of exactly that tree in emission order (`merkle::StreamingTree`):
//! 32 bytes per node, `merkle::node_count(chunks)` nodes. The writer
//! streams nodes as chunks arrive with one pending node per set bit of the
//! chunk count and never reads the file back. A reader verifies chunk `i`
//! by computing its leaf from the delivered plaintext, resolving
//! `merkle::audit_path(i, chunks)` with O(log chunks) positional 32-byte
//! reads, and calling `merkle_verify` against the committed root. No
//! stored digest is ever trusted, so there is nothing to cache and no
//! interval between verification and use.
//!
//! The reader takes the commitment itself, not a root, and checks that it
//! names the identity and chunk size being read: the caller obtains it
//! from the ledger of the epoch that published the content
//! ([`crate::content_install`] records it; [`crate::content_read`]
//! resolves it through the signed epoch). Encrypted and plaintext stores
//! keep the sidecar alike, so one verified-reader contract covers both:
//! an AEAD tag under the store key proves the store wrote the bytes, not
//! that they are the committed content.

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use kappa_types::merkle::{self, PathStep, StreamingTree};
use kappa_types::work::{Dimension, Meter};
use kappa_types::{ContentCommitment, StoreError};

use crate::representation::AllocationId;

const NODE: u64 = 32;

/// Sidecar writer: streams the tree nodes of the chunk digests.
pub struct ChunkListWriter {
    file: BufWriter<File>,
    tree: Option<StreamingTree>,
}

impl ChunkListWriter {
    pub(crate) fn create(blob_root: &Path, allocation: &AllocationId) -> Result<Self, StoreError> {
        let file = crate::allocation::private_create_new()
            .open(crate::allocation::chunk_list_path(blob_root, allocation))?;
        Ok(Self {
            file: BufWriter::with_capacity(64 * 1024, file),
            tree: Some(StreamingTree::new()),
        })
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<(), StoreError> {
        let tree = self.tree.take().ok_or_else(|| {
            StoreError::Internal("chunk list writer failed during emission".into())
        })?;
        let file = &mut self.file;
        self.tree = Some(tree.push(&kappa_types::sha256_raw(chunk), |_, node| {
            file.write_all(node).map_err(StoreError::Io)
        })?);
        Ok(())
    }

    /// Finish: flush and return the root and chunk count. The file is
    /// closed; durability is the batch's.
    pub(crate) fn finish(mut self) -> Result<([u8; 32], u64), StoreError> {
        let tree = self.tree.take().ok_or_else(|| {
            StoreError::Internal("cannot finish a failed chunk list writer".into())
        })?;
        self.file.flush()?;
        let file = self
            .file
            .into_inner()
            .map_err(std::io::IntoInnerError::into_error)?;
        drop(file);
        Ok((tree.root(), tree.leaves()))
    }
}

/// Sidecar reader bound to an epoch-committed commitment.
pub struct ChunkList {
    file: File,
    chunk_count: u64,
    root: [u8; 32],
}

impl ChunkList {
    /// Open the sidecar of the allocation holding `identity` in
    /// `chunk_count` chunks of `chunk_size`, under the `commitment` the
    /// caller resolved from authenticated epoch state. The commitment must
    /// name this identity and this chunk size; the file length must match
    /// the node count exactly.
    pub(crate) fn open(
        blob_root: &Path,
        allocation: &AllocationId,
        identity: &kappa_types::Kappa,
        chunk_size: u32,
        chunk_count: u32,
        commitment: &ContentCommitment,
    ) -> Result<Self, StoreError> {
        if commitment.identity() != identity {
            return Err(StoreError::Internal(format!(
                "commitment names {} not {identity}",
                commitment.identity()
            )));
        }
        if commitment.chunk_size() != chunk_size {
            return Err(StoreError::Internal(format!(
                "commitment chunk size {} disagrees with the row's {chunk_size}",
                commitment.chunk_size()
            )));
        }
        let chunk_count = u64::from(chunk_count);
        let file = File::open(crate::allocation::chunk_list_path(blob_root, allocation))?;
        let expected_len = merkle::node_count(chunk_count) * NODE;
        let actual_len = file.metadata()?.len();
        if actual_len != expected_len {
            return Err(StoreError::Internal(format!(
                "chunk list of {actual_len} bytes disagrees with {chunk_count} chunks"
            )));
        }
        Ok(Self {
            file,
            chunk_count,
            root: *commitment.chunk_root(),
        })
    }

    /// The stored node at `position`, its examination and read charged to
    /// `work` before the read.
    fn node_at(&mut self, position: u64, work: &mut dyn Meter) -> Result<[u8; 32], StoreError> {
        work.charge_all(&[(Dimension::Entries, 1), (Dimension::BytesRead, NODE)])?;
        let mut node = [0u8; 32];
        self.file.seek(SeekFrom::Start(position * NODE))?;
        self.file.read_exact(&mut node)?;
        Ok(node)
    }

    /// Verify `plaintext` as chunk `index` against the committed root, on
    /// `work`. Before the path is computed, its buffers are charged at their
    /// bound for this tree: one mountain per set bit of the chunk count,
    /// and at most one step per level below the tallest mountain plus one
    /// per mountain. Once the path is known, and before any node is read,
    /// every hash the verification computes is charged: the leaf digest,
    /// the leaf and each proof step, and the bag of the right peaks. Each
    /// stored node is then charged as it is read.
    pub(crate) fn verify(
        &mut self,
        index: u32,
        plaintext: &[u8],
        work: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let index = u64::from(index);
        let mountains = u64::from(self.chunk_count.count_ones());
        let height = u64::from(u64::BITS - 1 - self.chunk_count.max(1).leading_zeros());
        let steps = height + 1 + mountains;
        // The path grows by doubling from four elements.
        let path_bytes = mountains * size_of::<(u32, u64)>() as u64
            + (2 * steps).max(4) * size_of::<PathStep>() as u64
            + mountains * size_of::<u64>() as u64;
        work.charge(Dimension::BytesAllocated, path_bytes)?;
        let path = merkle::audit_path(index, self.chunk_count)
            .ok_or_else(|| StoreError::Internal("chunk index out of range".into()))?;
        let peaks = path
            .iter()
            .map(|step| match step {
                PathStep::RightPeaks { positions } => positions.len() as u64,
                PathStep::Sibling { .. } => 0,
            })
            .sum::<u64>();
        let proof_steps = path.len() as u64;
        work.charge_all(&[
            (Dimension::BytesHashed, plaintext.len() as u64),
            (
                Dimension::BytesHashed,
                32 + merkle::LEAF_HASH_OVERHEAD + proof_steps * merkle::NODE_HASH_INPUT,
            ),
            (
                Dimension::BytesHashed,
                peaks.saturating_sub(1) * merkle::NODE_HASH_INPUT,
            ),
            (
                Dimension::BytesAllocated,
                proof_steps * size_of::<([u8; 32], bool)>() as u64 + peaks * NODE,
            ),
        ])?;
        let mut proof = Vec::with_capacity(path.len());
        for step in path {
            match step {
                PathStep::Sibling { position, left } => {
                    proof.push((self.node_at(position, work)?, left));
                }
                PathStep::RightPeaks { positions } => {
                    let mut peaks = Vec::with_capacity(positions.len());
                    for position in positions {
                        peaks.push(self.node_at(position, work)?);
                    }
                    let bag = merkle::bag_peaks(&peaks)
                        .ok_or_else(|| StoreError::Internal("empty peak bag".into()))?;
                    proof.push((bag, false));
                }
            }
        }
        if !merkle::merkle_verify(&self.root, &kappa_types::sha256_raw(plaintext), &proof) {
            return Err(StoreError::Internal(format!(
                "chunk {index} disagrees with the committed chunk root"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_types::Kappa;
    use kappa_types::merkle::merkle_root;
    use kappa_types::work::{WorkExhausted, WorkLimit, WorkMeter};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Verification of `chunk` as `index` with no limit on any dimension:
    /// these tests examine the proof, not the allowance.
    fn verify(list: &mut ChunkList, index: u32, chunk: &[u8]) -> Result<(), StoreError> {
        list.verify(index, chunk, &mut WorkMeter::unbounded())
    }

    /// Hashing is charged before any stored node is read: an allowance one
    /// byte short of the hashing refuses with nothing read, and the same
    /// verification within the allowance reads its path and verifies.
    #[test]
    fn verification_is_refused_before_any_node_is_read() -> TestResult {
        let chunks: Vec<Vec<u8>> = (0..600u32).map(|i| vec![(i % 251) as u8; 50]).collect();
        let (dir, allocation, commitment) = allocation_with(&chunks)?;
        let mut list = open(&dir, &allocation, 600, &commitment)?;
        let mut measured = WorkMeter::unbounded();
        list.verify(300, &chunks[300], &mut measured)?;
        let hashed = measured.used().get(Dimension::BytesHashed);
        assert!(measured.used().get(Dimension::BytesRead) >= 32);
        let mut short =
            WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesHashed, hashed - 1));
        match list.verify(300, &chunks[300], &mut short) {
            Err(StoreError::WorkRefused(WorkExhausted::Limit {
                dimension: Dimension::BytesHashed,
                ..
            })) => {}
            other => panic!("expected a BytesHashed refusal, got {other:?}"),
        }
        assert_eq!(
            short.used().get(Dimension::BytesRead),
            0,
            "no node was read"
        );
        assert_eq!(
            short.used().get(Dimension::Entries),
            0,
            "no node was examined"
        );
        let mut exact = WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesHashed, hashed));
        list.verify(300, &chunks[300], &mut exact)?;
        Ok(())
    }

    fn allocation_with(
        chunks: &[Vec<u8>],
    ) -> Result<(tempfile::TempDir, AllocationId, ContentCommitment), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        crate::allocation::precreate_shards(dir.path())?;
        let allocation = AllocationId::generate()?;
        let mut writer = ChunkListWriter::create(dir.path(), &allocation)?;
        for chunk in chunks {
            writer.push(chunk)?;
        }
        let (root, count) = writer.finish()?;
        assert_eq!(count, chunks.len() as u64);
        let commitment = ContentCommitment::new(identity(), 50, root)?;
        Ok((dir, allocation, commitment))
    }

    fn identity() -> Kappa {
        Kappa::sha256(b"identity")
    }

    fn open(
        dir: &tempfile::TempDir,
        allocation: &AllocationId,
        count: u32,
        commitment: &ContentCommitment,
    ) -> Result<ChunkList, StoreError> {
        ChunkList::open(dir.path(), allocation, &identity(), 50, count, commitment)
    }

    #[test]
    fn root_is_merkle_root_over_chunk_digests() -> TestResult {
        for chunks in [1u64, 2, 3, 255, 256, 257, 1280] {
            let data: Vec<Vec<u8>> = (0..chunks).map(|i| i.to_le_bytes().to_vec()).collect();
            let (_dir, _allocation, commitment) = allocation_with(&data)?;
            let digests: Vec<[u8; 32]> = data.iter().map(|c| kappa_types::sha256_raw(c)).collect();
            let leaves: Vec<&[u8]> = digests.iter().map(<[u8; 32]>::as_slice).collect();
            assert_eq!(
                commitment.chunk_root(),
                &merkle_root(&leaves),
                "{chunks} chunks"
            );
        }
        Ok(())
    }

    #[test]
    fn chunks_verify_and_alteration_after_open_is_refused() -> TestResult {
        let chunks: Vec<Vec<u8>> = (0..600u32).map(|i| vec![(i % 251) as u8; 50]).collect();
        let (dir, allocation, commitment) = allocation_with(&chunks)?;
        let mut list = open(&dir, &allocation, 600, &commitment)?;
        for index in [0u32, 1, 255, 256, 257, 511, 512, 599] {
            verify(&mut list, index, &chunks[index as usize])?;
        }
        assert!(verify(&mut list, 3, &chunks[4]).is_err());
        assert!(verify(&mut list, 600, &chunks[0]).is_err());
        assert!(open(&dir, &allocation, 599, &commitment).is_err());
        // Correspondence: a commitment for another identity or chunk size
        // is refused before any byte is read.
        let other = ContentCommitment::new(Kappa::sha256(b"other"), 50, *commitment.chunk_root())?;
        assert!(open(&dir, &allocation, 600, &other).is_err());
        let resized = ContentCommitment::new(identity(), 51, *commitment.chunk_root())?;
        assert!(open(&dir, &allocation, 600, &resized).is_err());
        // Replace the leaf node of chunk 300 with the leaf of forged
        // plaintext after the reader opened: the forged proof no longer
        // folds to the committed root, through either reader.
        let path = crate::allocation::chunk_list_path(dir.path(), &allocation);
        let mut bytes = std::fs::read(&path)?;
        let forged = vec![9u8; 50];
        let position = usize::try_from(merkle::node_position(0, 300) * NODE)?;
        bytes[position..position + 32]
            .copy_from_slice(&merkle::hash_leaf(&kappa_types::sha256_raw(&forged)));
        std::fs::write(&path, &bytes)?;
        let mut fresh = open(&dir, &allocation, 600, &commitment)?;
        assert!(verify(&mut fresh, 300, &forged).is_err());
        assert!(
            verify(&mut list, 300, &forged).is_err(),
            "open reader accepted forgery"
        );
        // The genuine chunk 300 still verifies: its leaf is computed from
        // the plaintext, and its siblings are untouched.
        verify(&mut list, 300, &chunks[300])?;
        Ok(())
    }

    #[test]
    fn a_wrong_commitment_rejects_every_chunk() -> TestResult {
        let chunks: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 10]).collect();
        let (dir, allocation, _commitment) = allocation_with(&chunks)?;
        let wrong = ContentCommitment::new(identity(), 50, [7; 32])?;
        let mut list = open(&dir, &allocation, 3, &wrong)?;
        for (index, chunk) in (0u32..).zip(&chunks) {
            assert!(verify(&mut list, index, chunk).is_err());
        }
        Ok(())
    }
}
