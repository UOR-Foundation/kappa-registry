//! Content preparation for the in-memory backend.
//!
//! Preparation streams the request into a private temporary file in the
//! content cache while hashing under every mandatory axis, outside any
//! writer, checking its byte bound as it reads and its deadline before and
//! after every chunk. Compressed content streams to its file under its
//! storage identity and is then proven by decoding the file through the
//! shared bounded decoder (`kappa_store::compression`) every read of it
//! decodes through: the decoded
//! stream must hash to the claimed identity under every mandatory axis and
//! be exactly the claimed length. The segment digests of the file's bytes,
//! and of a compressed file's decoded bytes, are computed in the same
//! passes (`segments`). Installation only moves files. A
//! prepared value owns its file until installation turns it into an
//! allocation instance (`allocation`) or the value drops, which removes it.
//! Installation, composition and retirement are in `content_install`.

use std::io::{BufReader, Read, Write};
use std::sync::Arc;

use kappa_store::transition::PreparedResource;
use kappa_store::{
    ContentIdentity, ContentPreparation, Kappa, PreparationBounds, PreparedContent, StoreError,
};
use kappa_types::Axis;
use kappa_types::content::{ContentAdmissionEvidence, ContentAdmissionRecord};
use kappa_types::kappa_streaming::streaming_compute_into;

use super::InMemoryStore;
use super::segments::{SegmentHasher, Segments};

/// The compression of prepared content: its algorithm, the identity of the
/// compressed bytes the file holds, and the segment digests of the bytes
/// they decode to.
pub struct Compression {
    pub algorithm: String,
    pub storage: Kappa,
    pub decoded: Segments,
}

/// Content prepared by the in-memory backend: a verified temporary file in
/// the content cache and the segment digests of its bytes.
pub struct MemoryPrepared {
    pub(crate) identity: Kappa,
    pub(crate) aliases: Vec<Kappa>,
    pub(crate) total_size: u64,
    pub(crate) file: tempfile::NamedTempFile,
    pub(crate) segments: Segments,
    pub(crate) compression: Option<Compression>,
    pub(crate) owner: Arc<dyn Send + Sync>,
}

impl MemoryPrepared {
    pub(crate) fn validate_owner(&self, store: &InMemoryStore) -> Result<(), StoreError> {
        if !Arc::ptr_eq(&self.owner, &store.allocations.preparation_owner()) {
            return Err(StoreError::Rejected(
                "content was prepared by another store instance".into(),
            ));
        }
        Ok(())
    }
}

/// Prepared content installs only into the store that prepared it, under
/// the admission of its canonical holder (`canonical_order`) at its size.
impl PreparedResource for Box<MemoryPrepared> {
    type Context = InMemoryStore;

    fn validate_admission(
        &self,
        record: &ContentAdmissionRecord,
        store: &InMemoryStore,
    ) -> Result<(), StoreError> {
        self.validate_owner(store)?;
        let admission = record.admission();
        let holder = std::iter::once(&self.identity)
            .chain(self.aliases.iter())
            .min_by_key(|identity| identity.axis().discriminant());
        if holder != Some(admission.identity())
            || self.total_size != admission.logical_size()
            || !matches!(record.evidence(), ContentAdmissionEvidence::VerifiedBytes)
        {
            return Err(StoreError::Rejected(
                "prepared content differs from its admission".into(),
            ));
        }
        Ok(())
    }
}

/// What streaming a request into a staging file produced.
struct Staged {
    identity: Kappa,
    aliases: Vec<Kappa>,
    size: u64,
    file: tempfile::NamedTempFile,
    segments: Segments,
}

impl PreparedContent for MemoryPrepared {
    fn identity(&self) -> &Kappa {
        &self.identity
    }
    fn aliases(&self) -> &[Kappa] {
        &self.aliases
    }
    fn total_size(&self) -> u64 {
        self.total_size
    }
    fn etag(&self) -> Option<&str> {
        None
    }
    fn as_any(self: Box<Self>) -> Box<dyn std::any::Any + Send> {
        self
    }
}

impl InMemoryStore {
    /// `primary` followed by every other mandatory axis.
    pub(crate) fn axes_for(&self, primary: Axis) -> Vec<Axis> {
        let mut axes = vec![primary];
        for axis in kappa_store::BlobStore::mandatory_axes(self) {
            if !axes.contains(&axis) {
                axes.push(axis);
            }
        }
        axes
    }

    /// Stream `reader` into a staging file, hashing under `axes` and into
    /// segment digests, within `bounds`.
    fn stream(
        &self,
        axes: &[Axis],
        reader: &mut dyn Read,
        bounds: &PreparationBounds,
    ) -> Result<Staged, StoreError> {
        let mut file = self.allocations.staging_file()?;
        let mut segments = SegmentHasher::default();
        let mut buffer = [0u8; 16384];
        let (proof, size) = streaming_compute_into(
            axes,
            reader,
            &mut buffer,
            bounds.maximum,
            |chunk| -> Result<(), StoreError> {
                within_deadline(bounds)?;
                file.write_all(chunk)?;
                segments.update(chunk);
                Ok(())
            },
        )?;
        within_deadline(bounds)?;
        Ok(Staged {
            identity: proof.kappa().clone(),
            aliases: proof.additional().iter().map(|(_, k)| k.clone()).collect(),
            size,
            file,
            segments: segments.finish(),
        })
    }

    /// Stream compressed input into a staging file under its storage
    /// identity, then prove it by decoding the file: the decoded bytes must
    /// hash to `identity` and be exactly `size` long. Returns the verified
    /// identities of the decoded content, the compression, and the staged
    /// compressed file.
    fn stream_compressed(
        &self,
        identity: &Kappa,
        algorithm: &str,
        size: u64,
        reader: &mut dyn Read,
        bounds: &PreparationBounds,
    ) -> Result<(Vec<Kappa>, Compression, Staged), StoreError> {
        let mut stored = self.stream(&[Axis::Sha256], reader, bounds)?;
        stored.file.as_file_mut().flush()?;
        let mut decoded = kappa_store::compression::Codec::of(algorithm)?
            .decoder(BufReader::new(stored.file.reopen()?))?;
        let mut decoded_segments = SegmentHasher::default();
        let mut buffer = [0u8; 16384];
        let (proof, decoded_size) = streaming_compute_into(
            &self.axes_for(identity.axis()),
            &mut decoded,
            &mut buffer,
            size,
            |chunk| -> Result<(), StoreError> {
                within_deadline(bounds)?;
                decoded_segments.update(chunk);
                Ok(())
            },
        )?;
        drop(decoded);
        within_deadline(bounds)?;
        if proof.kappa() != identity || decoded_size != size {
            return Err(StoreError::Rejected(format!(
                "compressed content decodes to {} ({decoded_size} bytes), not {identity} ({size} bytes)",
                proof.kappa()
            )));
        }
        let aliases = proof.additional().iter().map(|(_, k)| k.clone()).collect();
        Ok((
            aliases,
            Compression {
                algorithm: algorithm.to_owned(),
                storage: stored.identity.clone(),
                decoded: decoded_segments.finish(),
            },
            stored,
        ))
    }
}

/// Refuse further preparation work once the deadline has passed. A
/// blocking read of the caller's input cannot be interrupted; the deadline
/// is checked before and after each chunk of work instead.
fn within_deadline(bounds: &PreparationBounds) -> Result<(), StoreError> {
    if std::time::Instant::now() > bounds.deadline {
        return Err(StoreError::Rejected(
            "content preparation passed its deadline".into(),
        ));
    }
    Ok(())
}

impl ContentPreparation for InMemoryStore {
    fn prepare_content(
        &self,
        identity: ContentIdentity,
        reader: &mut dyn Read,
        bounds: PreparationBounds,
    ) -> Result<Box<dyn PreparedContent>, StoreError> {
        within_deadline(&bounds)?;
        let prepared = match identity {
            ContentIdentity::Verified(expected) => {
                let staged = self.stream(&self.axes_for(expected.axis()), reader, &bounds)?;
                if staged.identity != expected {
                    return Err(StoreError::Rejected(format!(
                        "digest mismatch: expected {expected}, computed {}",
                        staged.identity
                    )));
                }
                MemoryPrepared {
                    owner: self.allocations.preparation_owner(),
                    identity: expected,
                    aliases: staged.aliases,
                    total_size: staged.size,
                    file: staged.file,
                    segments: staged.segments,
                    compression: None,
                }
            }
            ContentIdentity::Computed(axis) => {
                let staged = self.stream(&self.axes_for(axis), reader, &bounds)?;
                MemoryPrepared {
                    owner: self.allocations.preparation_owner(),
                    identity: staged.identity,
                    aliases: staged.aliases,
                    total_size: staged.size,
                    file: staged.file,
                    segments: staged.segments,
                    compression: None,
                }
            }
            ContentIdentity::Compressed {
                identity,
                algorithm,
                uncompressed_size,
            } => {
                let (aliases, compression, stored) = self.stream_compressed(
                    &identity,
                    &algorithm,
                    uncompressed_size,
                    reader,
                    &bounds,
                )?;
                MemoryPrepared {
                    owner: self.allocations.preparation_owner(),
                    identity,
                    aliases,
                    total_size: uncompressed_size,
                    file: stored.file,
                    segments: stored.segments,
                    compression: Some(compression),
                }
            }
        };
        Ok(Box::new(prepared))
    }
}

/// Order verified identities of the same bytes canonically: the holder is
/// the identity with the lowest axis discriminant; the rest alias it.
pub fn canonical_order(identity: Kappa, aliases: Vec<Kappa>) -> (Kappa, Vec<Kappa>) {
    let mut all: Vec<Kappa> = std::iter::once(identity).chain(aliases).collect();
    all.sort_by_key(|k| k.axis().discriminant());
    all.dedup();
    let holder = all.remove(0);
    (holder, all)
}
