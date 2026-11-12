//! Verified representation preparation without a database writer.

use std::fs::File;
use std::io::{Read, Write};
use std::time::Instant;

use kappa_store::BlobStore;
use kappa_types::{Axis, Kappa, StoreError, StreamingVerificationProof, streaming_compute_into};

use crate::PersistentStore;
use crate::chunk_integrity::ChunkListWriter;
use crate::content_install::PreparedContent;
use crate::durability::{Capability, DurabilityOutcome};
use crate::representation::{AllocationId, BlobRecord, Compression, ExternalLayout};

/// The encryption context is independent of digest aliases. Position and
/// allocation incarnation are authenticated for each physical frame.
pub fn frame_context(publication: &[u8; 32], ordinal: u32) -> String {
    format!("kappa/content/frame/{}/{ordinal}", hex::encode(publication))
}

/// What one preparation admits: the axes it digests under, the identity
/// it was claimed or proven to have, the compression of its stream, its
/// size bound and its monotonic deadline.
struct Admission<'a> {
    digest_axes: Vec<Axis>,
    expected: Option<&'a Kappa>,
    compression: Option<Compression>,
    maximum: u64,
    deadline: Instant,
}

impl Admission<'_> {
    /// The decompressed identity the caller proved for compressed content.
    /// Compressed bytes are not hashed: that identity has no aliases.
    const fn proven(&self) -> Option<&Kappa> {
        if self.compression.is_some() {
            self.expected
        } else {
            None
        }
    }

    /// The identity and aliases of plain content whose digests are
    /// `proof`, checked against the claimed identity.
    fn streamed(
        &self,
        proof: &StreamingVerificationProof,
    ) -> Result<(Kappa, Vec<Kappa>), StoreError> {
        check_identity(self.expected, proof.kappa())?;
        Ok((
            proof.kappa().clone(),
            proof.additional().iter().map(|(_, k)| k.clone()).collect(),
        ))
    }
}

/// External bytes written and framed under an allocation, before their
/// durability is established. `physical_bytes` is the payload as framed
/// on disk plus the sidecar's nodes.
struct Written {
    identity: Kappa,
    aliases: Vec<Kappa>,
    record: BlobRecord,
    physical_bytes: u64,
}

impl PersistentStore {
    /// Prepare once under all requested axes. The returned value owns the
    /// allocation pin; no content becomes visible until execution installs it.
    ///
    /// With `compression`, the stream is the compressed form of content
    /// whose identity `expected` names and whose decompressed size the
    /// compression states; the caller has proven the decompression, so the
    /// stream itself is not hashed and the identity has no aliases.
    ///
    /// The public form is `ContentPreparation::prepare_content`; this is
    /// the backend's representation-level entry the trait and the records
    /// the store produces share.
    pub(crate) fn prepare_representation(
        &self,
        axis: Axis,
        expected: Option<&Kappa>,
        reader: &mut dyn Read,
        compression: Option<Compression>,
        maximum: u64,
        deadline: Instant,
    ) -> Result<PreparedContent, StoreError> {
        if expected.is_some_and(|identity| identity.axis() != axis) {
            return Err(StoreError::Rejected(
                "claimed identity uses another axis".into(),
            ));
        }
        if compression.is_some() && expected.is_none() {
            return Err(StoreError::Rejected(
                "compressed content requires its decompressed identity".into(),
            ));
        }
        let admission = Admission {
            digest_axes: self.digest_axes(axis, compression.is_none()),
            expected,
            compression,
            maximum,
            deadline,
        };
        // Probe only the bounded inline candidate. EOF at the exact boundary
        // is checked by the streaming path, not assumed from a short read.
        let probe_limit = self
            .representation_limits
            .inline_limit
            .min(maximum.saturating_add(1));
        let mut prefix = Vec::new();
        (&mut *reader).take(probe_limit).read_to_end(&mut prefix)?;
        if prefix.len() as u64 > maximum {
            return Err(StoreError::CapacityExceeded(
                "content exceeds admission limit".into(),
            ));
        }
        let stored = prefix.len() as u64;
        let compression = admission.compression.as_ref();
        let inline_size = crate::representation_codec::inline_encoded_len(
            stored,
            compression.map_or(stored, |c| c.uncompressed_size),
            compression.map(|c| c.algorithm.as_str()),
        );
        if stored < probe_limit && inline_size <= self.representation_limits.inline_limit {
            return self.prepare_inline(admission, prefix);
        }
        self.prepare_external(&admission, &prefix, reader)
    }

    /// The axes a preparation digests under: the requested one, plus every
    /// other mandatory axis when the stream is hashed (plain content).
    fn digest_axes(&self, axis: Axis, hashed: bool) -> Vec<Axis> {
        let mut digest_axes = vec![axis];
        if hashed {
            for mandatory in self.mandatory_axes() {
                if !digest_axes.contains(&mandatory) {
                    digest_axes.push(mandatory);
                }
            }
        }
        digest_axes
    }

    /// Content whose complete encoded row fits the inline limit: the probe
    /// holds all of it and no allocation is made.
    fn prepare_inline(
        &self,
        admission: Admission<'_>,
        prefix: Vec<u8>,
    ) -> Result<PreparedContent, StoreError> {
        let (identity, aliases) = if let Some(proven) = admission.proven() {
            (proven.clone(), Vec::new())
        } else {
            let mut input = prefix.as_slice();
            let mut buffer = [0u8; 4096];
            let (proof, _) = streaming_compute_into::<StoreError>(
                &admission.digest_axes,
                &mut input,
                &mut buffer,
                admission.maximum,
                |_| Ok(()),
            )?;
            admission.streamed(&proof)?
        };
        let record = BlobRecord::inline(prefix, admission.compression, self.representation_limits)?;
        PreparedContent::unallocated(identity, record)
            .map(|prepared| prepared.owned_by(&self.protection).with_aliases(aliases))
    }

    /// Content beyond the inline limit: written to a fresh allocation,
    /// framed and sidecar-indexed, made durable, and charged to the
    /// unsettled budget. Any failure after the durability reservation
    /// abandons it.
    fn prepare_external(
        &self,
        admission: &Admission<'_>,
        prefix: &[u8],
        reader: &mut dyn Read,
    ) -> Result<PreparedContent, StoreError> {
        let chunk_size = u32::try_from(self.chunk_size).map_err(|_| {
            StoreError::Internal(format!(
                "chunk size {} exceeds the external framing width",
                self.chunk_size
            ))
        })?;
        let chunks = admission.maximum.div_ceil(u64::from(chunk_size));
        let reserve = admission
            .maximum
            .checked_add(chunks.checked_mul(128).ok_or_else(|| {
                StoreError::CapacityExceeded("content reservation overflow".into())
            })?)
            .ok_or_else(|| StoreError::CapacityExceeded("content reservation overflow".into()))?;
        let (pin, mut file) = self.protection.create(&self.blob_root)?;
        let allocation = *pin.allocation();
        self.content_durability.reserve(allocation, reserve)?;
        let written =
            self.write_external(admission, chunk_size, allocation, prefix, reader, &mut file);
        drop(file);
        let written = match written {
            Ok(written) => written,
            Err(error) => {
                self.content_durability.abandon(&allocation)?;
                return Err(error);
            }
        };
        let (capability, outcome) = self
            .content_durability
            .establish(allocation, admission.deadline);
        match outcome {
            DurabilityOutcome::Established | DurabilityOutcome::EstablishedThenFenced => {}
            DurabilityOutcome::NotEstablished(error) => return Err(error),
            DurabilityOutcome::DeadlineExceeded => {
                return Err(StoreError::Rejected(
                    "content durability deadline exceeded".into(),
                ));
            }
        }
        if capability != Capability::Durable {
            return Err(StoreError::Rejected(
                "persistent content requires established durability".into(),
            ));
        }
        // The identity is the verified one: the stream's digest for plain
        // content, the proven decompressed identity for compressed content.
        // The allocation is charged to the unsettled budget from here: the
        // durability queue's hold ended with `establish`, and the pin
        // carries the charge until the publication parks it or the
        // preparation is dropped. Preparation is always ordinary admission:
        // an external allocation is new ownership, refused while the pool
        // is closed whatever publication it is for.
        let charge =
            match self
                .unsettled
                .admit(crate::unsettled::Class::Ordinary, 1, written.physical_bytes)
            {
                Ok(charge) => charge,
                Err(error) => {
                    self.content_durability.abandon(&allocation)?;
                    return Err(error);
                }
            };
        let pin = pin.with_bytes(written.physical_bytes).charged(charge);
        PreparedContent::allocated(written.identity, written.record, pin).map(|prepared| {
            prepared
                .owned_by(&self.protection)
                .with_aliases(written.aliases)
        })
    }

    /// Stream `prefix` then `reader` into `file` under `allocation`: each
    /// chunk is pushed to the sidecar, encrypted under its frame context
    /// when the store encrypts content, and written. Refused once the
    /// admission's deadline passes. The physical bytes are measured here so
    /// the unsettled budget charges a measured value at commit instead of
    /// inspecting storage under the namespace writer.
    fn write_external(
        &self,
        admission: &Admission<'_>,
        chunk_size: u32,
        allocation: AllocationId,
        prefix: &[u8],
        reader: &mut dyn Read,
        file: &mut File,
    ) -> Result<Written, StoreError> {
        let mut publication = [0u8; 32];
        getrandom::fill(&mut publication)
            .map_err(|error| StoreError::Internal(format!("content entropy: {error}")))?;
        let mut sidecar = ChunkListWriter::create(&self.blob_root, &allocation)?;
        let mut input = prefix.chain(reader);
        let mut buffer = zeroize::Zeroizing::new(vec![0u8; self.chunk_size]);
        let mut ordinal = 0u32;
        let mut payload_bytes = 0u64;
        let (proof, size) = streaming_compute_into::<StoreError>(
            &admission.digest_axes,
            &mut input,
            &mut buffer,
            admission.maximum,
            |chunk| {
                if Instant::now() >= admission.deadline {
                    return Err(StoreError::Rejected(
                        "content preparation deadline exceeded".into(),
                    ));
                }
                sidecar.push(chunk)?;
                let framed = if let Some(cipher) = &self.blob_encryptor {
                    let framed = cipher.encrypt(&frame_context(&publication, ordinal), chunk)?;
                    file.write_all(&framed)?;
                    framed.len()
                } else {
                    file.write_all(chunk)?;
                    chunk.len()
                };
                payload_bytes = payload_bytes.saturating_add(framed as u64);
                ordinal = ordinal.checked_add(1).ok_or_else(|| {
                    StoreError::CapacityExceeded("content chunk count exhausted".into())
                })?;
                Ok(())
            },
        )?;
        let (identity, aliases) = if let Some(proven) = admission.proven() {
            (proven.clone(), Vec::new())
        } else {
            admission.streamed(&proof)?
        };
        let (chunk_root, leaves) = sidecar.finish()?;
        let sidecar_bytes = kappa_types::merkle::node_count(leaves).saturating_mul(32);
        file.flush()?;
        let record = BlobRecord::external(
            ExternalLayout {
                stored_size: size,
                chunk_size,
                chunk_count: ordinal,
                allocation,
                publication_id: publication,
                chunk_root,
            },
            admission.compression.clone(),
            self.representation_limits,
        )?;
        let physical_bytes = payload_bytes
            .checked_add(sidecar_bytes)
            .ok_or_else(|| StoreError::CapacityExceeded("content physical size overflow".into()))?;
        Ok(Written {
            identity,
            aliases,
            record,
            physical_bytes,
        })
    }
}

impl PersistentStore {
    /// Prepare `algorithm`-compressed bytes of content `identity` whose
    /// decompressed size is `uncompressed_size`. The decompression is proven
    /// here, outside any writer, against the complete compressed bytes
    /// (bounded by `maximum`); the compressed bytes are then represented
    /// like any other stored bytes, inline below the limit or external.
    pub(crate) fn prepare_compressed_content(
        &self,
        identity: &Kappa,
        algorithm: &str,
        uncompressed_size: u64,
        reader: &mut dyn Read,
        maximum: u64,
        deadline: Instant,
    ) -> Result<PreparedContent, StoreError> {
        let mut compressed = Vec::new();
        reader
            .take(maximum.saturating_add(1))
            .read_to_end(&mut compressed)?;
        if compressed.len() as u64 > maximum {
            return Err(StoreError::CapacityExceeded(format!(
                "compressed content exceeds {maximum} bytes"
            )));
        }
        kappa_store::compression::verify_compressed(
            &compressed,
            algorithm,
            identity,
            uncompressed_size,
        )?;
        self.prepare_representation(
            identity.axis(),
            Some(identity),
            &mut compressed.as_slice(),
            Some(Compression {
                algorithm: algorithm.to_string(),
                uncompressed_size,
            }),
            maximum,
            deadline,
        )
    }
}

fn check_identity(expected: Option<&Kappa>, actual: &Kappa) -> Result<(), StoreError> {
    if expected.is_some_and(|expected| expected != actual) {
        return Err(StoreError::Rejected("content digest mismatch".into()));
    }
    Ok(())
}
