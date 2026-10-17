//! Content representation index derived from epoch-committed registry
//! state.
//!
//! An index row selects the physical representation of one identity. It
//! does not independently authorize logical visibility or retention: those
//! are determined by authoritative epoch state. The installer writes the
//! row in the transaction that publishes the epoch naming the content; the
//! reader resolves the epoch-committed reference before it selects a
//! representation. Five representations exist:
//!
//! - `Inline`: the bytes are the row value. Ready for transactional
//!   installation; durable only when the epoch's commit is.
//! - `External`: the bytes are a file at an allocation-unique path, written
//!   and made durable before any writer is acquired; the row selects it.
//!   The row carries the chunk root the epoch commits, so a range read
//!   verifies each chunk it delivers against authenticated history.
//! - `Alias`: the identity under another mandatory axis of content whose
//!   representation another row holds. One hop, no composition, no
//!   framing of its own.
//! - `Composite`: the logical concatenation of components, keyed by the
//!   digest of the assembled bytes. With `leaf_children` the components are
//!   leaf content (inline, external, alias); without it they are manifest
//!   nodes.
//! - `Manifest`: a node of a composite, keyed by its own canonical identity
//!   (`manifest_identity`), never by the digest of the bytes it spans, so
//!   deduplication can never substitute a payload representation for a
//!   node a parent expects to be structure. Its components are leaf
//!   content.
//!
//! A composite is therefore at most two levels deep and traversal is
//! bounded. Effective capacity is set by the encoded descriptor bound, not
//! by `max_components` alone: a component encodes in at most
//! `COMPONENT_ENCODED_BYTES`, so a descriptor within `inline_limit` holds
//! at least `inline_limit / COMPONENT_ENCODED_BYTES` components per level,
//! and the two-level population is the square of that.
//!
//! Admission is one size policy over the encoded row: a representation is
//! inline when its complete encoded record fits `inline_limit`, and
//! external exactly when the inline encoding of the same stored bytes would
//! not. The publication group's aggregate byte budget is enforced by the
//! publisher, not here.
//!
//! `BlobRecord` has private fields and is built only through validated
//! constructors that encode it once; the cached encoding is what gets
//! persisted, so a record the decoder would reject is never written.

use kappa_types::{Kappa, StoreError};

#[cfg(test)]
#[path = "representation_tests.rs"]
mod tests;

/// A physical allocation of external content. The pathname is derived
/// from this identity alone. The preparation path creates the file
/// exclusively and draws a new identity on collision, so an allocation
/// never adopts or overwrites another's file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AllocationId(pub(crate) [u8; 16]);

impl AllocationId {
    pub(crate) fn generate() -> Result<Self, StoreError> {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id)
            .map_err(|error| StoreError::Internal(format!("allocation entropy: {error}")))?;
        Ok(Self(id))
    }

    pub(crate) fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Canonical lowercase hex of exactly 16 bytes.
    pub(crate) fn parse_hex(text: &str) -> Option<Self> {
        if text.len() != 32
            || !text
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return None;
        }
        let bytes = hex::decode(text).ok()?;
        let id: [u8; 16] = bytes.as_slice().try_into().ok()?;
        Some(Self(id))
    }
}

/// One component of a composite or manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    pub(crate) identity: Kappa,
    /// Logical bytes the component contributes; never zero.
    pub(crate) length: u64,
}

/// Where the committed bytes of an identity are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Representation {
    Inline {
        bytes: Vec<u8>,
    },
    External {
        allocation: AllocationId,
        chunk_count: u32,
        chunk_size: u32,
        /// Entropy drawn when the allocation was prepared. Chunk encryption
        /// contexts bind to it, so a chunk of another allocation of the
        /// same content cannot be spliced in.
        publication_id: [u8; 32],
        /// `merkle_root` over the SHA-256 digest of each plaintext chunk,
        /// in order; the same value the epoch commits.
        chunk_root: [u8; 32],
    },
    Alias {
        target: Kappa,
    },
    Composite {
        components: Vec<Component>,
        /// `cumulative[i]` is the logical offset at which component `i`
        /// ends; `cumulative.len() == components.len()`.
        cumulative: Vec<u64>,
        /// True when every component is leaf content; false when every
        /// component is a manifest node.
        leaf_children: bool,
    },
    Manifest {
        components: Vec<Component>,
        cumulative: Vec<u64>,
    },
}

/// Structural kind of a committed row, for shape checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Leaf,
    Alias,
    Composite { leaf_children: bool },
    Manifest,
}

/// Compression applied to the stored bytes of a representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compression {
    pub(crate) algorithm: String,
    /// Logical bytes the stored bytes decode to.
    pub(crate) uncompressed_size: u64,
}

/// Committed index record: private fields, validated construction, one
/// cached canonical encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobRecord {
    total_size: u64,
    stored_size: u64,
    compression: Option<String>,
    representation: Representation,
    encoded: Vec<u8>,
}

/// Bounds a representation must respect, fixed by the store at open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepresentationLimits {
    /// Largest encoded row an inline, composite, or manifest
    /// representation may occupy. External is selected exactly when the
    /// inline encoding of the same stored bytes would exceed it.
    pub(crate) inline_limit: u64,
    /// Largest number of components one composite or manifest may list;
    /// at most [`MAX_COMPONENTS`].
    pub(crate) max_components: usize,
}

/// Format ceilings, enforced by every constructor before encoding and by
/// the decoder before it parses or allocates.
pub const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_COMPONENTS: usize = 65_536;
/// Longest compression algorithm name the format admits.
pub const MAX_COMPRESSION_NAME: usize = 32;
/// Upper bound on the encoded size of one component: a 64-byte identity
/// (key bytes plus framing) and a 9-byte cumulative length.
pub const COMPONENT_ENCODED_BYTES: usize = 80;

impl RepresentationLimits {
    /// Configured limits must sit inside the format ceilings.
    pub(crate) fn validate(self) -> Result<Self, StoreError> {
        if self.inline_limit == 0 || self.inline_limit > MAX_RECORD_BYTES as u64 {
            return Err(StoreError::Rejected(format!(
                "inline limit {} is outside 1..={MAX_RECORD_BYTES}",
                self.inline_limit
            )));
        }
        if self.max_components == 0 || self.max_components > MAX_COMPONENTS {
            return Err(StoreError::Rejected(format!(
                "component limit {} is outside 1..={MAX_COMPONENTS}",
                self.max_components
            )));
        }
        Ok(self)
    }

    /// Components a descriptor within the inline limit is guaranteed to
    /// hold, from the encoded-size bound.
    pub(crate) fn guaranteed_fanout(self) -> usize {
        usize::try_from(self.inline_limit / COMPONENT_ENCODED_BYTES as u64)
            .unwrap_or(usize::MAX)
            .min(self.max_components)
            .max(1)
    }
}

/// The physical layout of an external representation: the stored bytes,
/// how they are framed into chunks, the allocation holding them, the
/// entropy their frame contexts bind to, and the chunk root the epoch
/// commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalLayout {
    pub stored_size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub allocation: AllocationId,
    pub publication_id: [u8; 32],
    pub chunk_root: [u8; 32],
}

/// Largest external chunk: one AEAD frame, so a chunk carries one tag.
pub const MAX_CHUNK_SIZE: u32 = {
    assert!(kappa_crypto::aead::FRAME_SIZE <= u32::MAX as usize);
    #[allow(clippy::cast_possible_truncation)]
    {
        kappa_crypto::aead::FRAME_SIZE as u32
    }
};

impl BlobRecord {
    /// Inline content. The complete candidate, compression included, is
    /// encoded and must fit `limits.inline_limit`.
    pub(crate) fn inline(
        bytes: Vec<u8>,
        compression: Option<Compression>,
        limits: RepresentationLimits,
    ) -> Result<Self, StoreError> {
        let stored_size = bytes.len() as u64;
        let (total_size, compression) = Self::sizes(stored_size, compression)?;
        let record = Self::build(
            total_size,
            stored_size,
            compression,
            Representation::Inline { bytes },
        )?;
        record.check_inline_limit(limits, "row")?;
        Ok(record)
    }

    /// External content laid out as `layout`. Admitted exactly when the
    /// inline encoding of the same stored bytes would exceed
    /// `limits.inline_limit`, so no content that could be inline is ever
    /// external.
    pub(crate) fn external(
        layout: ExternalLayout,
        compression: Option<Compression>,
        limits: RepresentationLimits,
    ) -> Result<Self, StoreError> {
        let ExternalLayout {
            stored_size,
            chunk_size,
            chunk_count,
            allocation,
            publication_id,
            chunk_root,
        } = layout;
        let (total_size, compression) = Self::sizes(stored_size, compression)?;
        let inline_encoding = crate::representation_codec::inline_encoded_len(
            stored_size,
            total_size,
            compression.as_deref(),
        );
        if inline_encoding <= limits.inline_limit {
            return Err(StoreError::Rejected(format!(
                "representation of {stored_size} stored bytes would encode inline in {inline_encoding} bytes"
            )));
        }
        Self::build(
            total_size,
            stored_size,
            compression,
            Representation::External {
                allocation,
                chunk_count,
                chunk_size,
                publication_id,
                chunk_root,
            },
        )
    }

    /// Alias of `target`, whose logical size is `total_size`.
    pub(crate) fn alias(
        target: Kappa,
        total_size: u64,
        limits: RepresentationLimits,
    ) -> Result<Self, StoreError> {
        let record = Self::build(
            total_size,
            total_size,
            None,
            Representation::Alias { target },
        )?;
        record.check_inline_limit(limits, "alias row")?;
        Ok(record)
    }

    /// Composite over `components` in order, all leaves when
    /// `leaf_children`, all manifest nodes otherwise.
    pub(crate) fn composite(
        components: Vec<Component>,
        leaf_children: bool,
        limits: RepresentationLimits,
    ) -> Result<Self, StoreError> {
        let (total, cumulative) = Self::membership(&components, limits)?;
        let record = Self::build(
            total,
            total,
            None,
            Representation::Composite {
                components,
                cumulative,
                leaf_children,
            },
        )?;
        record.check_inline_limit(limits, "composite descriptor")?;
        Ok(record)
    }

    /// Manifest node over leaf `components`.
    pub(crate) fn manifest(
        components: Vec<Component>,
        limits: RepresentationLimits,
    ) -> Result<Self, StoreError> {
        let (total, cumulative) = Self::membership(&components, limits)?;
        let record = Self::build(
            total,
            total,
            None,
            Representation::Manifest {
                components,
                cumulative,
            },
        )?;
        record.check_inline_limit(limits, "manifest descriptor")?;
        Ok(record)
    }

    /// The identity a manifest node is keyed by: the digest of its
    /// canonical descriptor, distinct from the digest of the bytes it
    /// spans.
    pub(crate) fn manifest_identity(&self) -> Result<Kappa, StoreError> {
        match self.representation {
            Representation::Manifest { .. } => Ok(Kappa::sha256(&self.encoded)),
            _ => Err(StoreError::Internal(
                "manifest identity requested of a non-manifest record".into(),
            )),
        }
    }

    fn membership(
        components: &[Component],
        limits: RepresentationLimits,
    ) -> Result<(u64, Vec<u64>), StoreError> {
        if components.is_empty() {
            return Err(StoreError::Rejected("composite has no components".into()));
        }
        if components.len() > limits.max_components || components.len() > MAX_COMPONENTS {
            return Err(StoreError::CapacityExceeded(format!(
                "composite of {} components exceeds the {} component limit",
                components.len(),
                limits.max_components.min(MAX_COMPONENTS)
            )));
        }
        let mut cumulative = Vec::with_capacity(components.len());
        let mut total: u64 = 0;
        for component in components {
            if component.length == 0 {
                return Err(StoreError::Rejected(
                    "composite component has zero length".into(),
                ));
            }
            total = total
                .checked_add(component.length)
                .ok_or_else(|| StoreError::CapacityExceeded("composite length overflows".into()))?;
            cumulative.push(total);
        }
        Ok((total, cumulative))
    }

    fn check_inline_limit(
        &self,
        limits: RepresentationLimits,
        what: &str,
    ) -> Result<(), StoreError> {
        let encoded = self.encoded.len() as u64;
        if encoded > limits.inline_limit {
            return Err(StoreError::CapacityExceeded(format!(
                "encoded {what} of {encoded} bytes exceeds the {} byte inline limit",
                limits.inline_limit
            )));
        }
        Ok(())
    }

    pub(crate) const fn kind(&self) -> Kind {
        match &self.representation {
            Representation::Inline { .. } | Representation::External { .. } => Kind::Leaf,
            Representation::Alias { .. } => Kind::Alias,
            Representation::Composite { leaf_children, .. } => Kind::Composite {
                leaf_children: *leaf_children,
            },
            Representation::Manifest { .. } => Kind::Manifest,
        }
    }

    /// Whether this composite's components are leaf content.
    #[cfg(test)]
    pub(crate) const fn leaf_children(&self) -> Option<bool> {
        match &self.representation {
            Representation::Composite { leaf_children, .. } => Some(*leaf_children),
            Representation::Manifest { .. } => Some(true),
            _ => None,
        }
    }

    /// Reconstruct a decoded record. Only the codec calls this, after it
    /// has bounded and parsed the input.
    pub(crate) fn from_parts(
        total_size: u64,
        stored_size: u64,
        compression: Option<String>,
        representation: Representation,
    ) -> Result<Self, StoreError> {
        Self::build(total_size, stored_size, compression, representation)
    }

    fn sizes(
        stored_size: u64,
        compression: Option<Compression>,
    ) -> Result<(u64, Option<String>), StoreError> {
        match compression {
            Some(compression) => {
                if compression.algorithm.is_empty()
                    || compression.algorithm.len() > MAX_COMPRESSION_NAME
                {
                    return Err(StoreError::Rejected(
                        "compression name is empty or too long".into(),
                    ));
                }
                Ok((compression.uncompressed_size, Some(compression.algorithm)))
            }
            None => Ok((stored_size, None)),
        }
    }

    /// Validate, then encode once. The format ceiling is checked on the
    /// payload before encoding and on the encoding after, so no
    /// representation the decoder refuses is ever produced.
    fn build(
        total_size: u64,
        stored_size: u64,
        compression: Option<String>,
        representation: Representation,
    ) -> Result<Self, StoreError> {
        let payload_bytes = match &representation {
            Representation::Inline { bytes } => bytes.len(),
            Representation::External { .. } | Representation::Alias { .. } => 0,
            Representation::Composite { components, .. }
            | Representation::Manifest { components, .. } => {
                components.len() * COMPONENT_ENCODED_BYTES
            }
        };
        if payload_bytes > MAX_RECORD_BYTES {
            return Err(StoreError::CapacityExceeded(format!(
                "representation payload of {payload_bytes} bytes exceeds the {MAX_RECORD_BYTES} byte format limit"
            )));
        }
        let mut record = Self {
            total_size,
            stored_size,
            compression,
            representation,
            encoded: Vec::new(),
        };
        record.validate_structure()?;
        record.encoded = crate::representation_codec::encode(&record);
        if record.encoded.len() > MAX_RECORD_BYTES {
            return Err(StoreError::CapacityExceeded(format!(
                "encoded record of {} bytes exceeds the {MAX_RECORD_BYTES} byte format limit",
                record.encoded.len()
            )));
        }
        Ok(record)
    }

    pub(crate) const fn total_size(&self) -> u64 {
        self.total_size
    }

    pub(crate) const fn stored_size(&self) -> u64 {
        self.stored_size
    }

    pub(crate) fn compression(&self) -> Option<&str> {
        self.compression.as_deref()
    }

    pub(crate) const fn representation(&self) -> &Representation {
        &self.representation
    }

    /// The canonical bytes this record persists as.
    pub(crate) fn canonical(&self) -> &[u8] {
        &self.encoded
    }

    fn validate_membership(
        &self,
        components: &[Component],
        cumulative: &[u64],
    ) -> Result<(), StoreError> {
        if components.is_empty()
            || components.len() != cumulative.len()
            || components.len() > MAX_COMPONENTS
        {
            return Err(StoreError::Internal("invalid composite membership".into()));
        }
        if self.compression.is_some() {
            return Err(StoreError::Internal(
                "composite representations are not compressed".into(),
            ));
        }
        let mut expected: u64 = 0;
        for (component, end) in components.iter().zip(cumulative) {
            if component.length == 0 {
                return Err(StoreError::Internal(
                    "composite component has zero length".into(),
                ));
            }
            expected = expected
                .checked_add(component.length)
                .ok_or_else(|| StoreError::Internal("composite length overflows".into()))?;
            if expected != *end {
                return Err(StoreError::Internal(
                    "composite cumulative lengths disagree".into(),
                ));
            }
        }
        if expected != self.stored_size {
            return Err(StoreError::Internal(
                "composite length disagrees with stored size".into(),
            ));
        }
        Ok(())
    }

    /// Structural invariants of the durable format.
    fn validate_structure(&self) -> Result<(), StoreError> {
        if self
            .compression
            .as_deref()
            .is_some_and(|name| name.is_empty() || name.len() > MAX_COMPRESSION_NAME)
        {
            return Err(StoreError::Internal(
                "compression name is empty or too long".into(),
            ));
        }
        if self.compression.is_none() && self.total_size != self.stored_size {
            return Err(StoreError::Internal(
                "uncompressed representation size mismatch".into(),
            ));
        }
        match &self.representation {
            Representation::Inline { bytes } => {
                if bytes.len() as u64 != self.stored_size {
                    return Err(StoreError::Internal(
                        "inline representation length mismatch".into(),
                    ));
                }
            }
            Representation::External {
                chunk_count,
                chunk_size,
                ..
            } => {
                if self.stored_size == 0 {
                    return Err(StoreError::Internal(
                        "external representation is empty".into(),
                    ));
                }
                if *chunk_size == 0 || *chunk_count == 0 || *chunk_size > MAX_CHUNK_SIZE {
                    return Err(StoreError::Internal("invalid blob index framing".into()));
                }
                if (self.stored_size - 1) / u64::from(*chunk_size) + 1 != u64::from(*chunk_count) {
                    return Err(StoreError::Internal(
                        "inconsistent blob index framing".into(),
                    ));
                }
            }
            Representation::Alias { .. } => {
                if self.compression.is_some() {
                    return Err(StoreError::Internal("alias rows are not compressed".into()));
                }
            }
            Representation::Composite {
                components,
                cumulative,
                ..
            }
            | Representation::Manifest {
                components,
                cumulative,
            } => self.validate_membership(components, cumulative)?,
        }
        Ok(())
    }
}

impl Representation {
    fn members(&self) -> Option<(&[Component], &[u64])> {
        match self {
            Self::Composite {
                components,
                cumulative,
                ..
            }
            | Self::Manifest {
                components,
                cumulative,
            } => Some((components, cumulative)),
            _ => None,
        }
    }

    /// Index of the component containing logical `offset`, with the
    /// offset of that component's first byte. `None` past the end or for
    /// a representation without components.
    pub(crate) fn component_at(&self, offset: u64) -> Option<(usize, u64)> {
        let (components, cumulative) = self.members()?;
        let index = cumulative.partition_point(|end| *end <= offset);
        if index >= components.len() {
            return None;
        }
        let start = if index == 0 { 0 } else { cumulative[index - 1] };
        Some((index, start))
    }

    /// The components of a composite or manifest.
    pub(crate) fn components(&self) -> &[Component] {
        self.members().map_or(&[], |(components, _)| components)
    }
}
