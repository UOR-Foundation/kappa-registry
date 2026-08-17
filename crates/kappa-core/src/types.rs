//! Core types for the kappa registry.
//!
//! Types that participate in kappa-label computation or signing derive
//! CBORCodable. The #[cbor(n = N)] attributes on each field are
//! PERMANENT -- changing a key number changes every kappa-label ever
//! computed for that type.
//!
//! Key assignment convention:
//!   0-9: primary identity/addressing fields
//!   10-19: content/value fields
//!   20-29: metadata/auxiliary fields
//!   30-39: cryptographic fields (signatures, proofs)

use dcbor::prelude::*;

// -- Server config types (shared across crates) ------------------------------

/// Maximum blob size for PUT requests. Registered as app_context by
/// kappa-server, enforced by kappa-module-oci blob handler. Defined
/// here so both crates import the same type -- no TypeId mismatch.
pub struct MaxBlobSize(pub usize);

// -- Namespace reference ----------------------------------------------------

/// Opaque namespace identifier backed by a 16-byte UUID.
///
/// All KappaStore trait methods that take a namespace parameter use this
/// type. The UUID is the canonical identity of the namespace. The
/// display_name is an alias resolved from the NAMESPACE_ALIASES table
/// at request time. Multiple aliases can point to the same UUID.
///
/// Construction paths:
/// - `NamespaceRef::deterministic(name)` -- system namespaces (_root, _nix).
///   BLAKE3 keyed hash, same name always produces same UUID across nodes.
/// - `NamespaceRef::generate(name)` -- new user namespaces. UUIDv7.
/// - `NamespaceRef::new(uuid)` -- from a known UUID (redb lookup).
/// - `NamespaceRef::with_name(uuid, name)` -- UUID + display name.
///
/// `From<&str>` is intentionally NOT implemented. All callers must go
/// through alias resolution or deterministic/generate constructors.
#[derive(Debug, Clone)]
pub struct NamespaceRef {
    uuid: [u8; 16],
    display_name: Option<String>,
    protocol: Option<ProtocolHint>,
}

impl NamespaceRef {
    /// Construct from a known UUID. No display name.
    pub fn new(uuid: [u8; 16]) -> Self {
        Self { uuid, display_name: None, protocol: None }
    }

    /// Construct from a known UUID with a display name.
    pub fn with_name(uuid: [u8; 16], name: String) -> Self {
        Self { uuid, display_name: Some(name), protocol: None }
    }

    /// Attach a protocol hint.
    pub fn with_protocol(mut self, protocol: ProtocolHint) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// The 16-byte UUID.
    pub fn uuid(&self) -> &[u8; 16] { &self.uuid }

    /// Hex-encoded UUID string.
    pub fn uuid_hex(&self) -> String { hex::encode(self.uuid) }

    /// The human-readable alias, if known.
    pub fn display_name(&self) -> Option<&str> { self.display_name.as_deref() }

    /// Protocol hint, if set.
    pub fn protocol(&self) -> Option<ProtocolHint> { self.protocol }

    /// Returns display_name if available, otherwise "ns:{hex_uuid}".
    /// Used for logging, error messages, epoch mutation namespace fields,
    /// and anywhere a human-readable string is needed.
    pub fn as_str(&self) -> &str {
        match &self.display_name {
            Some(name) => name.as_str(),
            None => {
                // Callers that need a string without allocation should
                // use display_name().unwrap_or("") or uuid_hex().
                // as_str() returning a reference requires the string
                // to be stored. display_name covers the common case.
                // The None branch should not be hit in normal operation
                // because all NamespaceRef instances carry a display_name
                // after alias resolution.
                ""
            }
        }
    }

    /// Deterministic UUID from a well-known name. Used for system
    /// namespaces (_root, _nix, _system) that must have the same UUID
    /// across all nodes and restarts. BLAKE3 keyed hash of the name
    /// with domain "kappa-namespace-uuid", truncated to 16 bytes,
    /// version nibble set to 0x80 (custom UUID).
    pub fn deterministic(name: &str) -> Self {
        let key = blake3::hash(b"kappa-namespace-uuid");
        let hash = blake3::keyed_hash(key.as_bytes(), name.as_bytes());
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&hash.as_bytes()[..16]);
        uuid[6] = (uuid[6] & 0x0F) | 0x80; // custom version
        uuid[8] = (uuid[8] & 0x3F) | 0x80; // RFC 4122 variant
        Self { uuid, display_name: Some(name.to_string()), protocol: None }
    }

    /// Generate a new UUIDv7 (time-ordered) for a new namespace.
    pub fn generate(name: &str) -> Self {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut uuid = [0u8; 16];
        // UUIDv7: 48-bit timestamp in first 6 bytes
        uuid[0..6].copy_from_slice(&ms.to_be_bytes()[2..8]);
        uuid[6] = (uuid[6] & 0x0F) | 0x70; // version 7
        // Fill remaining bytes with random
        getrandom::fill(&mut uuid[8..16]).expect("getrandom failed");
        uuid[8] = (uuid[8] & 0x3F) | 0x80; // RFC 4122 variant
        Self { uuid, display_name: Some(name.to_string()), protocol: None }
    }

    /// The alias table namespace. Hardcoded well-known UUID.
    ///
    /// This is the ONE exception to "everything goes through the alias
    /// table." The alias table's own namespace UUID is a compiled-in
    /// constant because the alias table must exist before any alias
    /// resolution can work. This breaks the chicken-and-egg: the
    /// NAMESPACE_ALIASES and NAMESPACE_RECORDS tables store their data
    /// under this UUID's key prefix.
    ///
    /// Value: 00000000-0000-8000-8000-6b61707061 ("kappa" in ASCII
    /// at the tail, custom version 0x80, RFC 4122 variant).
    pub const ALIASES_NS: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x80, 0x00, 0x6b, 0x61, 0x70, 0x70, 0x61, 0x00,
    ];

    /// The handles registry namespace. Hardcoded well-known UUID.
    /// Same pattern as ALIASES_NS -- exists before the alias table.
    pub const HANDLES_NS: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00,
        0x80, 0x00, 0x6b, 0x61, 0x70, 0x70, 0x61, 0x00,
    ];

    /// Construct the _aliases system namespace.
    pub fn aliases_ns() -> Self {
        Self::with_name(Self::ALIASES_NS, "_aliases".to_string())
    }

    /// Construct the _handles system namespace.
    pub fn handles_ns() -> Self {
        Self::with_name(Self::HANDLES_NS, "_handles".to_string())
    }
}

impl PartialEq for NamespaceRef {
    fn eq(&self, other: &Self) -> bool { self.uuid == other.uuid }
}

impl Eq for NamespaceRef {}

impl std::hash::Hash for NamespaceRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.uuid.hash(state);
    }
}

impl std::fmt::Display for NamespaceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.display_name {
            Some(name) => f.write_str(name),
            None => write!(f, "ns:{}", hex::encode(self.uuid)),
        }
    }
}

// -- Errors -----------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("rejected: {0}")]
    Rejected(String),
    #[error("canonical error: {0}")]
    Canonical(#[from] crate::canonical::CanonicalError),
}

// -- Tag entry --------------------------------------------------------------

/// CBOR key assignments (PERMANENT):
///   0: name, 1: kappa, 2: version
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct TagEntry {
    #[cbor(n = 0)]
    pub name: String,
    #[cbor(n = 1)]
    pub kappa: String,
    #[cbor(n = 2)]
    pub version: u64,
}

// -- Tag update -------------------------------------------------------------

/// CBOR key assignments (PERMANENT):
///   0: name, 1: kappa, 2: expected_version
#[derive(Debug, Clone, CBORCodable)]
pub struct TagUpdate {
    #[cbor(n = 0)]
    pub name: String,
    #[cbor(n = 1)]
    pub kappa: String,
    #[cbor(n = 2)]
    pub expected_version: Option<u64>,
}

// -- Edge relation ----------------------------------------------------------

/// CBOR key assignments (PERMANENT):
///   Each variant's discriminant is its CBOR integer key.
///   Adding a variant: use the next available number.
///   Changing a number changes every edge blob's kappa-label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, CBORCodable)]
pub enum EdgeRelation {
    #[cbor(n = 0)]
    Owns,
    #[cbor(n = 1)]
    ComposedOf,
    #[cbor(n = 2)]
    Assertion,
    #[cbor(n = 3)]
    Revocation,
    #[cbor(n = 4)]
    Capability,
    #[cbor(n = 5)]
    RecoveryShare,
    #[cbor(n = 6)]
    EpochRoot,
    #[cbor(n = 7)]
    AkdTreeNode,
    #[cbor(n = 8)]
    ChunkManifest,
    #[cbor(n = 9)]
    WitnessReceipt,
    #[cbor(n = 10)]
    OffloadReceipt,
    #[cbor(n = 11)]
    DerivedFrom,
    #[cbor(n = 12)]
    CertifiedBy,
    #[cbor(n = 13)]
    EvidenceProvenance,
    #[cbor(n = 14)]
    SectionOf,
    #[cbor(n = 15)]
    RefersTo,
    #[cbor(n = 16)]
    Delegation,
}

impl EdgeRelation {
    /// Canonical string name for this relation type.
    /// Used for HTTP JSON serialization in protocol modules.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owns => "owns",
            Self::ComposedOf => "composed-of",
            Self::Assertion => "assertion",
            Self::Revocation => "revocation",
            Self::Capability => "capability",
            Self::RecoveryShare => "recovery-share",
            Self::EpochRoot => "epoch-root",
            Self::AkdTreeNode => "akd-tree-node",
            Self::ChunkManifest => "chunk-manifest",
            Self::WitnessReceipt => "witness-receipt",
            Self::OffloadReceipt => "offload-receipt",
            Self::DerivedFrom => "derived-from",
            Self::CertifiedBy => "certified-by",
            Self::EvidenceProvenance => "evidence-provenance",
            Self::SectionOf => "section-of",
            Self::RefersTo => "refers-to",
            Self::Delegation => "delegation",
        }
    }

    /// Parse a relation string into an EdgeRelation.
    /// Accepts both canonical names and backward-compatible aliases:
    /// - "witness-of" -> WitnessReceipt
    /// - "derives-from" -> DerivedFrom
    ///
    ///   Returns None for unrecognized strings.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "owns" => Some(Self::Owns),
            "composed-of" => Some(Self::ComposedOf),
            "assertion" => Some(Self::Assertion),
            "revocation" => Some(Self::Revocation),
            "capability" => Some(Self::Capability),
            "recovery-share" => Some(Self::RecoveryShare),
            "epoch-root" => Some(Self::EpochRoot),
            "akd-tree-node" => Some(Self::AkdTreeNode),
            "chunk-manifest" => Some(Self::ChunkManifest),
            "witness-receipt" | "witness-of" => Some(Self::WitnessReceipt),
            "offload-receipt" => Some(Self::OffloadReceipt),
            "derived-from" | "derives-from" => Some(Self::DerivedFrom),
            "certified-by" => Some(Self::CertifiedBy),
            "evidence-provenance" => Some(Self::EvidenceProvenance),
            "section-of" => Some(Self::SectionOf),
            "refers-to" => Some(Self::RefersTo),
            "delegation" => Some(Self::Delegation),
            _ => None,
        }
    }

    /// Whether GC follows edges of this relation type.
    /// Exhaustive match -- adding a variant without handling it
    /// is a compile error.
    pub fn gc_reachable(&self) -> bool {
        match self {
            Self::Owns => true,
            Self::ComposedOf => true,
            Self::Assertion => true,
            Self::Revocation => true,
            Self::Capability => true,
            Self::RecoveryShare => true,
            Self::EpochRoot => true,
            Self::AkdTreeNode => true,
            Self::ChunkManifest => true,
            Self::WitnessReceipt => true,
            Self::OffloadReceipt => true,
            Self::DerivedFrom => true,
            Self::CertifiedBy => true,
            Self::EvidenceProvenance => true,
            Self::SectionOf => true,
            Self::RefersTo => true,
            Self::Delegation => true,
        }
    }
}

// -- Delegation scope -------------------------------------------------------

/// Scope constraints for a Delegation edge. Stored as serialized
/// metadata on the Edge. Restricts what the delegate can do, where,
/// when, and whether they can re-delegate.
///
/// CBOR key assignments (PERMANENT):
///   0: namespaces, 1: operations, 2: expires_at_ms, 3: delegation_depth
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct DelegationScope {
    /// Namespaces this delegation covers. Empty = all namespaces.
    #[cbor(n = 0)]
    pub namespaces: Vec<String>,
    /// Operations permitted: "read", "write", "admin". Empty = none.
    #[cbor(n = 1)]
    pub operations: Vec<String>,
    /// Expiration timestamp in milliseconds. None = no expiry.
    #[cbor(n = 2)]
    pub expires_at_ms: Option<u64>,
    /// Re-delegation depth. 0 = delegate cannot re-delegate.
    /// N = delegate can create Delegation edges with depth < N.
    #[cbor(n = 3)]
    pub delegation_depth: u32,
}

// -- Edge -------------------------------------------------------------------

/// CBOR key assignments (PERMANENT):
///   0: source, 1: target, 2: relation, 3: asserter,
///   4: value_kappa, 5: metadata
#[derive(Debug, Clone, CBORCodable)]
pub struct Edge {
    #[cbor(n = 0)]
    pub source: String,
    #[cbor(n = 1)]
    pub target: String,
    #[cbor(n = 2)]
    pub relation: EdgeRelation,
    #[cbor(n = 3)]
    pub asserter: String,
    #[cbor(n = 4)]
    pub value_kappa: Option<String>,
    #[cbor(n = 5)]
    pub metadata: Option<Vec<u8>>,
}

// -- Edge query -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
pub enum Direction {
    #[cbor(n = 0)]
    Outbound,
    #[cbor(n = 1)]
    Inbound,
}

#[derive(Debug, Clone)]
pub struct EdgeQuery {
    pub anchor: String,
    pub direction: Direction,
    pub relation: Option<EdgeRelation>,
    pub asserter: Option<String>,
}

// -- Epoch mutation ---------------------------------------------------------

/// CBOR key assignments (PERMANENT):
///   0: op, 1: namespace, 2: tag_name, 3: old_kappa, 4: new_kappa
#[derive(Debug, Clone, CBORCodable)]
pub struct EpochMutation {
    #[cbor(n = 0)]
    pub op: MutationOp,
    #[cbor(n = 1)]
    pub namespace: String,
    #[cbor(n = 2)]
    pub tag_name: String,
    #[cbor(n = 3)]
    pub old_kappa: Option<String>,
    #[cbor(n = 4)]
    pub new_kappa: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
pub enum MutationOp {
    #[cbor(n = 0)]
    TagSet,
    #[cbor(n = 1)]
    TagDelete,
    #[cbor(n = 2)]
    EdgePut,
    #[cbor(n = 3)]
    EdgeDelete,
    #[cbor(n = 4)]
    AssertionPublish,
    #[cbor(n = 5)]
    RevocationPublish,
    #[cbor(n = 6)]
    AnchorOrigin,
    #[cbor(n = 7)]
    BlobPut,
    #[cbor(n = 8)]
    BlobDelete,
}

// -- Federation config (per-namespace) ---------------------------------------

/// Per-namespace federation configuration.
///
/// Stored as a tag under _config/federation in each namespace.
/// CBOR key assignments (PERMANENT):
///   0: mode, 1: peers, 2: sync_interval_secs, 3: conflict_resolution
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct FederationConfig {
    #[cbor(n = 0)]
    pub mode: FederationMode,
    #[cbor(n = 1)]
    pub peers: Vec<String>,
    #[cbor(n = 2)]
    pub sync_interval_secs: u64,
    #[cbor(n = 3)]
    pub conflict_resolution: ConflictResolution,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            mode: FederationMode::Disabled,
            peers: Vec::new(),
            sync_interval_secs: 300,
            conflict_resolution: ConflictResolution::Reject,
        }
    }
}

/// Federation participation mode for a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
pub enum FederationMode {
    /// No federation. This namespace is local-only.
    #[cbor(n = 0)]
    Disabled,
    /// Active federation: push and pull.
    #[cbor(n = 1)]
    Active,
    /// Passive federation: pull only, never push.
    #[cbor(n = 2)]
    Passive,
}

/// How to resolve conflicts when federation pulls a tag that
/// already exists locally with a different kappa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
pub enum ConflictResolution {
    /// Reject the remote value. Manual resolution required.
    #[cbor(n = 0)]
    Reject,
    /// Accept all remote values unconditionally.
    #[cbor(n = 1)]
    AcceptAll,
    /// Higher version number wins.
    #[cbor(n = 2)]
    VersionWins,
}

// -- Writer mode (anti-seam) ------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterMode {
    SingleWriter,
    Contended,
}

// -- Durability (anti-seam) -------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    Ephemeral,
    Checkpoint,
    Replicated,
    Witnessed,
}

// -- Fault model (anti-seam) ------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultModel {
    CrashFault,
    Byzantine,
}

// -- Protocol hint for response shaping ----------------------------------------

/// Protocol hint registered per-route. Middleware reads this to apply
/// protocol-specific response headers (Warning for OCI, Cache-Control
/// differences for S3 vs Git, etc.). Registered at route registration
/// time, not per-request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolHint {
    Oci,
    S3,
    Git,
    KappaDistribution,
    Nix,
    None,
}

// -- Caller identity (request context) -----------------------------------------

/// The authenticated caller's asserter anchor. Stored in the request
/// context by the auth layer. Protocol module handlers read this to
/// set the asserter field on edges, assertions, and other
/// identity-bearing operations. "anonymous" when no auth is configured
/// or the request is unauthenticated.
///
/// Defined in kappa-core so protocol modules and the server can share
/// the type without circular dependencies.
#[derive(Debug, Clone)]
pub struct CallerIdentity(pub String);

// -- Resolved namespace (request-scoped, not persisted) -----------------------

/// Result of namespace resolution by the interceptor layer.
/// Stored in request context via `cx.with(resolved)`.
/// Handlers read it with `request_context::<ResolvedNamespace>(cx)`.
#[derive(Debug, Clone)]
pub enum ResolvedNamespace {
    /// Namespace exists. Handler uses the NamespaceRef directly.
    Exists(NamespaceRef),
    /// Namespace does not exist. Write handlers may create it.
    /// Read handlers return 404.
    NotFound { name: String, protocol: String },
    /// No namespace in this request path (/_status, /v2/, /docs, etc.).
    NoNamespace,
}

/// Operation intent detected from protocol signals by the interceptor.
/// Stored in request context for the auth layer to consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedOperation {
    /// Pure read: GET/HEAD that does not precede a write.
    Read,
    /// State-modifying operation: PUT/POST/PATCH/DELETE.
    Write,
    /// Read that must succeed for a subsequent write to proceed.
    /// Git: GET /info/refs?service=git-receive-pack
    /// Treated as Write for authorization (gets AllowCreateNew on
    /// nonexistent namespaces).
    WriteDiscovery,
}

impl DetectedOperation {
    /// Whether this operation modifies state or precedes a modification.
    pub fn is_write(&self) -> bool {
        matches!(self, Self::Write | Self::WriteDiscovery)
    }
}

/// Errors from namespace resolution in handler code.
#[derive(Debug, Clone, thiserror::Error)]
pub enum NamespaceError {
    #[error("namespace not found: {0}")]
    NotFound(String),
    #[error("no namespace in request path")]
    NoNamespace,
}

impl ResolvedNamespace {
    /// Extract the NamespaceRef if the namespace exists.
    /// Returns NamespaceError::NotFound or NoNamespace otherwise.
    /// Used by read-path handlers: `let ns = resolved.expect_exists()?;`
    pub fn expect_exists(&self) -> Result<NamespaceRef, NamespaceError> {
        match self {
            Self::Exists(ns) => Ok(ns.clone()),
            Self::NotFound { name, .. } => Err(NamespaceError::NotFound(name.clone())),
            Self::NoNamespace => Err(NamespaceError::NoNamespace),
        }
    }

    /// Returns (name, protocol) if the namespace was not found.
    /// Used by write-path handlers to decide whether to create.
    pub fn name_if_missing(&self) -> Option<(&str, &str)> {
        match self {
            Self::NotFound { name, protocol } => Some((name, protocol)),
            _ => None,
        }
    }
}

// -- Attestation digests (cannot produce KappaLabel) --------------------------

/// Digest algorithms that attest to content but do NOT produce content
/// addresses (KappaLabel). MD5, CRC32, CRC32C, CRC64-NVME are attestation
/// digests. They appear in S3 ETags, checksum headers, and part manifests.
/// They CANNOT be used as addressing axes. There is no conversion from
/// AttestationDigest to Axis or KappaLabel. Attempting to use one as
/// a content address is a type error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttestationDigest {
    Md5,
    Crc32,
    Crc32c,
    Crc64Nvme,
}

impl AttestationDigest {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Crc32 => "crc32",
            Self::Crc32c => "crc32c",
            Self::Crc64Nvme => "crc64nvme",
        }
    }

    /// Compute the attestation digest of content. Returns raw digest
    /// bytes, NOT a KappaLabel. There is no conversion path from this
    /// return type to KappaLabel.
    pub fn compute(&self, content: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => {
                use md5::Digest;
                md5::Md5::digest(content).to_vec()
            }
            Self::Crc32 => {
                let checksum = crc_fast::checksum(
                    crc_fast::CrcAlgorithm::Crc32IsoHdlc, content,
                );
                (checksum as u32).to_be_bytes().to_vec()
            }
            Self::Crc32c => {
                let checksum = crc_fast::checksum(
                    crc_fast::CrcAlgorithm::Crc32Iscsi, content,
                );
                (checksum as u32).to_be_bytes().to_vec()
            }
            Self::Crc64Nvme => {
                let checksum = crc_fast::checksum(
                    crc_fast::CrcAlgorithm::Crc64Nvme, content,
                );
                checksum.to_be_bytes().to_vec()
            }
        }
    }
}

// -- Versioning ---------------------------------------------------------------

/// Versioning state for a namespace/bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersioningState {
    Unversioned,
    Enabled,
    Suspended,
}

/// A single version entry in the version chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VersionEntry {
    pub version_id: String,
    pub kappa: Option<String>,
    pub is_delete_marker: bool,
    pub timestamp_ms: u64,
    pub size: u64,
    pub etag: Option<String>,
}

/// Result of a version delete operation.
#[derive(Debug, Clone)]
pub struct DeleteResult {
    pub version_id: String,
    pub is_delete_marker: bool,
}

// -- Namespace hash utilities -----------------------------------------------

/// Hash a namespace name to a u64 for use as a compound key prefix.
pub fn namespace_hash(ns: &str) -> u64 {
    let hash = blake3::hash(ns.as_bytes());
    let bytes = hash.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Hash a tag name or item identifier to a u64 for compound key suffix.
pub fn item_hash(name: &str) -> u64 {
    namespace_hash(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    #[test]
    fn tag_entry_roundtrip() {
        let entry = TagEntry {
            name: "latest".into(),
            kappa: "sha256:abcdef".into(),
            version: 3,
        };
        let bytes = canonical_bytes(&entry);
        let decoded: TagEntry = from_canonical(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn tag_entry_deterministic() {
        let e1 = TagEntry {
            name: "v1.0".into(),
            kappa: "sha256:1234".into(),
            version: 1,
        };
        let e2 = TagEntry {
            name: "v1.0".into(),
            kappa: "sha256:1234".into(),
            version: 1,
        };
        assert_eq!(canonical_bytes(&e1), canonical_bytes(&e2));
    }

    #[test]
    fn edge_roundtrip() {
        let edge = Edge {
            source: "sha256:aaa".into(),
            target: "sha256:bbb".into(),
            relation: EdgeRelation::DerivedFrom,
            asserter: "sha256:ccc".into(),
            value_kappa: Some("sha256:ddd".into()),
            metadata: None,
        };
        let bytes = canonical_bytes(&edge);
        let decoded: Edge = from_canonical(&bytes).unwrap();
        assert_eq!(decoded.source, edge.source);
        assert_eq!(decoded.relation, edge.relation);
    }

    #[test]
    fn edge_relation_roundtrip() {
        for rel in [
            EdgeRelation::Owns,
            EdgeRelation::Assertion,
            EdgeRelation::DerivedFrom,
            EdgeRelation::SectionOf,
        ] {
            let bytes = canonical_bytes(&rel);
            let decoded: EdgeRelation = from_canonical(&bytes).unwrap();
            assert_eq!(decoded, rel);
        }
    }

    #[test]
    fn edge_relation_gc_reachable_exhaustive() {
        // Verify every variant has an explicit gc_reachable decision
        let all = [
            EdgeRelation::Owns,
            EdgeRelation::ComposedOf,
            EdgeRelation::Assertion,
            EdgeRelation::Revocation,
            EdgeRelation::Capability,
            EdgeRelation::RecoveryShare,
            EdgeRelation::EpochRoot,
            EdgeRelation::AkdTreeNode,
            EdgeRelation::ChunkManifest,
            EdgeRelation::WitnessReceipt,
            EdgeRelation::OffloadReceipt,
            EdgeRelation::DerivedFrom,
            EdgeRelation::CertifiedBy,
            EdgeRelation::EvidenceProvenance,
            EdgeRelation::SectionOf,
            EdgeRelation::RefersTo,
            EdgeRelation::Delegation,
        ];
        for rel in all {
            // Just calling gc_reachable proves the match is exhaustive
            let _ = rel.gc_reachable();
        }
    }

    #[test]
    fn mutation_op_roundtrip() {
        let op = MutationOp::TagSet;
        let bytes = canonical_bytes(&op);
        let decoded: MutationOp = from_canonical(&bytes).unwrap();
        assert_eq!(decoded, op);
    }

    #[test]
    fn epoch_mutation_roundtrip() {
        let m = EpochMutation {
            op: MutationOp::AssertionPublish,
            namespace: "test/ns".into(),
            tag_name: "assertion/1".into(),
            old_kappa: None,
            new_kappa: Some("sha256:fff".into()),
        };
        let bytes = canonical_bytes(&m);
        let decoded: EpochMutation = from_canonical(&bytes).unwrap();
        assert_eq!(decoded.op, m.op);
        assert_eq!(decoded.namespace, m.namespace);
    }

    #[test]
    fn namespace_hash_deterministic() {
        assert_eq!(namespace_hash("test"), namespace_hash("test"));
        assert_ne!(namespace_hash("test"), namespace_hash("other"));
    }

    #[test]
    fn direction_roundtrip() {
        let d = Direction::Inbound;
        let bytes = canonical_bytes(&d);
        let decoded: Direction = from_canonical(&bytes).unwrap();
        assert_eq!(decoded, d);
    }

    #[test]
    fn federation_config_roundtrip() {
        let config = FederationConfig {
            mode: FederationMode::Active,
            peers: vec!["http://peer1:8080".into(), "http://peer2:8080".into()],
            sync_interval_secs: 60,
            conflict_resolution: ConflictResolution::VersionWins,
        };
        let bytes = canonical_bytes(&config);
        let decoded: FederationConfig = from_canonical(&bytes).unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn federation_config_default() {
        let config = FederationConfig::default();
        assert!(matches!(config.mode, FederationMode::Disabled));
        assert!(config.peers.is_empty());
        assert_eq!(config.sync_interval_secs, 300);
        assert!(matches!(config.conflict_resolution, ConflictResolution::Reject));
    }

    #[test]
    fn federation_mode_deterministic() {
        let a = canonical_bytes(&FederationMode::Active);
        let b = canonical_bytes(&FederationMode::Passive);
        assert_ne!(a, b);
    }

    #[test]
    fn tag_update_optional_version() {
        let a = TagUpdate {
            name: "t".into(),
            kappa: "k".into(),
            expected_version: None,
        };
        let b = TagUpdate {
            name: "t".into(),
            kappa: "k".into(),
            expected_version: Some(5),
        };
        assert_ne!(canonical_bytes(&a), canonical_bytes(&b));
    }
}
