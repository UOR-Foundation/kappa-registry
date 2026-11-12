//! Key schema of the authenticated current-state index (`state_index`).
//!
//! Every indexed fact of a namespace is one entry: its path is SHA-256 of
//! a domain tag, the family's code, the key's length and the key, so two
//! distinct (family, key) pairs never share a path short of a SHA-256
//! collision; its value is SHA-256 of the canonical record the entry
//! stands for. Family codes are permanent.
//!
//! Typed constructors build the (path, value) pair for each family from
//! its canonical record. Member-level families (binding, device, prekey)
//! have compound keys framed by length-prefixed components so adjacent
//! variable-length fields never create ambiguity.

use crate::kappa::Kappa;
use crate::sha256::{Hasher, digest};
use crate::state_index::{Path, Value};

const DOMAIN: &[u8] = b"kappa state key v1";

/// The families of indexed facts. Codes (PERMANENT): the discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Family {
    /// The authority record; the one key is empty.
    Authority = 0,
    /// A tag by name; the value is its canonical `TagEntry`.
    Tag = 1,
    /// An edge by its identity; the value is its canonical `EdgeInput`.
    Edge = 2,
    /// A namespace metadata key; the value is its canonical
    /// `MetadataRecord`.
    Metadata = 3,
    /// A sequence by name; the value is its canonical `SequenceRecord`.
    Sequence = 4,
    /// An admitted content identity; the value is the canonical
    /// admission record (identity and logical size).
    Content = 5,
    /// An operation identity; the value is its canonical
    /// `OperationReceipt`.
    Operation = 6,
    /// An identity assertion by its record identity.
    Assertion = 7,
    /// A revocation by its record identity.
    Revocation = 8,
    /// A watermark by its record identity.
    Watermark = 9,
    /// One binding member: key = framed source + target key bytes.
    Binding = 10,
    /// A handle record: key = framed protocol + handle.
    Handle = 11,
    /// One device member: key = framed anchor key bytes + device key.
    Device = 12,
    /// One prekey member: key = framed anchor key bytes + epoch BE +
    /// bundle hash.
    Prekey = 13,
    /// The locator record of one anchor by its key bytes.
    Locator = 14,
    /// The revocation commitment of one anchor by its key bytes.
    Commitment = 15,
    /// The succession record of one old anchor by its key bytes.
    Succession = 16,
    /// Blob metadata of one admitted identity and key.
    BlobMeta = 17,
    /// A governed session by its scope identifier.
    Session = 18,
    /// A governed credential by its scope identifier.
    Credential = 19,
    /// A governed trust position by its scope identifier.
    Trust = 20,
    /// Authenticated status of a public label (assertion or retraction
    /// evidence and coordinate).
    Status = 21,
    /// The complete namespace record; the key is empty (one per
    /// namespace). Carries name, aliases with protocol scope, owner,
    /// lifecycle, and timestamps.
    NamespaceRecord = 22,
}

/// The path of `key` in `family`.
pub fn path(family: Family, key: &[u8]) -> Path {
    let mut hasher = Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(&[family as u8]);
    hasher.update(&(key.len() as u64).to_be_bytes());
    hasher.update(key);
    hasher.finalize()
}

/// The path of the authority record.
pub fn authority_path() -> Path {
    path(Family::Authority, &[])
}

/// The value of an entry whose canonical record is `record`.
pub fn value(record: &[u8]) -> Value {
    digest(record)
}

// -- Compound key builders ----------------------------------------------------
//
// Each returns an owned Vec<u8> that path() hashes. Variable-length
// components are length-prefixed with their full length as u64 BE, the
// same framing path() applies to the whole key, so no component length
// wraps and adjacent variable-length fields never share an encoding.

/// Bytes of one component's length prefix.
const FRAME_PREFIX: usize = size_of::<u64>();

/// Length-prefix one component into `out`.
fn frame(out: &mut Vec<u8>, component: &[u8]) {
    let len = component.len() as u64;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(component);
}

/// The key of blob metadata `meta_key` of `identity`: the identity's key
/// bytes, length-prefixed, then the metadata key.
pub fn blob_meta_key(identity: &[u8], meta_key: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(FRAME_PREFIX + identity.len() + FRAME_PREFIX + meta_key.len());
    frame(&mut key, identity);
    frame(&mut key, meta_key.as_bytes());
    key
}

/// The key of a handle: framed protocol then framed handle.
pub fn handle_key(protocol: &str, handle: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(FRAME_PREFIX + protocol.len() + FRAME_PREFIX + handle.len());
    frame(&mut key, protocol.as_bytes());
    frame(&mut key, handle.as_bytes());
    key
}

/// The key of one binding member: framed source then target key bytes.
pub fn binding_member_key(source: &str, target: &Kappa) -> Vec<u8> {
    let target_bytes = target.key_bytes();
    let mut key = Vec::with_capacity(FRAME_PREFIX + source.len() + target_bytes.len());
    frame(&mut key, source.as_bytes());
    key.extend_from_slice(&target_bytes);
    key
}

/// The key of one device member: framed anchor key bytes then device key.
pub fn device_member_key(anchor: &Kappa, device_key: &[u8]) -> Vec<u8> {
    let anchor_bytes = anchor.key_bytes();
    let mut key = Vec::with_capacity(FRAME_PREFIX + anchor_bytes.len() + device_key.len());
    frame(&mut key, &anchor_bytes);
    key.extend_from_slice(device_key);
    key
}

/// The key of one prekey member: framed anchor key bytes, epoch as u64
/// BE, then bundle hash.
pub fn prekey_member_key(anchor: &Kappa, epoch: u64, bundle_hash: &[u8]) -> Vec<u8> {
    let anchor_bytes = anchor.key_bytes();
    let mut key = Vec::with_capacity(FRAME_PREFIX + anchor_bytes.len() + 8 + bundle_hash.len());
    frame(&mut key, &anchor_bytes);
    key.extend_from_slice(&epoch.to_be_bytes());
    key.extend_from_slice(bundle_hash);
    key
}

// -- Typed entry constructors -------------------------------------------------
//
// Each returns (Path, Value) for one state-index entry. The canonical
// record bytes are the caller's responsibility; the constructor hashes
// them for the value and builds the family-specific key for the path.

/// Authority record entry (one per namespace; key is empty).
pub fn authority_entry(canonical_record: &[u8]) -> (Path, Value) {
    (authority_path(), value(canonical_record))
}

/// Tag entry keyed by its UTF-8 name.
pub fn tag_entry(name: &str, canonical_record: &[u8]) -> (Path, Value) {
    (path(Family::Tag, name.as_bytes()), value(canonical_record))
}

/// Edge entry keyed by its identity (key bytes of the edge kappa).
pub fn edge_entry(edge_kappa: &Kappa, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Edge, &edge_kappa.key_bytes()),
        value(canonical_record),
    )
}

/// Namespace metadata entry keyed by its UTF-8 key.
pub fn metadata_entry(key: &str, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Metadata, key.as_bytes()),
        value(canonical_record),
    )
}

/// Sequence entry keyed by its UTF-8 name.
pub fn sequence_entry(name: &str, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Sequence, name.as_bytes()),
        value(canonical_record),
    )
}

/// Content admission entry keyed by the admitted identity's key bytes.
pub fn content_entry(identity: &Kappa, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Content, &identity.key_bytes()),
        value(canonical_record),
    )
}

/// Operation receipt entry keyed by the 32-byte operation identity.
pub fn operation_entry(operation_id: &[u8; 32], canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Operation, operation_id),
        value(canonical_record),
    )
}

/// Assertion entry keyed by the record identity's key bytes.
pub fn assertion_entry(record_kappa: &Kappa, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Assertion, &record_kappa.key_bytes()),
        value(canonical_record),
    )
}

/// Revocation entry keyed by the record identity's key bytes.
pub fn revocation_entry(record_kappa: &Kappa, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Revocation, &record_kappa.key_bytes()),
        value(canonical_record),
    )
}

/// Watermark entry keyed by the record identity's key bytes.
pub fn watermark_entry(record_kappa: &Kappa, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Watermark, &record_kappa.key_bytes()),
        value(canonical_record),
    )
}

/// Binding member entry keyed by framed source + target key bytes.
pub fn binding_entry(source: &str, target: &Kappa, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Binding, &binding_member_key(source, target)),
        value(canonical_record),
    )
}

/// Handle entry keyed by framed protocol + handle.
pub fn handle_entry(protocol: &str, handle: &str, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Handle, &handle_key(protocol, handle)),
        value(canonical_record),
    )
}

/// Device member entry keyed by framed anchor key bytes + device key.
pub fn device_entry(anchor: &Kappa, device_key: &[u8], canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Device, &device_member_key(anchor, device_key)),
        value(canonical_record),
    )
}

/// Prekey member entry keyed by framed anchor + epoch BE + bundle hash.
pub fn prekey_entry(
    anchor: &Kappa,
    epoch: u64,
    bundle_hash: &[u8],
    canonical_record: &[u8],
) -> (Path, Value) {
    (
        path(
            Family::Prekey,
            &prekey_member_key(anchor, epoch, bundle_hash),
        ),
        value(canonical_record),
    )
}

/// Locator entry keyed by the anchor's key bytes.
pub fn locator_entry(anchor: &Kappa, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Locator, &anchor.key_bytes()),
        value(canonical_record),
    )
}

/// Revocation commitment entry keyed by the anchor's key bytes.
pub fn commitment_entry(anchor: &Kappa, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Commitment, &anchor.key_bytes()),
        value(canonical_record),
    )
}

/// Succession entry keyed by the old anchor's key bytes.
pub fn succession_entry(old_anchor: &Kappa, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Succession, &old_anchor.key_bytes()),
        value(canonical_record),
    )
}

/// Blob metadata entry keyed by framed identity key bytes + metadata key.
pub fn blob_meta_entry(identity: &Kappa, meta_key: &str, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(
            Family::BlobMeta,
            &blob_meta_key(&identity.key_bytes(), meta_key),
        ),
        value(canonical_record),
    )
}

/// Session entry keyed by the scope identifier.
pub fn session_entry(scope_id: &str, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Session, scope_id.as_bytes()),
        value(canonical_record),
    )
}

/// Credential entry keyed by the scope identifier.
pub fn credential_entry(scope_id: &str, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Credential, scope_id.as_bytes()),
        value(canonical_record),
    )
}

/// Trust entry keyed by the scope identifier.
pub fn trust_entry(scope_id: &str, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Trust, scope_id.as_bytes()),
        value(canonical_record),
    )
}

/// Authenticated status entry keyed by the label.
pub fn status_entry(label: &str, canonical_record: &[u8]) -> (Path, Value) {
    (
        path(Family::Status, label.as_bytes()),
        value(canonical_record),
    )
}

/// Namespace record entry (one per namespace; key is empty).
pub fn namespace_record_entry(canonical_record: &[u8]) -> (Path, Value) {
    (path(Family::NamespaceRecord, &[]), value(canonical_record))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_separate_families_and_framed_keys() {
        assert_ne!(path(Family::Tag, b"a"), path(Family::Metadata, b"a"));
        assert_ne!(path(Family::Tag, b"ab"), path(Family::Tag, b"a"));
        assert_eq!(authority_path(), path(Family::Authority, b""));
    }

    #[test]
    fn compound_keys_are_unambiguous() {
        assert_ne!(blob_meta_key(b"ab", "c"), blob_meta_key(b"a", "bc"));
        assert_ne!(handle_key("p", "hx"), handle_key("ph", "x"));

        let a1 = Kappa::sha256(b"a");
        let a2 = Kappa::sha256(b"b");
        assert_ne!(
            binding_member_key("src", &a1),
            binding_member_key("src", &a2)
        );
        assert_ne!(device_member_key(&a1, b"dk"), device_member_key(&a2, b"dk"));
        assert_ne!(
            prekey_member_key(&a1, 1, b"bh"),
            prekey_member_key(&a1, 2, b"bh")
        );
    }

    /// A component's length prefix carries its whole length. With a prefix
    /// narrower than the component, a 65536-byte protocol and an empty
    /// handle frame to the same bytes as an empty protocol and a
    /// 65536-byte handle: both lengths wrap to zero and the bytes between
    /// them coincide.
    #[test]
    fn components_longer_than_a_short_prefix_stay_unambiguous() {
        let long = "\0".repeat(65_536);
        let protocol_first = handle_key(&long, "");
        let handle_first = handle_key("", &long);
        assert_ne!(protocol_first, handle_first);
        assert_ne!(
            path(Family::Handle, &protocol_first),
            path(Family::Handle, &handle_first)
        );
        assert_ne!(
            blob_meta_key(long.as_bytes(), ""),
            blob_meta_key(b"", &long)
        );
    }

    #[test]
    fn typed_constructors_produce_correct_paths_and_values() {
        let record = b"canonical record bytes";
        let kappa = Kappa::sha256(b"identity");

        let (p, v) = authority_entry(record);
        assert_eq!(p, authority_path());
        assert_eq!(v, value(record));

        let (p, _) = tag_entry("head", record);
        assert_eq!(p, path(Family::Tag, b"head"));

        let (p, _) = edge_entry(&kappa, record);
        assert_eq!(p, path(Family::Edge, &kappa.key_bytes()));

        let (p, _) = operation_entry(&[7; 32], record);
        assert_eq!(p, path(Family::Operation, &[7; 32]));

        let (p, _) = handle_entry("atproto", "user.bsky.social", record);
        assert_eq!(
            p,
            path(Family::Handle, &handle_key("atproto", "user.bsky.social"))
        );

        let (p, _) = binding_entry("dns:example.com", &kappa, record);
        assert_eq!(
            p,
            path(
                Family::Binding,
                &binding_member_key("dns:example.com", &kappa)
            )
        );

        let (p, _) = device_entry(&kappa, b"device-pub", record);
        assert_eq!(
            p,
            path(Family::Device, &device_member_key(&kappa, b"device-pub"))
        );

        let (p, _) = prekey_entry(&kappa, 3, b"bundle", record);
        assert_eq!(
            p,
            path(Family::Prekey, &prekey_member_key(&kappa, 3, b"bundle"))
        );

        let (p, _) = session_entry("session-scope", record);
        assert_eq!(p, path(Family::Session, b"session-scope"));

        let (p, _) = status_entry("label", record);
        assert_eq!(p, path(Family::Status, b"label"));
    }

    #[test]
    fn new_families_have_distinct_codes() {
        let families = [
            Family::Session,
            Family::Credential,
            Family::Trust,
            Family::Status,
        ];
        for (i, a) in families.iter().enumerate() {
            for b in &families[i + 1..] {
                assert_ne!(*a as u8, *b as u8);
                assert_ne!(path(*a, b"k"), path(*b, b"k"));
            }
        }
    }
}
