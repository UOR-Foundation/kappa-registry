//! redb table definitions for PersistentStore.
//!
//! All keys use \x00 as namespace/field separator. Null bytes never
//! appear in namespace names, tag names, kappa strings, or metadata
//! keys, so the separator is unambiguous.
//!
//! Multimap tables (edge indexes, ns_meta) use redb's native multimap
//! support: one key maps to multiple values via a sorted B+tree of
//! values per key. MultimapTableDefinition<K: Key, V: Key> requires
//! V to implement Key (not just Value) because values are stored in
//! a sorted sub-tree. &str implements Key with lexicographic ordering.

use redb::{MultimapTableDefinition, TableDefinition};

// -- Tags ---------------------------------------------------------------------
// Key: "{ns}\x00{name}"  Value: "{kappa}\x00{version}"
pub const TAGS: TableDefinition<&str, &str> = TableDefinition::new("tags");

// -- Edges --------------------------------------------------------------------
// Main table: Key: "{ns}\x00{edge_kappa}"  Value: dCBOR canonical bytes
pub const EDGES: TableDefinition<&str, &[u8]> = TableDefinition::new("edges");

// Forward index: Key: "{ns}\x00{source}"  Values: edge kappa strings
pub const EDGE_FWD: MultimapTableDefinition<&str, &str> =
    MultimapTableDefinition::new("edge_fwd");

// Reverse index: Key: "{ns}\x00{target}"  Values: edge kappa strings
pub const EDGE_REV: MultimapTableDefinition<&str, &str> =
    MultimapTableDefinition::new("edge_rev");

// Relation index: Key: "{ns}\x00{relation_str}"  Values: edge kappa strings
pub const EDGE_REL: MultimapTableDefinition<&str, &str> =
    MultimapTableDefinition::new("edge_rel");

// Asserter index: Key: "{ns}\x00{asserter}"  Values: edge kappa strings
pub const EDGE_ASR: MultimapTableDefinition<&str, &str> =
    MultimapTableDefinition::new("edge_asr");

// -- Sequences ----------------------------------------------------------------
// Key: "{ns}\x00{name}"  Value: counter as 8-byte big-endian (encrypted when enabled)
pub const SEQUENCES: TableDefinition<&str, &[u8]> = TableDefinition::new("sequences_v5");

// -- Blob metadata ------------------------------------------------------------
// Key: "{kappa}\x00{meta_key}"  Value: raw bytes
pub const BLOB_META: TableDefinition<&str, &[u8]> = TableDefinition::new("blob_meta");

// -- Namespace-scoped metadata ------------------------------------------------
// Key: "{ns}\x00{meta_key}\x00{meta_value}"  Values: kappa strings
pub const NS_META: MultimapTableDefinition<&str, &str> =
    MultimapTableDefinition::new("ns_meta");

// -- Namespaces ---------------------------------------------------------------
// Key: "{ns}"  Value: () (presence-only)
pub const NAMESPACES: TableDefinition<&str, ()> = TableDefinition::new("namespaces");

// -- Epoch current pointer ----------------------------------------------------
// Key: "{ns}"  Value: "{kappa}" of the current epoch root
pub const EPOCH_CURRENT: TableDefinition<&str, &str> =
    TableDefinition::new("epoch_current");

// -- Binding records (sigma-to-kappa mapping for encrypted stores) ------------
// Key: "{sigma}"  Value: dCBOR-encoded BindingRecord
// When encryption is enabled, sigma = hash(plaintext) and kappa = hash(ciphertext).
// The binding record maps the protocol-facing sigma to the storage-facing kappa
// plus the encryption nonce needed to decrypt. When encryption is disabled,
// this table is empty and unused (sigma == kappa, identity transform).
pub const BINDING_RECORDS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("binding_records");

// -- Credentials --------------------------------------------------------------
// Key: access_key_id  Value: TableEncryptor-encrypted credential record
pub const CREDENTIALS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("credentials");

// -- Versions -----------------------------------------------------------------
// Key: "{ns}\x00{key}\x00{!timestamp_be}"  Value: dCBOR VersionEntry
// Key ordering: namespace ascending, key ascending, timestamp descending
// (bit-inverted timestamp so newest sorts first in ascending B-tree).
pub const VERSIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("versions");

// -- Compression records (sigma-to-kappa mapping for compressed blobs) --------
// Key: "{uncompressed_hash}" (sigma -- hash of uncompressed content)
// Value: encoded CompressionRecord
// Maps the uncompressed content hash to the compressed blob's storage kappa
// plus the compression algorithm and uncompressed size. Same pattern as
// BINDING_RECORDS for encryption: sigma -> (kappa, metadata).
pub const COMPRESSION_RECORDS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("compression_records");

// -- Identity bindings --------------------------------------------------------
// Key: "{source}"  Values: JSON-serialized IdentityBinding
pub const IDENTITY_BINDINGS: MultimapTableDefinition<&str, &str> =
    MultimapTableDefinition::new("identity_bindings");

// -- Identity successions -----------------------------------------------------
// Key: "{old_anchor}"  Value: "{new_anchor}"
pub const IDENTITY_SUCCESSIONS: TableDefinition<&str, &str> =
    TableDefinition::new("identity_successions");

// -- Identity assertion inbound index -----------------------------------------
// Key: "{subject}\x00{facet}"  Values: assertion kappa strings
// Cross-namespace: assertions from any namespace are indexed here.
// Used by resolve endpoints to find assertions about a subject without
// scanning all namespace tag prefixes.
pub const ASSERTION_INBOUND: MultimapTableDefinition<&str, &str> =
    MultimapTableDefinition::new("assertion_inbound");
