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
// Key: "{ns}\x00{name}"  Value: counter (u64)
pub const SEQUENCES: TableDefinition<&str, u64> = TableDefinition::new("sequences");

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
