//! Table definitions, split by the database that owns them.
//!
//! A namespace database (`namespaces/{uuid}/state.redb`) holds every fact
//! the namespace's epochs admit: tags, edges, sequences, metadata, the
//! representations and commitments of the content it published, its
//! epochs, receipts, ledger buffer and tag digest. Keys keep their
//! `[ns_uuid:16]` prefix as a mismatch check: a row read from the wrong
//! database is refused by its prefix.
//!
//! The registry database (`state.redb`) holds the completed-generation
//! projections settlement derives from namespace epochs (`PROJECTION_*`,
//! `SETTLED`; see `projection`), the directory and its claims, the
//! authorization claims, the registry-wide authority and time state, and
//! node-local operational state. No ordinary publication writes to it
//! beyond its claims; a namespace's publication is complete when its own
//! database committed, and settlement follows.

use redb::{MultimapTableDefinition, TableDefinition};

// =============================================================================
// Namespace database
// =============================================================================

// Tags: key = [ns_uuid:16][name_bytes], value = dCBOR TagEntry
pub const TAGS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("tags_v1");

// Edges: key = [ns_uuid:16][edge_kappa_key_bytes], value = dCBOR Edge
pub const EDGES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("edges_v1");

// Edge indexes: key = [ns_uuid:16][anchor_key_bytes], values = edge kappa key_bytes
pub const EDGE_FWD: MultimapTableDefinition<&[u8], &[u8]> =
    MultimapTableDefinition::new("edge_fwd_v1");
pub const EDGE_REV: MultimapTableDefinition<&[u8], &[u8]> =
    MultimapTableDefinition::new("edge_rev_v1");

// Edge relation index: key = [ns_uuid:16][relation_discriminant:1], values = edge kappa key_bytes
pub const EDGE_REL: MultimapTableDefinition<&[u8], &[u8]> =
    MultimapTableDefinition::new("edge_rel_v1");

// Edge asserter index: key = [ns_uuid:16][asserter_key_bytes], values = edge kappa key_bytes
pub const EDGE_ASR: MultimapTableDefinition<&[u8], &[u8]> =
    MultimapTableDefinition::new("edge_asr_v1");

// Sequences: key = [ns_uuid:16][name_hash:16], value = big-endian u64
pub const SEQUENCES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("sequences_v1");

// Representations this namespace admitted: key = kappa key_bytes, value =
// encrypted dCBOR BlobRecord. A row is the namespace's admitted selection
// of a representation for the identity; the physical allocation it names
// may be shared with other namespaces (see `projection::Family::AllocationOwner`).
pub const BLOB_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blob_index");

// Per-blob metadata admitted by this namespace: key = [kappa_key_bytes ++ b":" ++ meta_key]
pub const BLOB_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blob_meta");

// Commitment coordinates: key = content kappa key_bytes, value (encrypted
// under "commitments") = [epoch_len:1][epoch root key_bytes][commitment_len:1]
// [commitment kappa key_bytes]. Written by the seal for every ContentPublish
// it seals, in the namespace that published it.
pub const COMMITMENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("commitments_v1");

// This namespace's allocation ownership: key = allocation id (16 bytes),
// value = the kappa key_bytes of the identity whose External row selects
// the allocation. Written in the transaction that installs the row,
// removed in the one that retires it; the namespace's authoritative claim
// on the allocation, from which the registry's allocation-owner projection
// is settled.
pub const ALLOCATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("allocations_v1");

// Epoch-derived reverse-reference index of this namespace.
// Key = content kappa key_bytes.
// Values = [ns_uuid:16][referrer_kind:1][referrer_id].
// Updated atomically with the epoch-committed reference mutation and
// rebuildable from the namespace's committed state. A representation row
// is the namespace's own, so its retirement consults only this index;
// physical sharing between namespaces is at the allocation level.
// Generation zero of the index (`derived_index`).
pub const REFERRERS: MultimapTableDefinition<&[u8], &[u8]> =
    MultimapTableDefinition::new("referrers_v1");

// Generation one of `REFERRERS` and `ALLOCATIONS`: the other physical copy
// a repair reconstructs privately and then makes live (`derived_index`).
pub const REFERRERS_G1: MultimapTableDefinition<&[u8], &[u8]> =
    MultimapTableDefinition::new("referrers_g1");
pub const ALLOCATIONS_G1: TableDefinition<&[u8], &[u8]> = TableDefinition::new("allocations_g1");

// State of the derived indexes: key = b"live", value = [generation:1], the
// generation readers and writers use; key = b"repair", value = the active
// repair's phase and progress (`derived_index::Repair`), committed with
// each chunk of reconstructed entries.
pub const DERIVED_STATE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("derived_index_state_v1");

// Committed causal floor of this namespace: key = b"committed-causal-floor",
// encrypted value = big-endian i64 of the latest time any of its mutations
// or epochs committed. Written in the namespace's own transaction.
pub const TIME_STATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("time_state_v1");

// Namespace-scoped metadata: key = [ns_uuid:16][key_hash:16], value = raw bytes
pub const NS_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ns_meta_v1");

// Namespace-level config: [ns_uuid:16][key bytes] -> encrypted value. The
// key is stored in the clear so metadata keys can be listed by prefix
// (`namespace_list_meta_keys`) and pins re-derived from the table.
pub const NAMESPACE_CONFIG: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("namespace_config_v1");

// Alias history of this namespace: [uuid:16][timestamp_be:8] -> dCBOR AliasEvent
pub const ALIAS_HISTORY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("alias_history");

// Current epoch: ns_uuid -> epoch kappa key_bytes
pub const EPOCH_CURRENT: TableDefinition<&[u8], &[u8]> = TableDefinition::new("epoch_current_v1");

// Epoch number index: [ns_uuid:16][epoch_number_be:8] -> epoch kappa key_bytes
pub const EPOCH_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("epoch_index_v1");

// [namespace UUID:16][operation identity:32] -> content-addressed receipt.
// The receipt must occur in the authenticated ledger of its named epoch.
pub const OPERATION_RECEIPTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("operation_receipts_v1");

// Mutations recorded inside the same write transaction as the data write,
// sealed and cleared by the next epoch. Key: [ns_uuid:16][sequence:8 BE].
pub const MUTATION_BUFFER: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mutation_buffer");

// Key: namespace UUID; encrypted value: [live digest:32][tag count:8 BE].
pub const LIVE_TAG_STATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("live_tag_state");

// Identity bindings admitted by this namespace: key = [ns_uuid:16][source_bytes...]
pub const ID_BINDINGS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("id_bindings");

// The namespace's own identity and incarnation, written once at creation:
// key = b"self", value = [ns_uuid:16]; key = b"incarnation", value =
// [incarnation:16] (absent in storage created before incarnations, whose
// instance is unknown; see `storage_instance`). Every open checks `self`
// against the namespace, so a database copied under another namespace is
// refused.
pub const NAMESPACE_SELF: TableDefinition<&[u8], &[u8]> = TableDefinition::new("namespace_self_v1");

/// Create every namespace table in `txn`. The identity records a
/// namespace's executions write (assertions, revocations, successions,
/// watermarks, handles, device, prekey, locator and commitment records)
/// and their indexes are namespace tables too: an execution writes them
/// in its own transaction, and the registry's cross-namespace indexes are
/// settled from the epochs afterwards.
pub(crate) fn create_namespace_tables(
    txn: &redb::WriteTransaction,
) -> Result<(), redb::TableError> {
    for table in [
        TAGS,
        EDGES,
        SEQUENCES,
        BLOB_INDEX,
        BLOB_META,
        COMMITMENTS,
        NS_META,
        NAMESPACE_CONFIG,
        NAMESPACE_RECORDS,
        ALIAS_HISTORY,
        EPOCH_CURRENT,
        EPOCH_INDEX,
        OPERATION_RECEIPTS,
        MUTATION_BUFFER,
        LIVE_TAG_STATE,
        ALLOCATIONS,
        ALLOCATIONS_G1,
        DERIVED_STATE,
        TIME_STATE,
        ID_BINDINGS,
        ID_ASSERTIONS,
        ID_REVOCATIONS,
        ID_SUCCESSIONS,
        ID_WATERMARKS,
        ID_DEVICE_BINDINGS,
        ID_PREKEY_BINDINGS,
        ID_LOCATOR_RECORDS,
        ID_REVOCATION_COMMITMENTS,
        NAMESPACE_SELF,
    ] {
        txn.open_table(table)?;
    }
    txn.open_table(ID_SUCCESSION_DEPTH)?;
    for table in [
        ID_HANDLES,
        ID_SESSIONS,
        ID_CREDENTIALS,
        ID_CREDENTIAL_GRACE,
        ID_TRUST,
    ] {
        txn.open_table(table)?;
    }
    for table in [
        EDGE_FWD,
        EDGE_REV,
        EDGE_REL,
        EDGE_ASR,
        REFERRERS,
        REFERRERS_G1,
        ID_ASSERTION_ASSERTER_IDX,
        ID_REVOCATION_ASSERTER_IDX,
        ID_WATERMARK_ASSERTER_IDX,
    ] {
        txn.open_multimap_table(table)?;
    }
    txn.open_multimap_table(ID_BINDING_SRC_IDX)?;
    txn.open_multimap_table(ID_ASSERTION_SUBJECT_IDX)?;
    txn.open_multimap_table(ID_HANDLE_ANCHOR_IDX)?;
    crate::state_nodes::create_tables(txn)
}

// =============================================================================
// Registry database: projections settled from namespace epochs
// =============================================================================

// Every `[instance]` below is a storage instance key (`storage_instance`):
// [ns_uuid:16][incarnation:16], or [ns_uuid:16] alone for a record written
// before incarnations existed.

// The content catalog, allocation ownership, routing assignments, epoch
// root locators, directory records and identity indexes settled from
// namespace epochs are completed-generation projections in the
// `PROJECTION_*` tables below, read and written only through
// `projection` (`projection::Family`).

// Settlement checkpoint: key = [instance], value = [epoch_number:8 BE]
// [epoch root key_bytes]. Advanced in the same registry transaction that
// completes the epoch's projection attempt (`PROJECTION_COMPLETED`), so a
// checkpoint never precedes its effects and no reader sees part of them;
// an instance whose head is past its checkpoint is unsettled, and a new
// instance of a namespace starts from no checkpoint.
pub const SETTLED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("settled_v1");

// Completed-generation projections (`projection`): every settled row,
// versioned. Key = [family:1][escaped logical key][0x00 0x00][instance
// length:1][instance][epoch:8 BE][attempt:4 BE][sequence:8 BE]; value =
// [kind:1 (0 put, 1 tombstone)][payload]. A version is visible only once
// `PROJECTION_COMPLETED` names its attempt for its (instance, epoch);
// readers take, per logical key and instance, the newest visible version.
pub const PROJECTION_VERSIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("projection_versions_v1");

// Every version a settlement attempt staged, for bounded cleanup of
// attempts that never completed and compaction of superseded versions:
// key = [instance length:1][instance][epoch:8 BE][attempt:4 BE]
// [sequence:8 BE], value = the version's `PROJECTION_VERSIONS` key.
pub const PROJECTION_LOG: TableDefinition<&[u8], &[u8]> = TableDefinition::new("projection_log_v1");

// The completed attempt of each settled epoch: key = [instance length:1]
// [instance][epoch:8 BE], value = [attempt:4 BE][completion sequence:8 BE].
// Written in the one registry transaction that advances `SETTLED`; removed
// by compaction once no version of another attempt of the epoch remains,
// after which every version of an epoch at or below the instance's
// checkpoint is of its completed attempt.
pub const PROJECTION_COMPLETED: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("projection_completed_v1");

// The last completion sequence of each instance: key = [instance], value =
// [completion sequence:8 BE]. Orders, across instances, the versions of
// epochs whose completed row compaction removed.
pub const PROJECTION_INSTANCES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("projection_instances_v1");

// The next settlement attempt of each instance: key = [instance], value =
// [attempt:4 BE]. An attempt is never reused, so versions a restarted or
// abandoned attempt staged can never become visible.
pub const PROJECTION_ATTEMPTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("projection_attempts_v1");

// Projection counters: key = b"completion" (the last completion sequence,
// 8 BE), b"staged-bytes" and b"staged-entries" (versions not yet compacted,
// 8 BE each).
pub const PROJECTION_COUNTERS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("projection_counters_v1");

// Recovery enumeration marker: key = b"pass", value = [u8; 1] (1 once the
// enumeration of the obligations present at open finished). An operator
// signal: neither reclamation nor discovery completeness depends on it.
pub const SETTLEMENT_PASS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("settlement_pass_v1");

// Storage retirement records: key = [instance], value = the encoded
// `retirement_record::RetirementRecord` (empty: legacy; [1]: a creation
// proven never committed; [2][governing][request]: a governed intent;
// [3][governing][decision]: a governed release). A record locates evidence
// and fences the instance's storage when it opens; it never authorizes a
// removal by itself: every destructive use verifies the decision it names
// from the governing namespace's published evidence (`release_verified`).
// Committed before the instance's directory is removed; a retirement a
// crash interrupted is completed by recovery only against storage of
// exactly that instance, and reclamation and discovery tell an instance's
// verified release from storage that is merely missing.
pub const RETIRED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("retired_namespaces_v1");

// Namespaces whose derived indexes have a repair started and not finished:
// key = ns_uuid, value = (). Written before the namespace's repair state,
// removed after it, so a restart resumes every repair whose fence is
// durable in its namespace (`index_repair`).
pub const INDEX_REPAIRS: TableDefinition<&[u8], ()> = TableDefinition::new("index_repairs_v1");

// =============================================================================
// Registry database: directory
// =============================================================================

// Namespace existence: key = ns_uuid, value = ()
pub const NAMESPACES: TableDefinition<&[u8], ()> = TableDefinition::new("namespaces_v1");

// Alias resolution: alias_key (protocol-scoped string) -> [uuid:16] when
// committed, [uuid:16][0x01] while reserved by an execution not yet
// resolved: a reservation refuses every other claimant and resolves to
// nothing (`namespace_directory_journal`). Same values in
// `NAMESPACE_NAMES`.
pub const NAMESPACE_ALIASES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("namespace_aliases");

// Directory changes an execution made before its commit: key =
// [ns_uuid:16][alias_key bytes] for an alias it reserved or moves away
// from, [ns_uuid:16] alone for a deletion of every alias. Written in the
// registry transaction that makes the change; resolved against the
// namespace's committed record and removed under its writer gate
// (`namespace_directory_journal`).
pub const DIRECTORY_JOURNAL: TableDefinition<&[u8], ()> =
    TableDefinition::new("directory_journal_v1");

// Namespace records: UUID -> dCBOR NamespaceInfo. In a namespace database
// the namespace's own authoritative record, written by its executions; in
// the registry the projection settled from `NamespaceUpdate` evidence,
// which the directory reads serve.
pub const NAMESPACE_RECORDS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("namespace_records");

// Forward lookup: name -> UUID (for resolve without protocol)
pub const NAMESPACE_NAMES: TableDefinition<&str, &[u8]> = TableDefinition::new("namespace_names");

// =============================================================================
// Registry database: registry-wide authority and node-local state
// =============================================================================

// Epoch signing authority history, a projection of the governing evidence.
// Key 0: the origin authority's length-prefixed (algorithm, public key).
// Key n >= 1: the n-th admitted transition (canonical succession record,
// outgoing key, incoming key, activation), written after the governing
// epoch that publishes it under `_authority/{n}` in its control namespace
// committed, and re-verified against that evidence on every open.
pub const AUTHORITY_HISTORY: TableDefinition<u64, &[u8]> =
    TableDefinition::new("authority_history_v1");

// The activation in progress: key = b"pending", encrypted value =
// [position:8 BE][control:16][incarnation:16][record identity key bytes].
// Written before the governing epoch is published and removed with the
// history row that projects it, or once the epoch is known not to have
// committed; a restart resolves one left behind from the control
// namespace's evidence (`authority_evidence`).
pub const ACTIVATION_INTENT: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("activation_intent_v1");

// Registry-wide reserved causal ceiling: key = b"reserved-causal-ceiling",
// encrypted value = big-endian i64. Every issued timestamp is below a
// durable reservation, so the ceiling alone recovers the time floor of
// the whole registry; committed floors are per namespace (`TIME_STATE`
// in the namespace database). Written only by `reserve_time`, never by a
// publication.
pub const TIME_RESERVATION: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("time_reservation_v1");

// Latest timestamp of any settled epoch: key = b"settled-epoch-time",
// encrypted value = big-endian i64. Raised in the registry transaction that
// advances `SETTLED`, so at open it bounds every epoch no pending marker
// names; recovery raises the bound further from the heads of the instances
// it visits. Read by authority rotation through `latest_epoch_ms`.
pub const EPOCH_TIME_BOUND: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("epoch_time_bound_v1");

// Binding records: sigma key_bytes -> [kappa_key_bytes | base_nonce:8 | plaintext_size:8]
pub const BINDING_RECORDS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("binding_records_v1");

// Compression records: uncompressed kappa key_bytes -> [storage_kappa_key_bytes | algo | uncompressed_size:8]
pub const COMPRESSION_RECORDS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("compression_records_v1");

// -- Identity records shared across namespaces -------------------------------

// Source index: key = source string, values = ns_uuids (16 bytes each)
pub const ID_BINDING_SRC_IDX: MultimapTableDefinition<&str, &[u8]> =
    MultimapTableDefinition::new("id_binding_src_idx");

// Primary: key = assertion kappa key_bytes, value = dCBOR IdentityAssertion
pub const ID_ASSERTIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("id_assertions");

// Asserter index: key = asserter kappa key_bytes, values = assertion kappa key_bytes
pub const ID_ASSERTION_ASSERTER_IDX: MultimapTableDefinition<&[u8], &[u8]> =
    MultimapTableDefinition::new("id_assertion_asserter_idx");

// Subject index: key = "subject\0facet" string
// Values = [asserter_key_bytes | assertion_kappa_key_bytes] concatenated.
pub const ID_ASSERTION_SUBJECT_IDX: MultimapTableDefinition<&str, &[u8]> =
    MultimapTableDefinition::new("id_assertion_subject_idx");

pub const ID_REVOCATIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("id_revocations");
pub const ID_REVOCATION_ASSERTER_IDX: MultimapTableDefinition<&[u8], &[u8]> =
    MultimapTableDefinition::new("id_revocation_asserter_idx");

// key = old anchor kappa key_bytes, value = dCBOR Succession
pub const ID_SUCCESSIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("id_successions");

// key = anchor kappa key_bytes, value = links in the longest chain ending at
// the anchor. Written in the same transaction as every ID_SUCCESSIONS insert.
pub const ID_SUCCESSION_DEPTH: TableDefinition<&[u8], u64> =
    TableDefinition::new("id_succession_depth_v1");

pub const ID_WATERMARKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("id_watermarks");
pub const ID_WATERMARK_ASSERTER_IDX: MultimapTableDefinition<&[u8], &[u8]> =
    MultimapTableDefinition::new("id_watermark_asserter_idx");

pub const ID_HANDLES: TableDefinition<&str, &[u8]> = TableDefinition::new("id_handles");
pub const ID_HANDLE_ANCHOR_IDX: MultimapTableDefinition<&[u8], &str> =
    MultimapTableDefinition::new("id_handle_anchor_idx");

// Authorization rows (`identity_local.rs`). In a namespace database the
// admitted row: key = session id / credential id / "current", value =
// ciphertext bound to the key. In the registry the settled locator:
// `[ns_uuid:16] ++ ciphertext`; reads decide from the namespace row.
pub const ID_SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("id_sessions");

pub const ID_CREDENTIALS: TableDefinition<&str, &[u8]> = TableDefinition::new("id_credentials");
pub const ID_CREDENTIAL_GRACE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("id_credential_grace");

pub const ID_TRUST: TableDefinition<&str, &[u8]> = TableDefinition::new("id_trust");

// key = anchor kappa key_bytes, value = dCBOR Vec<DeviceBinding>
pub const ID_DEVICE_BINDINGS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("id_device_bindings");

// key = anchor kappa key_bytes, value = dCBOR Vec<PrekeyBinding>
pub const ID_PREKEY_BINDINGS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("id_prekey_bindings");

// key = anchor kappa key_bytes, value = dCBOR LocatorRecord
pub const ID_LOCATOR_RECORDS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("id_locator_records");

// key = anchor kappa key_bytes, value = dCBOR RevocationCommitment
pub const ID_REVOCATION_COMMITMENTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("id_revocation_commitments");

/// Create every registry table in `txn`, so readers never observe a
/// missing table. The identity tables are namespace tables; in the
/// registry only the authorization tables exist, holding claims
/// (`identity_local`).
pub(crate) fn create_registry_tables(txn: &redb::WriteTransaction) -> Result<(), redb::TableError> {
    for table in [
        SETTLED,
        PROJECTION_VERSIONS,
        PROJECTION_LOG,
        PROJECTION_COMPLETED,
        PROJECTION_INSTANCES,
        PROJECTION_ATTEMPTS,
        PROJECTION_COUNTERS,
        SETTLEMENT_PASS,
        RETIRED,
        TIME_RESERVATION,
        EPOCH_TIME_BOUND,
        ACTIVATION_INTENT,
        BINDING_RECORDS,
        COMPRESSION_RECORDS,
    ] {
        txn.open_table(table)?;
    }
    for table in [
        ID_SESSIONS,
        ID_CREDENTIALS,
        ID_CREDENTIAL_GRACE,
        ID_TRUST,
        NAMESPACE_ALIASES,
        NAMESPACE_NAMES,
    ] {
        txn.open_table(table)?;
    }
    txn.open_table(NAMESPACES)?;
    txn.open_table(INDEX_REPAIRS)?;
    txn.open_table(DIRECTORY_JOURNAL)?;
    txn.open_table(AUTHORITY_HISTORY)?;
    Ok(())
}
