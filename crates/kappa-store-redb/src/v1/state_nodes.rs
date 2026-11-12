//! The namespace's authenticated state machinery, persisted natively in
//! its own database: the nodes of its current-state index
//! (`kappa_types::state_index`) by hash, the emitted nodes of its history
//! log (`kappa_types::merkle`) by position, and the lifecycle of every held
//! index node, from which superseded nodes are reclaimed.
//!
//! Rows are encrypted under the table key bound to their key, and every
//! read is validated against what its key commits: an index node must hash
//! to the hash it is read by, and the history peaks read must resume the
//! log to exactly the size and root the predecessor's state commits. A node
//! a reachable hash or position names that the database does not hold is
//! unavailable, never absent. Every read is charged before it is made.
//!
//! Everything here is written by the seal in the epoch's own transaction,
//! so it commits atomically with the root that reaches it, and an aborted
//! or retained publication leaves nothing behind: a node deletion commits
//! only with the epoch that decided it, as redb itself frees retired pages
//! only after the commit that retired them is durable.
//!
//! Reclamation. The index roots of a namespace form one chain, root `k`
//! being root `k - 1` with epoch `k`'s update applied. An update rewrites
//! only the paths it touches: every node it does not report keeps its
//! reachability, a node it supersedes is absent from root `k`, and a node
//! it creates is present in root `k` (a node both superseded and created by
//! one update is still in the tree). Nodes of one tree are distinct, so a
//! node is reachable from root `k` exactly when the latest lifecycle event
//! at or before `k` is a creation. `STATE_NODE_EVENTS` keeps that latest
//! event per held node, and `STATE_NODE_RECLAIM` every node whose latest
//! event is a supersession, by epoch. A root is retained while the epoch
//! index holds it, and the index is released only from its oldest entry,
//! so the retained roots are the epochs from the oldest the index holds
//! (the horizon) to the head. A node superseded at `s` and not created
//! since is unreachable from every root from `s` on, so it is deleted once
//! `s` is at or below the horizon; one created again leaves the queue. A
//! reader holding an older snapshot reads it through redb's own snapshot
//! isolation, unaffected by a later transaction's deletions.
//!
//! No production operation releases an epoch index entry: every root a
//! namespace sealed stays servable (`EpochStore::epoch_get_by_number`) and
//! retained by its successor's predecessor edge, so the horizon is the
//! genesis epoch, nothing is reclaimed while the storage instance lives,
//! and the instance's nodes go with its storage (`storage_retirement`).

use redb::{ReadableTable, TableDefinition};

use kappa_store::namespace_commitment::HistoryNode;
use kappa_store::StoreError;
use kappa_types::merkle::{peak_positions, StreamingTree, NODE_HASH_INPUT};
use kappa_types::namespace::NamespaceRef;
use kappa_types::state_index::{Node, NodeSource, Update, NODE_BYTES};
use kappa_types::work::{Dimension, WorkMeter};
use kappa_types::NamespaceState;

use crate::encrypted::bound;
use crate::tables::EPOCH_INDEX;
use crate::PersistentStore;

#[cfg(test)]
#[path = "state_nodes_tests.rs"]
mod tests;

// Current-state index nodes: key = node hash (32 bytes), value = the node's
// 65-byte persisted form, encrypted under "state_node" bound to the hash.
pub const STATE_NODES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state_nodes_v1");

// The latest lifecycle event of each held index node: key = node hash,
// value = [kind:1 (0 created, 1 superseded)][epoch number:8 BE].
pub const STATE_NODE_EVENTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("state_node_events_v1");

// Index nodes whose latest event is a supersession: key = [epoch number:8
// BE][node hash:32], ordered so reclamation reads the oldest first.
pub const STATE_NODE_RECLAIM: TableDefinition<&[u8], ()> =
    TableDefinition::new("state_node_reclaim_v1");

// History log nodes: key = emission position, value = the 32-byte node
// hash, encrypted under "history_node" bound to the position.
pub const HISTORY_NODES: TableDefinition<u64, &[u8]> = TableDefinition::new("history_nodes_v1");

/// Create the state machinery tables of a namespace database.
pub(crate) fn create_tables(txn: &redb::WriteTransaction) -> Result<(), redb::TableError> {
    txn.open_table(STATE_NODES)?;
    txn.open_table(STATE_NODE_EVENTS)?;
    txn.open_table(STATE_NODE_RECLAIM)?;
    txn.open_table(HISTORY_NODES)?;
    Ok(())
}

fn node_context(hash: &[u8; 32]) -> String {
    bound("state_node", hash)
}

fn history_context(position: u64) -> String {
    bound("history_node", &position.to_be_bytes())
}

const CREATED: u8 = 0;
const SUPERSEDED: u8 = 1;

/// A lifecycle event row.
fn event(kind: u8, epoch: u64) -> [u8; 9] {
    let mut row = [0u8; 9];
    row[0] = kind;
    row[1..].copy_from_slice(&epoch.to_be_bytes());
    row
}

/// A reclamation queue key.
fn queued(epoch: u64, hash: &[u8; 32]) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..8].copy_from_slice(&epoch.to_be_bytes());
    key[8..].copy_from_slice(hash);
    key
}

/// Rows one queued node's reclamation reads or removes: its queue entry,
/// its event, its node and its event again.
const RECLAIM_ENTRIES: u64 = 4;

/// Bytes of one node hash.
const HASH_BYTES: u64 = 32;

/// Bytes one queued node's reclamation holds: its queue key.
const RECLAIM_BYTES: u64 = 40;

/// The index nodes a table view holds, read and validated through
/// `NodeSource`: a write transaction's (the seal's) or a snapshot's.
pub(crate) struct Nodes<'s, T> {
    pub(crate) store: &'s PersistentStore,
    pub(crate) table: T,
}

impl<T: ReadableTable<&'static [u8], &'static [u8]>> NodeSource for Nodes<'_, T> {
    fn node(&self, hash: &[u8; 32]) -> Result<Node, StoreError> {
        let stored = self
            .table
            .get(hash.as_slice())
            .map_err(crate::error::redb)?
            .ok_or_else(|| {
                StoreError::Unavailable(format!(
                    "state index node {} is not held by the namespace",
                    hex::encode(hash)
                ))
            })?;
        let bytes = self
            .store
            .decrypt_bytes(&node_context(hash), stored.value())?;
        let node = Node::from_bytes(&bytes)?;
        if node.hash() != *hash {
            return Err(StoreError::Internal(format!(
                "state index node held under {} hashes elsewhere",
                hex::encode(hash)
            )));
        }
        Ok(node)
    }
}

impl PersistentStore {
    /// Hold every node epoch `epoch`'s `update` created and record the
    /// lifecycle of every node it created or superseded, in the seal's
    /// transaction. Every row is charged to `meter` before any is written.
    pub(crate) fn write_index_update(
        &self,
        txn: &redb::WriteTransaction,
        epoch: u64,
        update: &Update,
        meter: &mut WorkMeter,
    ) -> Result<(), StoreError> {
        // Charged at its bound before any of it is done: every created node
        // hashed once, its persisted form and its hash held, and at most
        // three rows written per created node and two per superseded one.
        let creations = update.created.len() as u64;
        let supersessions = update.superseded.len() as u64;
        meter.charge_all(&[
            (
                Dimension::Entries,
                creations
                    .saturating_mul(3)
                    .saturating_add(supersessions.saturating_mul(2)),
            ),
            (Dimension::BytesHashed, creations.saturating_mul(NODE_BYTES)),
            (
                Dimension::BytesAllocated,
                creations.saturating_mul(NODE_BYTES.saturating_add(HASH_BYTES)),
            ),
        ])?;
        // The same fallible allocation supplies the write list and the
        // reachability lookup. No independently allocated tree mirrors it.
        let mut created: Vec<([u8; 32], &Node)> = Vec::new();
        created
            .try_reserve_exact(update.created.len())
            .map_err(|_| StoreError::CapacityExceeded("state node write list".into()))?;
        created.extend(update.created.iter().map(|node| (node.hash(), node)));
        created.sort_unstable_by_key(|(hash, _)| *hash);
        let mut nodes = txn.open_table(STATE_NODES).map_err(crate::error::redb)?;
        let mut events = txn
            .open_table(STATE_NODE_EVENTS)
            .map_err(crate::error::redb)?;
        let mut queue = txn
            .open_table(STATE_NODE_RECLAIM)
            .map_err(crate::error::redb)?;
        for &(hash, node) in &created {
            let stored = self.encrypt_bytes(&node_context(&hash), &node.to_bytes())?;
            nodes
                .insert(hash.as_slice(), stored.as_slice())
                .map_err(crate::error::redb)?;
            let previous = events
                .insert(hash.as_slice(), event(CREATED, epoch).as_slice())
                .map_err(crate::error::redb)?
                .map(|guard| decode_event(&hash, guard.value()))
                .transpose()?;
            if let Some((SUPERSEDED, at)) = previous {
                queue
                    .remove(queued(at, &hash).as_slice())
                    .map_err(crate::error::redb)?;
            }
        }
        for hash in update
            .superseded
            .iter()
            .filter(|hash| created.binary_search_by(|(key, _)| key.cmp(hash)).is_err())
        {
            events
                .insert(hash.as_slice(), event(SUPERSEDED, epoch).as_slice())
                .map_err(crate::error::redb)?;
            queue
                .insert(queued(epoch, hash).as_slice(), ())
                .map_err(crate::error::redb)?;
        }
        Ok(())
    }

    /// The oldest epoch of `ns` whose root the epoch index still holds, or
    /// `None` when it holds none. The entry must name a root identity.
    fn retention_horizon(
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
    ) -> Result<Option<u64>, StoreError> {
        let index = txn.open_table(EPOCH_INDEX).map_err(crate::error::redb)?;
        let prefix = ns.id().as_slice();
        let mut range = match Self::prefix_successor(prefix) {
            Some(end) => index.range(prefix..end.as_slice()),
            None => index.range(prefix..),
        }
        .map_err(crate::error::redb)?;
        let Some(entry) = range.next() else {
            return Ok(None);
        };
        let (key, root) = entry.map_err(crate::error::redb)?;
        let number: [u8; 8] = key.value()[prefix.len()..].try_into().map_err(|_| {
            StoreError::Internal("epoch index key is not namespace and number".into())
        })?;
        kappa_store::Kappa::from_key_bytes(root.value())?;
        Ok(Some(u64::from_be_bytes(number)))
    }

    /// Delete the index nodes no retained root of `ns` reaches (see the
    /// module documentation), oldest supersession first, in the seal's
    /// transaction. Returns how many were deleted. Each node's work is
    /// admitted against `meter` before it starts; a node the remaining
    /// allowance does not admit stops the pass without error, and the
    /// queue holds it for the next seal's pass.
    pub(crate) fn reclaim_index_nodes(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        meter: &mut WorkMeter,
    ) -> Result<u64, StoreError> {
        meter.charge(Dimension::Entries, 1)?;
        let Some(horizon) = Self::retention_horizon(txn, ns)? else {
            return Ok(0);
        };
        let per_node = [
            (Dimension::Entries, RECLAIM_ENTRIES),
            (Dimension::BytesAllocated, RECLAIM_BYTES),
        ];
        let candidates = {
            let queue = txn
                .open_table(STATE_NODE_RECLAIM)
                .map_err(crate::error::redb)?;
            let end = horizon.checked_add(1).map(u64::to_be_bytes);
            let mut range = match &end {
                Some(end) => queue.range(..end.as_slice()),
                None => queue.range::<&[u8]>(..),
            }
            .map_err(crate::error::redb)?;
            let mut candidates = Vec::new();
            // A node is admitted before its queue entry is read: one the
            // remaining allowance does not admit stops the pass, and the
            // queue holds it for the next seal's.
            while meter.admits(&per_node).is_ok() {
                let Some(entry) = range.next() else {
                    break;
                };
                meter.charge_all(&per_node)?;
                let (key, _) = entry.map_err(crate::error::redb)?;
                let key: [u8; 40] = key.value().try_into().map_err(|_| {
                    StoreError::Internal("state node reclamation key is not 40 bytes".into())
                })?;
                candidates.push(key);
            }
            candidates
        };
        let mut nodes = txn.open_table(STATE_NODES).map_err(crate::error::redb)?;
        let mut events = txn
            .open_table(STATE_NODE_EVENTS)
            .map_err(crate::error::redb)?;
        let mut queue = txn
            .open_table(STATE_NODE_RECLAIM)
            .map_err(crate::error::redb)?;
        for key in &candidates {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&key[8..]);
            let mut epoch = [0u8; 8];
            epoch.copy_from_slice(&key[..8]);
            let epoch = u64::from_be_bytes(epoch);
            let latest = events
                .get(hash.as_slice())
                .map_err(crate::error::redb)?
                .map(|guard| decode_event(&hash, guard.value()))
                .transpose()?;
            if latest != Some((SUPERSEDED, epoch)) {
                return Err(StoreError::Internal(format!(
                    "state node {} is queued for reclamation at epoch {epoch} but its latest event is {latest:?}",
                    hex::encode(hash)
                )));
            }
            nodes
                .remove(hash.as_slice())
                .map_err(crate::error::redb)?
                .ok_or_else(|| {
                    StoreError::Internal(format!(
                        "state node {} is queued for reclamation but not held",
                        hex::encode(hash)
                    ))
                })?;
            events.remove(hash.as_slice()).map_err(crate::error::redb)?;
            queue.remove(key.as_slice()).map_err(crate::error::redb)?;
        }
        Ok(candidates.len() as u64)
    }

    /// Hold the history nodes one epoch's append emitted, in the seal's
    /// transaction, each row charged to `meter` first. The log is
    /// append-only: a position already held is refused, never overwritten.
    pub(crate) fn write_history_nodes(
        &self,
        txn: &redb::WriteTransaction,
        nodes: &[HistoryNode],
        meter: &mut WorkMeter,
    ) -> Result<(), StoreError> {
        meter.charge(Dimension::Entries, (nodes.len() as u64).saturating_mul(2))?;
        let mut table = txn.open_table(HISTORY_NODES).map_err(crate::error::redb)?;
        for &(position, hash) in nodes {
            if table.get(position).map_err(crate::error::redb)?.is_some() {
                return Err(StoreError::Internal(format!(
                    "history node {position} is already held"
                )));
            }
            let stored = self.encrypt_bytes(&history_context(position), &hash)?;
            table
                .insert(position, stored.as_slice())
                .map_err(crate::error::redb)?;
        }
        Ok(())
    }

    /// The history node at `position` in `table`.
    pub(crate) fn history_node(
        &self,
        table: &impl ReadableTable<u64, &'static [u8]>,
        position: u64,
    ) -> Result<[u8; 32], StoreError> {
        let stored = table
            .get(position)
            .map_err(crate::error::redb)?
            .ok_or_else(|| {
                StoreError::Unavailable(format!(
                    "history node {position} is not held by the namespace"
                ))
            })?;
        self.decrypt_bytes(&history_context(position), stored.value())?
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Internal(format!("history node {position} is not 32 bytes")))
    }

    /// The history log builder as of `predecessor`, the committed state the
    /// next epoch extends: empty at genesis, otherwise resumed from the
    /// peaks `table` holds and checked against the size and root the state
    /// commits. The peak reads, their buffer and the root they bag are
    /// charged to `meter` before any is read.
    pub(crate) fn resume_history(
        &self,
        table: &impl ReadableTable<u64, &'static [u8]>,
        predecessor: Option<&NamespaceState>,
        meter: &mut WorkMeter,
    ) -> Result<StreamingTree, StoreError> {
        let Some(state) = predecessor else {
            return Ok(StreamingTree::new());
        };
        let size = state.history_size();
        // One peak per set bit of the size, known before any is located: its
        // position and its hash held, its row read, and the root bagged.
        let count = u64::from(size.count_ones());
        meter.charge_all(&[
            (Dimension::Entries, count),
            (
                Dimension::BytesAllocated,
                count.saturating_mul(HASH_BYTES.saturating_add(8)),
            ),
            (
                Dimension::BytesHashed,
                count.saturating_sub(1).saturating_mul(NODE_HASH_INPUT),
            ),
        ])?;
        let peaks = peak_positions(size)
            .into_iter()
            .map(|position| self.history_node(table, position))
            .collect::<Result<Vec<_>, _>>()?;
        let history = StreamingTree::resume(size, &peaks).ok_or_else(|| {
            StoreError::Internal(format!("history peaks do not form a log of {size} leaves"))
        })?;
        if history.root() != *state.history_root() {
            return Err(StoreError::Internal(
                "held history nodes resume to a root the predecessor state does not commit".into(),
            ));
        }
        Ok(history)
    }
}

/// The `(kind, epoch)` of the lifecycle event row of `hash`.
fn decode_event(hash: &[u8; 32], row: &[u8]) -> Result<(u8, u64), StoreError> {
    match row.split_first() {
        Some((&kind @ (CREATED | SUPERSEDED), epoch)) => {
            let epoch: [u8; 8] = epoch.try_into().map_err(|_| {
                StoreError::Internal(format!(
                    "state node {} lifecycle row is malformed",
                    hex::encode(hash)
                ))
            })?;
            Ok((kind, u64::from_be_bytes(epoch)))
        }
        _ => Err(StoreError::Internal(format!(
            "state node {} lifecycle row is malformed",
            hex::encode(hash)
        ))),
    }
}
