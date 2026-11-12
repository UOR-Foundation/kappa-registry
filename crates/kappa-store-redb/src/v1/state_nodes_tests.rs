//! Validated persistence of index and history nodes and the reclamation
//! lifecycle, over a real encrypted namespace database.

use kappa_store::StoreError;
use kappa_types::merkle::{peak_positions, StreamingTree};
use kappa_types::namespace::NamespaceRef;
use kappa_types::state_index::{self, Change, Node, Update, EMPTY};
use kappa_types::work::{Dimension, WorkLimit, WorkMeter};
use kappa_types::{AuthorityState, NamespaceState};
use redb::ReadableTable;

use super::{history_context, node_context, Nodes, HISTORY_NODES, STATE_NODES};
use crate::control_plane::Guarantees;
use crate::epoch::epoch_idx_key;
use crate::tables::EPOCH_INDEX;
use crate::test_support::TestWriter;
use crate::PersistentStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn store() -> Result<PersistentStore, kappa_fixture::SetupError> {
    Ok(crate::test_support::PersistentSpec::new()
        .encryption_key([7; 32])
        .acquire()?
        .into_store())
}

fn writer(store: &PersistentStore, name: &str) -> Result<(NamespaceRef, TestWriter), StoreError> {
    let ns = store.create_for_test(name, None, Guarantees::NONE)?;
    let writer = store.test_writer(&ns)?;
    Ok((ns, writer))
}

fn path(seed: u8) -> [u8; 32] {
    kappa_types::sha256_raw(&[seed])
}

fn set(seed: u8, value: u8) -> Change {
    (path(seed), Some([value; 32]))
}

/// Apply `changes` to `root` over the nodes the transaction holds and store
/// the update as epoch `epoch`'s: index bookkeeping only, with no signed
/// epoch, ledger, committed state or head.
fn apply_and_store_index_update(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    epoch: u64,
    root: [u8; 32],
    changes: &[Change],
) -> Result<Update, StoreError> {
    let update = {
        let source = Nodes {
            store,
            table: txn.open_table(STATE_NODES).map_err(crate::error::redb)?,
        };
        state_index::apply(&source, root, changes, &mut WorkMeter::unbounded())?
    };
    store.write_index_update(txn, epoch, &update, &mut WorkMeter::unbounded())?;
    Ok(update)
}

fn lookup(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    root: [u8; 32],
    seed: u8,
    meter: &mut WorkMeter,
) -> Result<Option<[u8; 32]>, StoreError> {
    let source = Nodes {
        store,
        table: txn.open_table(STATE_NODES).map_err(crate::error::redb)?,
    };
    let (value, proof) = state_index::lookup(&source, root, &path(seed), meter)?;
    assert!(state_index::verify(
        &root,
        &path(seed),
        value.as_ref(),
        &proof
    ));
    Ok(value)
}

/// Replace `ns`'s epoch index with synthetic entries for `epochs`, each
/// naming a root identity: a fabricated retention horizon for exercising
/// the lifecycle bookkeeping, not a production retention operation.
fn synthetic_horizon(
    txn: &redb::WriteTransaction,
    ns: &NamespaceRef,
    epochs: std::ops::RangeInclusive<u64>,
) -> Result<(), StoreError> {
    let mut index = txn.open_table(EPOCH_INDEX).map_err(crate::error::redb)?;
    index
        .retain(|key, _| !key.starts_with(ns.id()))
        .map_err(crate::error::redb)?;
    for epoch in epochs {
        let root = kappa_store::Kappa::sha256(&epoch.to_be_bytes()).key_bytes();
        index
            .insert(epoch_idx_key(ns, epoch).as_slice(), root.as_slice())
            .map_err(crate::error::redb)?;
    }
    Ok(())
}

/// A validly encoded and validly encrypted node held under another node's
/// hash is refused by updates and lookups alike: the adapter establishes
/// the correspondence the shared algorithm relies on.
#[test]
fn a_node_held_under_another_hash_is_refused() -> TestResult {
    let store = store()?;
    let (_, writer) = writer(&store, "node-swap")?;
    let txn = &writer.txn;
    let first = apply_and_store_index_update(&store, txn, 2, EMPTY, &[set(1, 1)])?;
    let second = apply_and_store_index_update(&store, txn, 3, EMPTY, &[set(2, 2)])?;
    let foreign = Node::from_bytes(
        &store.decrypt_bytes(
            &node_context(&second.root),
            txn.open_table(STATE_NODES)?
                .get(second.root.as_slice())?
                .ok_or("second root not held")?
                .value(),
        )?,
    )?;
    let forged = store.encrypt_bytes(&node_context(&first.root), &foreign.to_bytes())?;
    txn.open_table(STATE_NODES)?
        .insert(first.root.as_slice(), forged.as_slice())?;
    assert!(matches!(
        lookup(&store, txn, first.root, 1, &mut WorkMeter::unbounded()),
        Err(StoreError::Internal(_))
    ));
    let source = Nodes {
        store: &store,
        table: txn.open_table(STATE_NODES)?,
    };
    assert!(matches!(
        state_index::apply(
            &source,
            first.root,
            &[set(3, 3)],
            &mut WorkMeter::unbounded()
        ),
        Err(StoreError::Internal(_))
    ));
    Ok(())
}

/// A node a reachable hash names but the database does not hold is
/// unavailable, and a read the allowance does not admit is refused before
/// it is made: the same missing node then reports the budget, not its
/// absence.
#[test]
fn a_missing_node_is_unavailable_and_reads_are_charged_first() -> TestResult {
    let store = store()?;
    let (_, writer) = writer(&store, "node-missing")?;
    let txn = &writer.txn;
    let missing = [9; 32];
    assert!(matches!(
        lookup(&store, txn, missing, 1, &mut WorkMeter::unbounded()),
        Err(StoreError::Unavailable(_))
    ));
    let mut short = WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesHashed, 0));
    assert!(matches!(
        lookup(&store, txn, missing, 1, &mut short),
        Err(StoreError::WorkRefused(
            kappa_types::work::WorkExhausted::Limit {
                dimension: Dimension::BytesHashed,
                limit: 0,
                used: 0,
                ..
            }
        ))
    ));
    Ok(())
}

/// Storing an update is charged at its bound before any node is hashed or
/// written: an allowance one hash short refuses it and leaves the table as
/// it was.
#[test]
fn an_index_update_is_charged_before_it_is_stored() -> TestResult {
    let store = store()?;
    let (_, writer) = writer(&store, "node-charge")?;
    let txn = &writer.txn;
    let update = {
        let source = Nodes {
            store: &store,
            table: txn.open_table(STATE_NODES)?,
        };
        state_index::apply(
            &source,
            EMPTY,
            &[set(1, 1), set(2, 2)],
            &mut WorkMeter::unbounded(),
        )?
    };
    let hashed = update.created.len() as u64 * state_index::NODE_BYTES;
    let mut short = WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesHashed, hashed - 1));
    assert!(matches!(
        store.write_index_update(txn, 2, &update, &mut short),
        Err(StoreError::WorkRefused(kappa_types::work::WorkExhausted::Limit {
            dimension: Dimension::BytesHashed, limit, used: 0, requested,
        })) if limit == hashed - 1 && requested == hashed
    ));
    assert!(txn
        .open_table(STATE_NODES)?
        .get(update.root.as_slice())?
        .is_none());
    let mut exact = WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesHashed, hashed));
    store.write_index_update(txn, 2, &update, &mut exact)?;
    assert!(txn
        .open_table(STATE_NODES)?
        .get(update.root.as_slice())?
        .is_some());
    Ok(())
}

/// A history continuation resumes exactly from the held peaks, and every
/// way the peaks can disagree with the committed state is refused: a
/// missing peak, a peak of the wrong length, a peak of the right length
/// with the wrong hash, and an allowance that does not admit the reads.
#[test]
fn history_resumes_only_from_the_committed_peaks() -> TestResult {
    let store = store()?;
    // This independent thirteen-leaf model starts at an empty history.
    // Opening storage directly avoids publishing a genesis leaf before it.
    let ns = NamespaceRef::deterministic("history-resume");
    let writer = store.test_writer(&ns)?;
    let txn = &writer.txn;
    let mut tree = StreamingTree::new();
    let mut nodes = Vec::new();
    for leaf in 0u64..13 {
        tree = tree.push(&leaf.to_be_bytes(), |position, node| {
            nodes.push((position, *node));
            Ok::<_, std::convert::Infallible>(())
        })?;
    }
    store.write_history_nodes(txn, &nodes, &mut WorkMeter::unbounded())?;
    assert!(matches!(
        store.write_history_nodes(txn, &nodes[..1], &mut WorkMeter::unbounded()),
        Err(StoreError::Internal(_))
    ));
    let mut incarnation = [0; 16];
    incarnation[15] = 1;
    let authority = AuthorityState::new(*ns.id(), incarnation, None, "h".into(), None, false)?;
    let state = NamespaceState::new(&authority, EMPTY, tree.root(), tree.leaves());
    let resumed = store.resume_history(
        &txn.open_table(HISTORY_NODES)?,
        Some(&state),
        &mut WorkMeter::unbounded(),
    )?;
    assert_eq!(resumed, tree);
    assert_eq!(
        store.resume_history(
            &txn.open_table(HISTORY_NODES)?,
            None,
            &mut WorkMeter::unbounded()
        )?,
        StreamingTree::new()
    );
    let peak = *peak_positions(tree.leaves())
        .last()
        .ok_or("thirteen leaves have peaks")?;
    let short = store.encrypt_bytes(&history_context(peak), &[1; 31])?;
    let wrong = store.encrypt_bytes(&history_context(peak), &[1; 32])?;
    let resume = |meter: &mut WorkMeter| {
        store.resume_history(
            &txn.open_table(HISTORY_NODES).map_err(crate::error::redb)?,
            Some(&state),
            meter,
        )
    };
    let mut none = WorkMeter::new(WorkLimit::unbounded().with(Dimension::Entries, 0));
    assert!(matches!(
        resume(&mut none),
        Err(StoreError::WorkRefused(
            kappa_types::work::WorkExhausted::Limit {
                dimension: Dimension::Entries,
                limit: 0,
                used: 0,
                requested: 3,
            }
        ))
    ));
    txn.open_table(HISTORY_NODES)?
        .insert(peak, short.as_slice())?;
    assert!(matches!(
        resume(&mut WorkMeter::unbounded()),
        Err(StoreError::Internal(_))
    ));
    txn.open_table(HISTORY_NODES)?
        .insert(peak, wrong.as_slice())?;
    assert!(matches!(
        resume(&mut WorkMeter::unbounded()),
        Err(StoreError::Internal(_))
    ));
    txn.open_table(HISTORY_NODES)?.remove(peak)?;
    assert!(matches!(
        resume(&mut WorkMeter::unbounded()),
        Err(StoreError::Unavailable(_))
    ));
    Ok(())
}

/// The lifecycle bookkeeping against a synthetic retention horizon, reuse
/// included: root 1 holds A, root 2 supersedes it, root 3 holds A again.
/// While root 2 is within the horizon nothing it reaches goes; once only
/// root 3 is, the nodes only root 2 reached go and A, which root 3 reaches
/// again, stays. This exercises the bookkeeping only; it does not show that
/// production retention advances the horizon (see the module documentation).
#[test]
fn reclamation_bookkeeping_spares_every_node_a_root_within_the_horizon_reaches() -> TestResult {
    let store = store()?;
    let (ns, writer) = writer(&store, "node-reclaim")?;
    let txn = &writer.txn;
    let r1 = apply_and_store_index_update(&store, txn, 1, EMPTY, &[set(1, 1), set(2, 2)])?;
    let r2 = apply_and_store_index_update(&store, txn, 2, r1.root, &[set(1, 9)])?;
    let r3 = apply_and_store_index_update(&store, txn, 3, r2.root, &[set(1, 1)])?;
    assert_eq!(r3.root, r1.root, "root 3 holds exactly root 1's entries");

    synthetic_horizon(txn, &ns, 1..=3)?;
    assert_eq!(
        store.reclaim_index_nodes(txn, &ns, &mut WorkMeter::unbounded())?,
        0
    );
    synthetic_horizon(txn, &ns, 2..=3)?;
    assert_eq!(
        store.reclaim_index_nodes(txn, &ns, &mut WorkMeter::unbounded())?,
        0,
        "every node superseded at 2 is reached again by root 3"
    );
    assert_eq!(
        lookup(&store, txn, r2.root, 1, &mut WorkMeter::unbounded())?,
        Some([9; 32])
    );

    synthetic_horizon(txn, &ns, 3..=3)?;
    let mut none = WorkMeter::new(WorkLimit::unbounded().with(Dimension::Entries, 0));
    assert!(
        matches!(
            store.reclaim_index_nodes(txn, &ns, &mut none),
            Err(StoreError::WorkRefused(
                kappa_types::work::WorkExhausted::Limit {
                    dimension: Dimension::Entries,
                    limit: 0,
                    used: 0,
                    requested: 1,
                }
            ))
        ),
        "the horizon read is charged before it is made"
    );
    let mut horizon_only = WorkMeter::new(WorkLimit::unbounded().with(Dimension::Entries, 1));
    assert_eq!(
        store.reclaim_index_nodes(txn, &ns, &mut horizon_only)?,
        0,
        "a node the allowance does not admit is deferred before its entry is read"
    );
    assert_eq!(horizon_only.used().get(Dimension::Entries), 1);
    let removed = store.reclaim_index_nodes(txn, &ns, &mut WorkMeter::unbounded())?;
    assert!(
        removed > 0,
        "root 2's own nodes are unreachable once it is released"
    );
    for seed in [1, 2] {
        assert!(lookup(&store, txn, r3.root, seed, &mut WorkMeter::unbounded())?.is_some());
    }
    assert!(lookup(&store, txn, r2.root, 1, &mut WorkMeter::unbounded()).is_err());
    assert_eq!(
        store.reclaim_index_nodes(txn, &ns, &mut WorkMeter::unbounded())?,
        0,
        "a node is reclaimed once"
    );
    Ok(())
}
