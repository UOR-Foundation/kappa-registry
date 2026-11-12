//! Settlement's consumer of an epoch's effects: each effect staged as
//! versions of its projection families (`projection_stage`), invisible
//! until the epoch is verified and its attempt completed together with the
//! instance's `SETTLED` checkpoint, in one registry transaction.
//!
//! Content effects: an admitted row is a catalog presence and, for an
//! External row, an allocation owner and the row's allocation; a retirement
//! tombstones what the instance's admission wrote. Directory effects: the
//! admitted assignment and namespace record. Identity effects project the
//! row the namespace held when settlement read it (`settlement_identity`):
//! current state at the epoch's captured snapshot, never a reconstruction
//! of what the epoch alone admitted. A later epoch's settlement of the same
//! instance supersedes it; settlement of an instance is sequential, so a
//! projection is never replaced by one from an older snapshot. Secondary
//! indexes are maintained from the instance's own previous version, so an
//! index member always corresponds to a primary row of the same instance.
//!
//! One ledger element is applied whole or not at all, in two phases within
//! one step's transaction:
//!
//! 1. Preparation decides every version the element's effects write: each
//!    lookup they depend on (the instance's previous version, the holders of
//!    a key across instances, the succession plan) and every copy they make
//!    is charged on the step's meter as it is done; nothing is written. A
//!    refused charge defers the element with nothing applied; the lookups
//!    retain completed preparation. Cross-instance observations are checked
//!    against the projection completion sequence before reuse; an unfinished
//!    holder scan retreats to its last complete group after compaction.
//! 2. Application admits one unit for every prepared write, at exactly what
//!    each costs (`ProjectionStage::write_cost`), and the cursor's
//!    finalization, after checking the element's staging fits the capacity
//!    left; then writes, and finishes the element, inside that unit, which
//!    carries no deadline. Writes of one element never depend on each other:
//!    every lookup reads what earlier elements staged, never this element's.

use std::sync::Arc;

use redb::{TableHandle, WriteTransaction};

use kappa_store::canonical::from_canonical;
use kappa_store::capacity::CapacityPool;
use kappa_store::identity::{HandleRecord, IdentityAssertion, Revocation, Succession, Watermark};
use kappa_store::succession_index::{SuccessionOutcome, plan_succession_link};
use kappa_store::work::{Dimension, Meter, reserve_charged};
use kappa_store::{Kappa, StoreError};
use kappa_types::canonical::Canonical;

use super::SettlementStop;
use super::cursors::{EffectProgress, Element, EpochConsumer};
use super::pending::{MAX_CHECKPOINT_BYTES, checkpoint, checkpoint_of};
use super::stage::Staged;
use super::work::{MAX_ELEMENT_WRITES, SettlementLimits};
use crate::control_plane::encode_assignment;
use crate::identity_local::AuthorizationTable;
use crate::identity_write::encode_subject_idx_value;
use crate::projection::{Family, Version, VersionRef};
use crate::projection_stage::{
    ATTEMPT_VALUE_BYTES, HolderScan, ProjectionStage, Protection, active_attempt, begin_attempt,
    restart_cost,
};
use crate::settlement_identity::{AnchorTable, IdentityEffect};
use crate::storage_instance::StorageInstance;
use crate::tables::{self, PROJECTION_ATTEMPTS, SETTLED};

/// The consumer of one settlement step: stages into the step's registry
/// write transaction.
pub struct Apply<'t> {
    txn: &'t WriteTransaction,
    instance: StorageInstance,
    epoch: u64,
    capacity: u64,
    limits: SettlementLimits,
    /// Live storage of the canonical encodings succession admission holds.
    storage: &'t Arc<CapacityPool>,
    /// Live storage of retained preparation buffers.
    _preparation: &'t Arc<CapacityPool>,
    stage: Option<ProjectionStage<'t>>,
}

/// What a prepared version holds: nothing, an owned payload, a canonical
/// encoding owned with its live reservation (framed straight from it, never
/// copied), or a tombstone.
enum Payload {
    Put(Vec<u8>),
    Encoded(Canonical),
    Tombstone,
}

impl Payload {
    /// The version staging frames from this payload.
    fn as_version_ref(&self) -> VersionRef<'_> {
        match self {
            Self::Put(payload) => VersionRef::Put(payload),
            Self::Encoded(encoded) => VersionRef::Put(encoded.as_ref()),
            Self::Tombstone => VersionRef::Tombstone,
        }
    }
}

/// One version an element's application writes, decided by preparation.
struct Write {
    family: Family,
    key: Vec<u8>,
    member: Option<Vec<u8>>,
    version: Payload,
}

/// Every version one element writes, each owning what it stages until it
/// is written.
#[derive(Default)]
struct Prepared {
    writes: Vec<Write>,
}

/// Preparation of one element's effects, built incrementally and retained
/// with the pending element across deliveries. Two parts:
///
/// - **Immutable writes** derive only from the snapshot-owned effect: keys,
///   decoded records, canonical encoding, assignment bytes. Built once; never
///   invalidated by a registry change.
/// - **Registry-dependent writes** read `stage.latest` or `stage.holders`:
///   the previous allocation, the previous handle, foreign authorization
///   holders, succession plan observations. Retained under the projection's
///   completion protection and rebuilt when that protection changes.
///
/// `next_effect` records progress: effects before it are fully prepared.
/// `writes_per_effect` records how many writes each completed effect
/// produced, so `rebuild_dependent` can truncate to the exact immutable
/// prefix without estimating. A refusal while an effect is prepared removes
/// that effect's partial writes and keeps every completed one, so a
/// resumed preparation never appends an effect's writes twice:
///
/// - `writes_per_effect[..next_effect]` describes the completed effects;
/// - `writes_per_effect[next_effect..]` is zero;
/// - `prepared.writes` holds only the completed effects' writes.
///
/// Every retained preparation passes through `Element::keep_prepared`,
/// which marks its registry-dependent writes as requiring validation
/// ([`Self::retained_between_transactions`]): the next delivery runs in
/// another transaction and validates their protection before reuse.
pub(super) struct ElementPreparation {
    /// Which effect to prepare next. Effects before this index have all
    /// their writes in `prepared`.
    next_effect: usize,
    /// How many writes each completed effect produced, in effect order; the
    /// entries from `next_effect` on are zero.
    writes_per_effect: [usize; super::stage::MAX_ELEMENT_EFFECTS],
    /// Writes completed so far, immutable and registry-dependent together
    /// in effect order.
    prepared: Prepared,
    /// Whether the registry-dependent writes were built in the current
    /// transaction. Set to false when the element is retained across a
    /// commit; the next delivery validates protection before reuse.
    registry_current: bool,
    protection: Option<Protection>,
    authorization_scan: Option<HolderScan>,
}

impl Prepared {
    /// Add `write`, its room charged first: refused, as a defect, past the
    /// most versions one element writes.
    fn push(&mut self, write: Write, work: &mut dyn Meter) -> Result<(), StoreError> {
        if self.writes.len() == MAX_ELEMENT_WRITES {
            return Err(StoreError::Internal(format!(
                "a ledger element prepared more than its {MAX_ELEMENT_WRITES} writes"
            )));
        }
        reserve_charged(work, &mut self.writes)?;
        self.writes.push(write);
        Ok(())
    }
}

/// `bytes` copied into storage allocated fallibly, the allocation and the
/// copy (bytes read) charged before either is made.
fn copy(bytes: &[u8], work: &mut dyn Meter) -> Result<Vec<u8>, StoreError> {
    let length = bytes.len() as u64;
    work.charge_all(&[
        (Dimension::BytesAllocated, length),
        (Dimension::BytesRead, length),
    ])?;
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len()).map_err(|_| {
        StoreError::CapacityExceeded(format!("a copy of {length} bytes could not be allocated"))
    })?;
    out.extend_from_slice(bytes);
    Ok(out)
}

/// `kappa`'s key bytes, charged before they are built.
fn key_of(kappa: &Kappa, work: &mut dyn Meter) -> Result<Vec<u8>, StoreError> {
    work.charge(
        Dimension::BytesAllocated,
        1 + kappa.digest_bytes().len() as u64,
    )?;
    Ok(kappa.key_bytes())
}

/// A version holding a copy of `value`, or a tombstone.
fn put_or_tombstone(value: Option<&[u8]>, work: &mut dyn Meter) -> Result<Payload, StoreError> {
    Ok(match value {
        Some(value) => Payload::Put(copy(value, work)?),
        None => Payload::Tombstone,
    })
}

impl<'t> Apply<'t> {
    pub(super) const fn new(
        txn: &'t WriteTransaction,
        instance: StorageInstance,
        epoch: u64,
        capacity: u64,
        limits: SettlementLimits,
        storage: &'t Arc<CapacityPool>,
        preparation: &'t Arc<CapacityPool>,
    ) -> Self {
        Self {
            txn,
            instance,
            epoch,
            capacity,
            limits,
            storage,
            _preparation: preparation,
            stage: None,
        }
    }

    /// The stage of the attempt in progress, opened on first use on `work`:
    /// a cursor that resumes continues the attempt its earlier steps began.
    fn current(&mut self, work: &mut dyn Meter) -> Result<&mut ProjectionStage<'t>, StoreError> {
        if self.stage.is_none() {
            let attempts = self
                .txn
                .open_table(PROJECTION_ATTEMPTS)
                .map_err(crate::error::redb)?;
            // The instance key built, the attempt row examined and read.
            work.charge_all(&[
                (
                    Dimension::BytesAllocated,
                    u64::from(self.instance.key_len()),
                ),
                (Dimension::Entries, 1),
                (Dimension::BytesRead, ATTEMPT_VALUE_BYTES),
            ])?;
            let attempt = match active_attempt(&attempts, &self.instance)? {
                Some((attempt, epoch)) if epoch == self.epoch => attempt,
                _ => {
                    return Err(StoreError::Conflict(format!(
                        "no settlement attempt of epoch {} of {} is in progress",
                        self.epoch, self.instance
                    )));
                }
            };
            drop(attempts);
            self.stage = Some(ProjectionStage::open(
                self.txn,
                self.instance,
                self.epoch,
                attempt,
                self.capacity,
                self.limits,
                work,
            )?);
        }
        self.stage
            .as_mut()
            .ok_or_else(|| StoreError::Internal("settlement stage not opened".into()))
    }

    /// The epoch is verified: complete its attempt and advance `SETTLED` to
    /// it, in the step's transaction, on `work`. The checkpoint must be the
    /// epoch's predecessor, so effects are never completed out of order.
    pub(super) fn complete(mut self, root: &Kappa, work: &mut dyn Meter) -> Result<(), StoreError> {
        // The root's own locator is the epoch's last staged row; an epoch
        // with no other effect still stages it and completes its attempt.
        let key = key_of(root, work)?;
        self.current(work)?
            .write(Family::EpochRoot, &key, None, VersionRef::Put(&[]), work)?;
        let stage = self
            .stage
            .take()
            .ok_or_else(|| StoreError::Internal("settlement stage not opened".into()))?;
        stage.complete()?;
        let mut settled = self.txn.open_table(SETTLED).map_err(crate::error::redb)?;
        // The predecessor checkpoint: one row examined, its longest value
        // read and decoded, the instance key and the decoded root built.
        work.charge_all(&[
            (Dimension::Entries, 1),
            (
                Dimension::BytesAllocated,
                u64::from(self.instance.key_len()),
            ),
            (Dimension::BytesRead, MAX_CHECKPOINT_BYTES as u64),
            (Dimension::BytesDecoded, MAX_CHECKPOINT_BYTES as u64),
            (Dimension::BytesAllocated, MAX_CHECKPOINT_BYTES as u64),
        ])?;
        let previous = checkpoint_of(&settled, &self.instance)?.map_or(0, |(number, _)| number);
        if previous.checked_add(1) != Some(self.epoch) {
            return Err(StoreError::Internal(format!(
                "settlement of epoch {} after checkpoint {previous}",
                self.epoch
            )));
        }
        // `[epoch_number:8][root key_bytes]`, the root key built for it.
        let root_key = 1 + root.digest_bytes().len() as u64;
        work.charge_all(&[
            (Dimension::BytesAllocated, root_key),
            (Dimension::BytesAllocated, 8 + root_key),
        ])?;
        let value = checkpoint(self.epoch, root);
        settled
            .insert(self.instance.key().as_slice(), value.as_slice())
            .map_err(crate::error::redb)?;
        Ok(())
    }
}

impl EpochConsumer for Apply<'_> {
    /// Begin a new attempt and open its stage as one unit admitted whole
    /// before anything is written (`restart_cost`): a refusal leaves
    /// `PROJECTION_ATTEMPTS` unchanged and the restart owed; once admitted,
    /// nothing inside it can be refused for work, and any database failure
    /// propagates and abandons the step's transaction.
    fn restart(&mut self, work: &mut dyn Meter) -> Result<(), StoreError> {
        let bound = restart_cost(&self.instance)?;
        let mut unit = work.admit(&bound.as_bound())?;
        self.stage = None;
        // Inside the admitted unit a refusal is a bound below the work it
        // admits, a defect: never a refusal the caller may retain the cursor
        // over, since the attempt row may already be written.
        let restarted = (|| {
            let attempt = begin_attempt(self.txn, &self.instance, self.epoch, &mut unit)?;
            ProjectionStage::open(
                self.txn,
                self.instance,
                self.epoch,
                attempt,
                self.capacity,
                self.limits,
                &mut unit,
            )
        })();
        let stage = restarted.map_err(|error| match error {
            StoreError::WorkRefused(refused) => StoreError::Internal(format!(
                "settlement restart exceeded its admitted bound: {refused}"
            )),
            other => other,
        })?;
        self.stage = Some(stage);
        Ok(())
    }

    fn apply(
        &mut self,
        mut element: Element<'_>,
        work: &mut dyn Meter,
    ) -> Result<EffectProgress, StoreError> {
        let ns = *self.instance.namespace();
        let storage = self.storage;
        let capacity = self.capacity;
        let stage = self.current(work)?;

        // Resume or start preparation. Immutable writes already prepared
        // are kept; registry-dependent writes are validated below before
        // any new preparation or application can use them.
        let mut prep = match element.take_prepared() {
            Some(retained) => retained,
            None => ElementPreparation {
                next_effect: 0,
                writes_per_effect: [0; super::stage::MAX_ELEMENT_EFFECTS],
                prepared: Prepared::default(),
                registry_current: true,
                protection: None,
                authorization_scan: None,
            },
        };

        // Incremental preparation: resume from where we left off.
        let preparation = (|| {
            if prep.protection.is_none() || !prep.registry_current {
                let protection = stage.protection(work)?;
                if prep
                    .protection
                    .is_some_and(|previous| previous != protection)
                {
                    prep.rebuild_dependent(element.effects());
                    prep.authorization_scan = None;
                } else if !prep.registry_current {
                    if let Some(scan) = &mut prep.authorization_scan {
                        scan.resume_in_new_transaction(work)?;
                    }
                }
                prep.protection = Some(protection);
                prep.registry_current = true;
            }
            prepare_from(&mut prep, stage, &ns, element.effects(), storage, work)
        })();
        match preparation {
            Ok(()) => {}
            Err(StoreError::WorkRefused(_)) => {
                element.keep_prepared(prep);
                return Ok(EffectProgress::Deferred(SettlementStop::Budget));
            }
            Err(error) => return Err(error),
        }

        // All effects prepared. Compute the application bound.
        let mut total = *element.finalization();
        let mut staged = 0u64;
        for write in &prep.prepared.writes {
            let cost = stage.write_cost(
                &write.key,
                write.member.as_deref(),
                write.version.as_version_ref(),
            )?;
            total.checked_add_assign(&cost.work).map_err(|dimension| {
                StoreError::Internal(format!("one element's application overflows {dimension:?}"))
            })?;
            staged = staged
                .checked_add(cost.staged)
                .ok_or_else(|| StoreError::Internal("one element's staging exceeds u64".into()))?;
        }
        // An element whose staging exceeds the whole capacity can never be
        // applied, whatever compaction frees: a terminal capacity error,
        // never a deferral that waits forever.
        if staged > capacity {
            return Err(StoreError::CapacityExceeded(format!(
                "ledger element requires {staged} staging bytes, exceeding total staging capacity {capacity}"
            )));
        }
        if staged > stage.headroom()? {
            element.keep_prepared(prep);
            return Ok(EffectProgress::Deferred(SettlementStop::StagingCapacity));
        }
        let mut unit = match work.admit(&total.as_bound()) {
            Ok(unit) => unit,
            Err(_) => {
                element.keep_prepared(prep);
                return Ok(EffectProgress::Deferred(SettlementStop::Budget));
            }
        };
        // Written inside the unit admitted at exactly their cost: the
        // writer accounts, it admits nothing again.
        for write in &prep.prepared.writes {
            stage.write_admitted(
                write.family,
                &write.key,
                write.member.as_deref(),
                write.version.as_version_ref(),
                &mut unit,
            )?;
        }
        element.finish(&mut unit)?;
        Ok(EffectProgress::Applied)
    }
}

/// Whether an effect's preparation depends on registry observations.
fn is_registry_dependent(effect: &Staged) -> bool {
    matches!(
        effect,
        Staged::Retired(_)
            | Staged::Identity(IdentityEffect::Handle { .. })
            | Staged::Identity(IdentityEffect::Authorization { .. })
            | Staged::Identity(IdentityEffect::Succession { .. })
    )
}

impl ElementPreparation {
    /// The preparation is retained past its transaction: the
    /// registry-dependent writes it holds were observed in that
    /// transaction, and the next delivery validates them in its own.
    pub(super) const fn retained_between_transactions(&mut self) {
        self.registry_current = false;
    }

    /// Discard writes that depend on registry observations (retirement's
    /// allocation lookup, handle's previous anchor, authorization holders,
    /// succession plan observations) because the transaction changed. Keep
    /// immutable writes, using the counts recorded during preparation, and
    /// the effect index they complete through.
    fn rebuild_dependent(&mut self, effects: &[Staged]) {
        let first_dependent = effects
            .iter()
            .take(self.next_effect)
            .position(is_registry_dependent)
            .unwrap_or(self.next_effect);
        if self.next_effect > first_dependent {
            let immutable_writes: usize = self.writes_per_effect[..first_dependent].iter().sum();
            self.prepared.writes.truncate(immutable_writes);
            self.writes_per_effect[first_dependent..].fill(0);
            self.next_effect = first_dependent;
        }
    }
}

/// Prepare effects incrementally starting from `prep.next_effect`. Each
/// completed effect advances `next_effect`; a refusal while an effect is
/// prepared removes that effect's partial writes, so its next preparation
/// starts clean, and keeps every completed effect.
fn prepare_from(
    prep: &mut ElementPreparation,
    stage: &ProjectionStage<'_>,
    ns: &[u8; 16],
    effects: &[Staged],
    storage: &Arc<CapacityPool>,
    work: &mut dyn Meter,
) -> Result<(), StoreError> {
    while prep.next_effect < effects.len() {
        let before = prep.prepared.writes.len();
        let effect = &effects[prep.next_effect];
        let result = prepare_effect(
            stage,
            ns,
            effect,
            storage,
            &mut prep.prepared,
            &mut prep.authorization_scan,
            work,
        );
        match result {
            Ok(()) => {
                let produced = prep.prepared.writes.len() - before;
                prep.writes_per_effect[prep.next_effect] = produced;
                prep.next_effect += 1;
                prep.authorization_scan = None;
            }
            Err(error) => {
                prep.prepared.writes.truncate(before);
                return Err(error);
            }
        }
    }
    Ok(())
}

/// Prepare one effect's writes into `prepared`.
fn prepare_effect(
    stage: &ProjectionStage<'_>,
    ns: &[u8; 16],
    effect: &Staged,
    storage: &Arc<CapacityPool>,
    prepared: &mut Prepared,
    authorization_scan: &mut Option<HolderScan>,
    work: &mut dyn Meter,
) -> Result<(), StoreError> {
    match effect {
        Staged::Admitted {
            identity,
            allocation,
            ..
        } => {
            let key = key_of(identity, work)?;
            prepared.push(
                Write {
                    family: Family::Catalog,
                    key: copy(&key, work)?,
                    member: None,
                    version: Payload::Put(Vec::new()),
                },
                work,
            )?;
            if let Some(allocation) = allocation {
                prepared.push(
                    Write {
                        family: Family::AllocationOwner,
                        key: copy(allocation, work)?,
                        member: Some(copy(&key, work)?),
                        version: Payload::Put(Vec::new()),
                    },
                    work,
                )?;
                prepared.push(
                    Write {
                        family: Family::AllocationByRow,
                        key,
                        member: None,
                        version: Payload::Put(copy(allocation, work)?),
                    },
                    work,
                )?;
            }
        }
        Staged::Retired(identity) => {
            let key = key_of(identity, work)?;
            prepared.push(
                Write {
                    family: Family::Catalog,
                    key: copy(&key, work)?,
                    member: None,
                    version: Payload::Tombstone,
                },
                work,
            )?;
            if let Some(Version::Put(allocation)) =
                stage.latest(Family::AllocationByRow, &key, None, work)?
            {
                prepared.push(
                    Write {
                        family: Family::AllocationOwner,
                        key: allocation,
                        member: Some(copy(&key, work)?),
                        version: Payload::Tombstone,
                    },
                    work,
                )?;
                prepared.push(
                    Write {
                        family: Family::AllocationByRow,
                        key,
                        member: None,
                        version: Payload::Tombstone,
                    },
                    work,
                )?;
            }
        }
        Staged::Assignment(assignment) => {
            let encoded = encode_assignment(assignment.plane_id()?, assignment.generation);
            work.charge(Dimension::BytesAllocated, encoded.len() as u64)?;
            prepared.push(
                Write {
                    family: Family::Assignment,
                    key: copy(ns, work)?,
                    member: None,
                    version: Payload::Put(encoded),
                },
                work,
            )?;
        }
        Staged::Directory(record) => prepared.push(
            Write {
                family: Family::NamespaceRecord,
                key: copy(ns, work)?,
                member: None,
                version: Payload::Put(copy(record, work)?),
            },
            work,
        )?,
        Staged::Identity(effect) => identity(
            stage,
            ns,
            effect,
            storage,
            prepared,
            authorization_scan,
            work,
        )?,
    }
    Ok(())
}

/// A signed record under its identity, indexed by its asserter.
fn asserted(
    prepared: &mut Prepared,
    records: Family,
    by_asserter: Family,
    kappa: &Kappa,
    bytes: &[u8],
    asserter: &Kappa,
    work: &mut dyn Meter,
) -> Result<(), StoreError> {
    let key = key_of(kappa, work)?;
    prepared.push(
        Write {
            family: records,
            key: copy(&key, work)?,
            member: None,
            version: Payload::Put(copy(bytes, work)?),
        },
        work,
    )?;
    prepared.push(
        Write {
            family: by_asserter,
            key: key_of(asserter, work)?,
            member: Some(key),
            version: Payload::Put(Vec::new()),
        },
        work,
    )
}

/// `bytes` decoded as `T`, the decoding charged first.
fn decoded<T>(bytes: &[u8], work: &mut dyn Meter) -> Result<T, StoreError>
where
    T: TryFrom<dcbor::prelude::CBOR, Error = dcbor::Error>,
{
    work.charge(Dimension::BytesDecoded, bytes.len() as u64)?;
    Ok(from_canonical(bytes)?)
}

fn identity(
    stage: &ProjectionStage<'_>,
    ns: &[u8; 16],
    effect: &IdentityEffect,
    storage: &Arc<CapacityPool>,
    prepared: &mut Prepared,
    authorization_scan: &mut Option<HolderScan>,
    work: &mut dyn Meter,
) -> Result<(), StoreError> {
    match effect {
        IdentityEffect::Assertion { kappa, bytes } => {
            let assertion: IdentityAssertion = decoded(bytes, work)?;
            work.charge(
                Dimension::BytesAllocated,
                (assertion.subject.len() + 1 + assertion.facet.len()) as u64,
            )?;
            let subject = format!("{}\x00{}", assertion.subject, assertion.facet);
            // Both keys, the asserter's then the assertion's.
            work.charge(
                Dimension::BytesAllocated,
                2 + (assertion.asserter.digest_bytes().len() + kappa.digest_bytes().len()) as u64,
            )?;
            prepared.push(
                Write {
                    family: Family::AssertionBySubject,
                    key: subject.into_bytes(),
                    member: Some(encode_subject_idx_value(&assertion.asserter, kappa)?),
                    version: Payload::Put(Vec::new()),
                },
                work,
            )?;
            asserted(
                prepared,
                Family::Assertion,
                Family::AssertionByAsserter,
                kappa,
                bytes,
                &assertion.asserter,
                work,
            )
        }
        IdentityEffect::Revocation { kappa, bytes } => {
            let revocation: Revocation = decoded(bytes, work)?;
            asserted(
                prepared,
                Family::Revocation,
                Family::RevocationByAsserter,
                kappa,
                bytes,
                &revocation.asserter,
                work,
            )
        }
        IdentityEffect::Watermark { kappa, bytes } => {
            let watermark: Watermark = decoded(bytes, work)?;
            asserted(
                prepared,
                Family::Watermark,
                Family::WatermarkByAsserter,
                kappa,
                bytes,
                &watermark.asserter,
                work,
            )
        }
        IdentityEffect::Succession { record } => succession(stage, record, storage, prepared, work),
        IdentityEffect::Binding { key, source, bytes } => {
            prepared.push(
                Write {
                    family: Family::Binding,
                    key: copy(key, work)?,
                    member: None,
                    version: put_or_tombstone(bytes.as_deref(), work)?,
                },
                work,
            )?;
            prepared.push(
                Write {
                    family: Family::BindingBySource,
                    key: copy(source.as_bytes(), work)?,
                    member: Some(copy(ns, work)?),
                    version: if bytes.is_some() {
                        Payload::Put(Vec::new())
                    } else {
                        Payload::Tombstone
                    },
                },
                work,
            )
        }
        IdentityEffect::Handle { key, bytes } => {
            handle(stage, key, bytes.as_deref(), prepared, work)
        }
        IdentityEffect::Authorization { table, key, bytes } => authorization(
            stage,
            *table,
            key,
            bytes.as_deref(),
            prepared,
            authorization_scan,
            work,
        ),
        IdentityEffect::AnchorRow {
            table,
            anchor_key,
            bytes,
        } => {
            let family = match table {
                AnchorTable::Device => Family::DeviceBinding,
                AnchorTable::Prekey => Family::PrekeyBinding,
                AnchorTable::Locator => Family::LocatorRecord,
                AnchorTable::Commitment => Family::RevocationCommitment,
            };
            prepared.push(
                Write {
                    family,
                    key: copy(anchor_key, work)?,
                    member: None,
                    version: put_or_tombstone(bytes.as_deref(), work)?,
                },
                work,
            )
        }
    }
}

/// A handle's anchor index follows its record: the instance's previous
/// version names the anchor whose member is removed first.
fn handle(
    stage: &ProjectionStage<'_>,
    key: &str,
    bytes: Option<&[u8]>,
    prepared: &mut Prepared,
    work: &mut dyn Meter,
) -> Result<(), StoreError> {
    if let Some(Version::Put(previous)) =
        stage.latest(Family::Handle, key.as_bytes(), None, work)?
    {
        let previous: HandleRecord = decoded(&previous, work)?;
        prepared.push(
            Write {
                family: Family::HandleByAnchor,
                key: key_of(&previous.anchor, work)?,
                member: Some(copy(key.as_bytes(), work)?),
                version: Payload::Tombstone,
            },
            work,
        )?;
    }
    if let Some(bytes) = bytes {
        let record: HandleRecord = decoded(bytes, work)?;
        prepared.push(
            Write {
                family: Family::HandleByAnchor,
                key: key_of(&record.anchor, work)?,
                member: Some(copy(key.as_bytes(), work)?),
                version: Payload::Put(Vec::new()),
            },
            work,
        )?;
    }
    prepared.push(
        Write {
            family: Family::Handle,
            key: copy(key.as_bytes(), work)?,
            member: None,
            version: put_or_tombstone(bytes, work)?,
        },
        work,
    )
}

/// The admitted ciphertext of an authorization row, cached for the key's
/// owner. The key's ownership is its claim (`identity_local::claim_locator`),
/// decided before publication; a completed copy from another instance means
/// the claim protocol was bypassed, and is refused rather than projected.
fn authorization(
    stage: &ProjectionStage<'_>,
    table: AuthorizationTable,
    key: &str,
    bytes: Option<&[u8]>,
    prepared: &mut Prepared,
    scan: &mut Option<HolderScan>,
    work: &mut dyn Meter,
) -> Result<(), StoreError> {
    let family = authorization_family(table)?;
    let own = *stage.instance();
    if scan.is_none() {
        *scan = Some(HolderScan::new(family, key.as_bytes(), None, work)?);
    }
    let scan = scan
        .as_mut()
        .ok_or_else(|| StoreError::Internal("authorization scan missing".into()))?;
    stage.scan_holders(scan, work)?.complete()?;
    let foreign = scan.found().iter().any(|(instance, version)| {
        instance.namespace() != own.namespace() && matches!(version, Version::Put(_))
    });
    if foreign {
        return Err(StoreError::Conflict(format!(
            "authorization key {key} is projected for another namespace"
        )));
    }
    prepared.push(
        Write {
            family,
            key: copy(key.as_bytes(), work)?,
            member: None,
            version: put_or_tombstone(bytes, work)?,
        },
        work,
    )
}

/// The family caching rows of an authorization table.
fn authorization_family(table: AuthorizationTable) -> Result<Family, StoreError> {
    let name = table.name();
    [
        (tables::ID_SESSIONS, Family::Session),
        (tables::ID_CREDENTIALS, Family::Credential),
        (tables::ID_CREDENTIAL_GRACE, Family::CredentialGrace),
        (tables::ID_TRUST, Family::Trust),
    ]
    .into_iter()
    .find(|(candidate, _)| candidate.name() == name)
    .map(|(_, family)| family)
    .ok_or_else(|| StoreError::Internal(format!("{name} is not an authorization table")))
}

/// Index a successor for its old anchor across every instance's settled
/// successions (`identity_records::succession_index_in_txn` holds the same
/// rules within one database): the identical record is idempotent, another
/// record for the anchor conflicts, and a cycle or a chain past the bound
/// is refused. Every holder lookup, decode and the record's encoding are
/// charged to `work`, the encoding held live in `storage`; the record's
/// version is a copy of the planner's own encoding, charged and held under
/// a live reservation of its own until it is written.
fn succession(
    stage: &ProjectionStage<'_>,
    record: &Succession,
    storage: &Arc<CapacityPool>,
    prepared: &mut Prepared,
    work: &mut dyn Meter,
) -> Result<(), StoreError> {
    let old_key = key_of(&record.old_anchor, work)?;
    let existing = stage.holders(Family::Succession, &old_key, None, work)?;
    let admitted = plan_succession_link(
        record,
        work,
        storage,
        existing
            .iter()
            .filter_map(|(_, version)| match version.as_ref() {
                VersionRef::Put(bytes) => Some(bytes),
                VersionRef::Tombstone => None,
            }),
        |anchor, work| {
            let mut depth = 0u64;
            for (_, version) in stage.holders(Family::SuccessionDepth, anchor, None, work)? {
                if let Version::Put(value) = version {
                    let value: [u8; 8] = value
                        .as_slice()
                        .try_into()
                        .map_err(|_| StoreError::Internal("malformed succession depth".into()))?;
                    depth = depth.max(u64::from_be_bytes(value));
                }
            }
            Ok(depth)
        },
        |anchor, work| {
            for (_, version) in stage.holders(Family::Succession, anchor, None, work)? {
                if let Version::Put(value) = version {
                    let next: Succession = decoded(&value, work)?;
                    return Ok(Some(next.new_anchor));
                }
            }
            Ok(None)
        },
    )?;
    let SuccessionOutcome::New(updates) = admitted.outcome else {
        return Ok(());
    };
    // The canonical encoding is framed directly from its reservation;
    // no copy, no separate held vector.
    prepared.push(
        Write {
            family: Family::Succession,
            key: old_key,
            member: None,
            version: Payload::Encoded(admitted.canonical),
        },
        work,
    )?;
    for (anchor, links) in updates {
        work.charge(Dimension::BytesAllocated, 8)?;
        prepared.push(
            Write {
                family: Family::SuccessionDepth,
                key: anchor,
                member: None,
                version: Payload::Put(links.to_be_bytes().to_vec()),
            },
            work,
        )?;
    }
    Ok(())
}
