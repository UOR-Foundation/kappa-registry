//! Bounded reading of one committed epoch for settlement and recovery.
//!
//! An [`EpochCursor`] reads one epoch of one storage instance across as
//! many steps as its budget requires, each unit admitted on the step's
//! meter at its bound before it starts (`Meter::admit`) and accounted as
//! measured inside it (`Meter::account`; bounds in `settlement_work`):
//!
//! 1. the read is opened in stages (`settlement_ledger_open`): the epoch
//!    index, the root record, the state record and the ledger row, each
//!    stage its own unit, each completed stage kept across steps;
//! 2. the consumer is restarted once, inside its own admitted unit, before
//!    any element is delivered ([`ConsumerState`]);
//! 3. the seal's own records (root, ledger, rotation evidence, predecessor)
//!    are resolved against the instance's rows;
//! 4. the ledger is read in bounded units from its retained source, split
//!    into its canonical elements, and each element decoded, hashed and
//!    folded into the mutation tree, and staged (`settlement_stage`) as it
//!    is decoded;
//! 5. the `EDGE_FWD` targets sourced at the root are resolved through one
//!    retained value iterator, advanced across steps;
//! 6. the epoch is verified: the root's authority was admitted when the
//!    root was completed, and when the last element is decoded the ledger
//!    identity and mutation root computed over every persisted byte must
//!    equal the root's (`check_ledger_digests`) and the authority is admitted
//!    again, charged there.
//!
//! Everything the cursor delivers before [`Advance::Verified`] is
//! unadmitted: its consumer stages it as disposable work and admits it only
//! on verification. The cursor holds no population of the epoch: its
//! decode state is one element (at most `record_bytes`) plus one read unit,
//! the hash state and the tree's peaks, and the one element read but not
//! yet applied ([`Pending`]).
//!
//! An element is read (decoded, its leaf built, its bounded effects derived
//! from the snapshot) and held pending; it is delivered to the consumer,
//! which applies all of its effects or none (`EffectProgress`). Only once
//! they are applied does the cursor move past it: the seal position
//! advances, or the mutation's leaf is pushed into the tree and its bytes
//! and count consumed. A consumer that defers leaves the element pending,
//! read exactly once and applied exactly once whatever the steps between.
//!
//! The cursor owns, until it is verified or discarded, one snapshot of the
//! instance's namespace (`namespace_snapshot`: its activity grant, taken
//! once when it opens, and one read transaction of its database), the
//! table and edge iterator opened in it, and the ledger's allocation when
//! it is external, pinned once for the read, so every read of the epoch
//! comes from one snapshot and the database can be neither evicted nor
//! retired under it. The storage must be storage the instance's records may
//! have been written for (`Identification::permits_settlement`). Fields
//! drop in declaration order: iterator, table, then the snapshot (its
//! transaction, then its grant). Cursors live inside the store
//! (`PersistentStore::epoch_cursors`), whose filesystem owner is released
//! after every cursor. A cursor is process state: after a restart its
//! position is gone and the epoch is read again from the authenticated
//! evidence.

use redb::{MultimapValue, ReadOnlyTable};

use kappa_store::canonical::from_canonical;
use kappa_store::epoch::EpochMutation;
use kappa_store::epoch_authority::EpochAuthority;
use kappa_store::epoch_publication::{check_ledger_digests, verify_epoch_authority};
use kappa_store::work::{Dimension, Meter, Work};
use kappa_store::{EpochRoot, Kappa, LogicalIncarnation, NamespaceRef, StoreError};
use kappa_types::canonical::canonical_bytes;
use kappa_types::kappa_streaming::IncrementalHasher;
use kappa_types::merkle::{push_hash_bound, push_hash_input, StreamingTree};

use super::apply::ElementPreparation;
use super::cursors::{EffectProgress, Element, EpochConsumer};
use super::stage::{admit, collect_effects, stage_mutation, Reads, Staged, EFFECTS_BUFFER_BYTES};
use super::work::{SettlementLimits, VERIFICATION_SIGNATURES};
use super::SettlementStop;
use crate::namespace_snapshot::{InstanceAdmission, NamespaceSnapshot};
use crate::storage::NamespaceStorage;
use crate::storage_instance::StorageInstance;
use crate::tables::{BLOB_INDEX, EDGE_FWD};
use kappa_types::canonical::framing::{head, item_len};

#[path = "settlement_ledger_open.rs"]
mod open;
#[path = "settlement_ledger_read.rs"]
mod read;
use crate::PersistentStore;
use open::{LedgerSource, OpenStep, Opened, Opener};

/// Bytes of ledger one read takes at most.
const READ_UNIT: u64 = crate::BLOB_CHUNK_SIZE as u64;

/// What opening a cursor reached.
pub enum CursorOpen {
    Opened(EpochCursor),
    /// No cursor was opened: the meter does not admit taking the namespace
    /// snapshot (`Budget`), or every namespace activity of the store is held
    /// (`ActivityCapacity`).
    Deferred(SettlementStop),
}

/// What one advance of a cursor reached.
pub enum Advance {
    /// The resource named stopped it first (the budget, or the consumer's
    /// deferral of the pending element); the cursor keeps its position and
    /// any element read but not applied.
    Pending(SettlementStop),
    /// The epoch is read and verified: everything delivered is admitted.
    Verified,
}

/// Whether the consumer has been told the epoch is read from its start.
/// No element is delivered while `RestartRequired`; the transition to
/// `Active` happens only once the consumer's complete restart unit
/// succeeded (`EpochConsumer::restart`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConsumerState {
    RestartRequired,
    Active,
}

#[derive(Debug)]
enum Phase {
    Seal(usize),
    Ledger,
    Edges,
    Verified,
}

/// Where an element read but not yet applied came from, and what applying
/// it moves the cursor past.
enum Origin {
    /// The seal record at this position.
    Seal(usize),
    /// The ledger element of `length` encoded bytes whose leaf is `leaf`.
    Mutation { length: usize, leaf: Vec<u8> },
    /// An edge target; the edge iterator is already past it.
    Edge,
}

/// The element read but not yet applied: owned data only, held across
/// steps with the cursor, and what its consumer prepared of its effects
/// that no later transaction can change (`settlement_apply`), kept while
/// the element stays pending and dropped with it.
struct Pending {
    origin: Origin,
    effects: Vec<Staged>,
    prepared: Option<ElementPreparation>,
}

/// The open read of an epoch: what opening established and the read's
/// position through it.
struct Reading {
    root_identity: Kappa,
    root: EpochRoot,
    /// The instance the epoch's authenticated state names, checked at open.
    incarnation: LogicalIncarnation,
    seal: Vec<Kappa>,
    ledger: LedgerSource,
    ledger_size: u64,
    consumer: ConsumerState,
    phase: Phase,
    position: u64,
    buffer: Vec<u8>,
    /// A completed composite read awaiting append admission. Retaining it
    /// prevents a refusal after I/O from rereading the same components.
    pending_read: Option<Vec<u8>>,
    consumed: usize,
    remaining: Option<u64>,
    hasher: Option<IncrementalHasher>,
    tree: Option<StreamingTree>,
    pending: Option<Pending>,
}

impl Reading {
    fn new(opened: Opened) -> Self {
        let Opened {
            root_identity,
            root,
            incarnation,
            ledger,
            ledger_size,
        } = opened;
        let seal = [
            Some(root_identity.clone()),
            Some(root.ledger_root().clone()),
            Some(root.state().clone()),
            root.rotation_kappa().cloned(),
            root.prev_identifier().cloned(),
        ]
        .into_iter()
        .flatten()
        .collect();
        let hasher = IncrementalHasher::new(root.ledger_root().axis());
        Self {
            root_identity,
            root,
            incarnation,
            seal,
            ledger,
            ledger_size,
            consumer: ConsumerState::RestartRequired,
            phase: Phase::Seal(0),
            position: 0,
            buffer: Vec::new(),
            pending_read: None,
            consumed: 0,
            remaining: None,
            hasher: Some(hasher),
            tree: Some(StreamingTree::new()),
            pending: None,
        }
    }
}

/// Where the cursor stands: opening in stages, or reading what opening
/// established.
enum State {
    Opening(Opener),
    Reading(Reading),
}

/// One epoch of one storage instance being read; see the module docs.
pub struct EpochCursor {
    /// Owns its transaction guard and pages: redb's value iterator needs
    /// no table retained beside it.
    edges: Option<MultimapValue<'static, &'static [u8]>>,
    index: ReadOnlyTable<&'static [u8], &'static [u8]>,
    snapshot: NamespaceSnapshot,
    epoch: u64,
    state: State,
}

impl std::fmt::Debug for EpochCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.state {
            State::Opening(opener) => opener.fmt(formatter),
            State::Reading(reading) => formatter
                .debug_struct("EpochCursor")
                .field("epoch", &self.epoch)
                .field("phase", &reading.phase)
                .field("consumer", &reading.consumer)
                .field("position", &reading.position)
                .field("ledger_size", &reading.ledger_size)
                .field("buffered", &reading.buffer.len())
                .field("consumed", &reading.consumed)
                .field("remaining", &reading.remaining)
                .field(
                    "pending_effects",
                    &reading
                        .pending
                        .as_ref()
                        .map(|pending| pending.effects.len()),
                )
                .field("pending_read", &reading.pending_read.as_ref().map(Vec::len))
                .finish(),
        }
    }
}

/// Retained across steps under the recovery lock: it must move between the
/// threads that run steps.
const _: fn() = || {
    const fn send<T: Send>() {}
    send::<EpochCursor>();
};

impl EpochCursor {
    /// Open a cursor over epoch `epoch` of `instance`: take the namespace's
    /// activity grant and one read transaction, refuse storage of another
    /// instance, and open the blob index. Admitted on `work` at
    /// `limits.opening_snapshot()` (the one handle); deferred (`Budget`) when
    /// the meter does not admit it, and (`ActivityCapacity`) when every
    /// namespace activity is held. Nothing of the epoch is read here: the
    /// staged opening runs inside [`Self::advance`], so a refusal there
    /// keeps the cursor and its snapshot.
    pub(super) fn open(
        store: &PersistentStore,
        instance: &StorageInstance,
        epoch: u64,
        limits: SettlementLimits,
        work: &mut dyn Meter,
    ) -> Result<CursorOpen, StoreError> {
        let Ok(mut unit) = work.admit(&limits.opening_snapshot().as_bound()) else {
            return Ok(CursorOpen::Deferred(SettlementStop::Budget));
        };
        unit.account(Dimension::Handles, 1)?;
        let snapshot = match store.admit_instance(instance) {
            InstanceAdmission::Held {
                snapshot,
                identification,
            } if identification.permits_settlement() => snapshot,
            InstanceAdmission::CapacityDeferred { .. } => {
                return Ok(CursorOpen::Deferred(SettlementStop::ActivityCapacity));
            }
            InstanceAdmission::Held { snapshot, .. } => {
                return Err(StoreError::Conflict(format!(
                    "storage of {} is instance {}, not {instance}",
                    hex::encode(instance.namespace()),
                    snapshot.controller().instance
                )));
            }
            InstanceAdmission::Released(_) => {
                return Err(StoreError::NotFound(format!(
                    "storage of {instance} is retired"
                )));
            }
            InstanceAdmission::Unexplained(error) | InstanceAdmission::Unreadable(error) => {
                return Err(error);
            }
        };
        let index = snapshot.table(BLOB_INDEX)?;
        Ok(CursorOpen::Opened(Self {
            edges: None,
            index,
            snapshot,
            epoch,
            state: State::Opening(Opener::new(epoch)),
        }))
    }

    pub(super) const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The root read and admitted by the opening; verified once
    /// [`Advance::Verified`] is reached. A cursor still opening has none.
    pub(super) fn epoch_root(&self) -> Result<&EpochRoot, StoreError> {
        match &self.state {
            State::Reading(reading) => Ok(&reading.root),
            State::Opening(_) => Err(StoreError::Internal(
                "the epoch root of a cursor still opening was requested".into(),
            )),
        }
    }

    /// Advance within `work`, delivering each element the epoch admits to
    /// `consumer` (see the module documentation). An error leaves the
    /// cursor unusable: its owner discards it, and the epoch is read again
    /// from the start.
    pub(super) fn advance(
        &mut self,
        limits: SettlementLimits,
        authority: &EpochAuthority,
        work: &mut dyn Meter,
        consumer: &mut dyn EpochConsumer,
    ) -> Result<Advance, StoreError> {
        let budget = Advance::Pending(SettlementStop::Budget);
        loop {
            let reading = match &mut self.state {
                State::Opening(opener) => {
                    match opener.advance(&self.snapshot, &self.index, limits, authority, work)? {
                        OpenStep::Budget => return Ok(budget),
                        OpenStep::Opened(opened) => {
                            self.state = State::Reading(Reading::new(opened));
                            continue;
                        }
                    }
                }
                State::Reading(reading) => reading,
            };
            if reading.consumer == ConsumerState::RestartRequired {
                // The consumer's restart is one unit it admits itself; a
                // refusal before that admission changes nothing and the
                // restart stays owed. Anything else propagates and the
                // enclosing transaction is abandoned.
                match consumer.restart(work) {
                    Ok(()) => reading.consumer = ConsumerState::Active,
                    Err(StoreError::WorkRefused(_)) => return Ok(budget),
                    Err(error) => return Err(error),
                }
            }
            if reading.pending.is_some() {
                if let Some(stop) = Self::deliver(reading, work, consumer)? {
                    return Ok(Advance::Pending(stop));
                }
                continue;
            }
            match reading.phase {
                Phase::Seal(next) => {
                    let Some(identity) = reading.seal.get(next).cloned() else {
                        reading.phase = Phase::Ledger;
                        continue;
                    };
                    let Ok(mut unit) = work.admit(&limits.record().as_bound()) else {
                        return Ok(budget);
                    };
                    unit.account(Dimension::Entries, 1)?;
                    unit.account(Dimension::BytesAllocated, EFFECTS_BUFFER_BYTES)?;
                    let reads =
                        Self::reads(&self.snapshot, &self.index, reading.incarnation, limits);
                    let effects =
                        collect_effects(|sink| admit(&reads, &identity, &mut unit, sink))?;
                    reading.pending = Some(Pending {
                        origin: Origin::Seal(next),
                        effects,
                        prepared: None,
                    });
                }
                Phase::Ledger => {
                    if !Self::advance_ledger(
                        reading,
                        &self.snapshot,
                        &self.index,
                        self.epoch,
                        limits,
                        authority,
                        work,
                    )? {
                        return Ok(budget);
                    }
                }
                Phase::Edges => {
                    if self.edges.is_none() {
                        let table = self.snapshot.multimap(EDGE_FWD)?;
                        let mut source = Self::namespace(&self.snapshot).id().to_vec();
                        source.extend_from_slice(&reading.root_identity.key_bytes());
                        self.edges =
                            Some(table.get(source.as_slice()).map_err(crate::error::redb)?);
                    }
                    // The edge examined, and its target admitted, as one
                    // unit admitted before the iterator advances; the end
                    // of the edges is the same examination. The target is
                    // held pending, so the iterator never passes an edge
                    // whose target is not yet applied.
                    let Ok(mut unit) = work.admit(&limits.record().as_bound()) else {
                        return Ok(budget);
                    };
                    unit.account(Dimension::Entries, 1)?;
                    let next = self.edges.as_mut().and_then(Iterator::next);
                    let Some(entry) = next else {
                        reading.phase = Phase::Verified;
                        continue;
                    };
                    let target = Kappa::from_key_bytes(entry.map_err(crate::error::redb)?.value())?;
                    unit.account(Dimension::BytesAllocated, EFFECTS_BUFFER_BYTES)?;
                    let reads =
                        Self::reads(&self.snapshot, &self.index, reading.incarnation, limits);
                    let effects = collect_effects(|sink| admit(&reads, &target, &mut unit, sink))?;
                    reading.pending = Some(Pending {
                        origin: Origin::Edge,
                        effects,
                        prepared: None,
                    });
                }
                Phase::Verified => return Ok(Advance::Verified),
            }
        }
    }

    /// Deliver the pending element to `consumer` within `work`. The
    /// coordinates applying it moves the cursor to are decided first; the
    /// consumer applies its effects and then finishes it inside the one unit
    /// it admitted for both: a mutation's leaf is pushed into the tree and
    /// the hashing accounted on that unit, whose bound included it
    /// (`finalization`). Once applied the cursor moves past it and `None` is
    /// returned; a deferral leaves it pending, unfinished, and is returned.
    /// An error leaves the cursor unusable, as every read error does.
    fn deliver(
        reading: &mut Reading,
        work: &mut dyn Meter,
        consumer: &mut dyn EpochConsumer,
    ) -> Result<Option<SettlementStop>, StoreError> {
        let mut pending = reading
            .pending
            .take()
            .ok_or_else(|| StoreError::Internal("no ledger element is pending".into()))?;
        let (finalization, next_remaining) = match &pending.origin {
            Origin::Mutation { leaf, .. } => {
                let hashing = push_hash_bound(leaf.len() as u64)
                    .ok_or_else(|| StoreError::Internal("leaf hashing bound exceeds u64".into()))?;
                let remaining = reading
                    .remaining
                    .and_then(|remaining| remaining.checked_sub(1))
                    .ok_or_else(|| {
                        StoreError::Internal("a ledger element past the array's end".into())
                    })?;
                (
                    Work::default().with(Dimension::BytesHashed, hashing),
                    Some(remaining),
                )
            }
            Origin::Seal(_) | Origin::Edge => (Work::default(), None),
        };
        let mut finished = false;
        let progress = {
            let tree = &mut reading.tree;
            let Pending {
                origin,
                effects,
                prepared,
            } = &mut pending;
            let origin = &*origin;
            let finished = &mut finished;
            let mut finish = |unit: &mut dyn Meter| -> Result<(), StoreError> {
                if *finished {
                    return Err(StoreError::Internal(
                        "a ledger element was finished twice".into(),
                    ));
                }
                if let Origin::Mutation { leaf, .. } = origin {
                    let current = tree
                        .take()
                        .ok_or_else(|| StoreError::Internal("mutation tree consumed".into()))?;
                    let mut nodes = 0u64;
                    let pushed = current.push(leaf, |_, _| {
                        nodes += 1;
                        Ok::<(), std::convert::Infallible>(())
                    });
                    *tree = Some(match pushed {
                        Ok(tree) => tree,
                        Err(never) => match never {},
                    });
                    let hashed = push_hash_input(leaf.len() as u64, nodes).ok_or_else(|| {
                        StoreError::Internal(format!(
                            "a mutation tree push emitted {nodes} nodes for one leaf"
                        ))
                    })?;
                    unit.account(Dimension::BytesHashed, hashed)?;
                }
                *finished = true;
                Ok(())
            };
            consumer.apply(
                Element::new(effects, prepared, finalization, &mut finish),
                work,
            )?
        };
        match progress {
            EffectProgress::Deferred(stop) => {
                if finished {
                    return Err(StoreError::Internal(
                        "a deferred ledger element was finished".into(),
                    ));
                }
                reading.pending = Some(pending);
                return Ok(Some(stop));
            }
            EffectProgress::Applied if !finished => {
                return Err(StoreError::Internal(
                    "an applied ledger element was not finished".into(),
                ));
            }
            EffectProgress::Applied => {}
        }
        match pending.origin {
            Origin::Seal(next) => reading.phase = Phase::Seal(next + 1),
            Origin::Edge => {}
            Origin::Mutation { length, .. } => {
                reading.consumed += length;
                reading.remaining = next_remaining;
            }
        }
        Ok(None)
    }

    /// The namespace whose activity this cursor holds.
    fn namespace(snapshot: &NamespaceSnapshot) -> NamespaceRef {
        NamespaceStorage::namespace_ref(snapshot.controller().id)
    }

    fn reads<'c>(
        snapshot: &'c NamespaceSnapshot,
        index: &'c ReadOnlyTable<&'static [u8], &'static [u8]>,
        incarnation: LogicalIncarnation,
        limits: SettlementLimits,
    ) -> Reads<'c> {
        Reads {
            view: snapshot.view(),
            txn: snapshot.transaction(),
            index,
            ns: Self::namespace(snapshot),
            incarnation,
            limit: limits.record_bytes(),
        }
    }

    /// One unit of ledger progress: the array head, one element read and
    /// held pending, or one read. Returns false when the budget stops it;
    /// moves to the edges once the last element is applied and the digests
    /// correspond.
    #[allow(
        clippy::too_many_arguments,
        reason = "the reading, the snapshot it reads from and the step's bounds, named"
    )]
    fn advance_ledger(
        reading: &mut Reading,
        snapshot: &NamespaceSnapshot,
        index: &ReadOnlyTable<&'static [u8], &'static [u8]>,
        epoch: u64,
        limits: SettlementLimits,
        authority: &EpochAuthority,
        work: &mut dyn Meter,
    ) -> Result<bool, StoreError> {
        let available = &reading.buffer[reading.consumed..];
        match reading.remaining {
            None => match head(available)? {
                Some((4, count, length)) => {
                    reading.consumed += length;
                    reading.remaining = Some(count);
                    Ok(true)
                }
                Some(_) => Err(StoreError::Rejected("epoch ledger is not an array".into())),
                None => Self::read_more(reading, snapshot, epoch, work),
            },
            Some(0) => Self::finish_ledger(reading, epoch, authority, work),
            Some(remaining) => match item_len(available)? {
                Some(length) if length as u64 > limits.record_bytes() => {
                    Err(StoreError::CapacityExceeded(format!(
                        "an element of the ledger of epoch {epoch} is {length} bytes, beyond the settlement record limit {}",
                        limits.record_bytes()
                    )))
                }
                Some(length) => {
                    // Admitted at its bound before anything is allocated:
                    // one record each for the decoded mutation and its
                    // re-encoded leaf (both bounded by the element, itself
                    // within the record limit and the splitter's nesting
                    // limit), the buffer of its effects, and every read
                    // deriving them. The element is read as that one unit,
                    // and its consumption is the step's on every path, a
                    // failed decoding included. Its leaf is pushed, and its
                    // bytes and count consumed, only once it is applied
                    // (`deliver`).
                    let Ok(mut unit) = work.admit(&limits.mutation().as_bound()) else {
                        return Ok(false);
                    };
                    let decoded = length as u64;
                    unit.account(Dimension::BytesDecoded, decoded)?;
                    let mutation: EpochMutation = from_canonical(&available[..length])?;
                    let leaf = canonical_bytes(&mutation);
                    unit.account(Dimension::BytesAllocated, leaf.len() as u64)?;
                    unit.account(Dimension::Entries, 1)?;
                    unit.account(Dimension::BytesAllocated, EFFECTS_BUFFER_BYTES)?;
                    let reads = Self::reads(snapshot, index, reading.incarnation, limits);
                    let effects =
                        collect_effects(|sink| stage_mutation(&reads, &mutation, &mut unit, sink))?;
                    debug_assert!(remaining > 0, "an element is read only while some remain");
                    reading.pending = Some(Pending {
                        origin: Origin::Mutation { length, leaf },
                        effects,
                        prepared: None,
                    });
                    Ok(true)
                }
                None if available.len() as u64 >= limits.record_bytes() => {
                    Err(StoreError::CapacityExceeded(format!(
                        "an element of the ledger of epoch {epoch} exceeds the settlement record limit {}",
                        limits.record_bytes()
                    )))
                }
                None => Self::read_more(reading, snapshot, epoch, work),
            },
        }
    }

    /// Read the next unit of the ledger into the decode buffer, hashing it,
    /// within what `work` has left. A source whose read cost is known from
    /// its framing (`read::ledger_read_cost`) is read as one unit admitted
    /// at that cost plus the hashing and the decode buffer's growth, so the
    /// read is whole or not begun; a composite ledger is charged as its
    /// components are resolved, and a refusal there leaves the position and
    /// buffer as they were. Returns false when nothing is left or the meter
    /// refuses.
    fn read_more(
        reading: &mut Reading,
        snapshot: &NamespaceSnapshot,
        epoch: u64,
        work: &mut dyn Meter,
    ) -> Result<bool, StoreError> {
        let left = reading.ledger_size - reading.position;
        if left == 0 {
            return Err(StoreError::Rejected(format!(
                "the ledger of epoch {epoch} ends inside its elements"
            )));
        }
        let length = READ_UNIT.min(left);
        let appended = Work::default()
            .with(Dimension::BytesHashed, length)
            .with(Dimension::BytesAllocated, length);
        let bytes = if reading.pending_read.is_some() {
            if work.charge_all(&appended.as_bound()).is_err() {
                return Ok(false);
            }
            reading
                .pending_read
                .take()
                .ok_or_else(|| StoreError::Internal("completed ledger read disappeared".into()))?
        } else {
            match read::ledger_read_cost(&reading.ledger, reading.position, length)? {
                Some(mut cost) => {
                    cost.checked_add_assign(&appended).map_err(|dimension| {
                        StoreError::Internal(format!("a ledger read overflows {dimension:?}"))
                    })?;
                    let Ok(mut unit) = work.admit(&cost.as_bound()) else {
                        return Ok(false);
                    };
                    let bytes = read::read_ledger(
                        &mut reading.ledger,
                        snapshot,
                        reading.position,
                        length,
                        &mut unit,
                    )?;
                    unit.account(Dimension::BytesHashed, length)?;
                    unit.account(Dimension::BytesAllocated, length)?;
                    bytes
                }
                None => {
                    let bytes = match read::read_ledger(
                        &mut reading.ledger,
                        snapshot,
                        reading.position,
                        length,
                        work,
                    ) {
                        Ok(bytes) => bytes,
                        Err(StoreError::WorkRefused(_)) => return Ok(false),
                        Err(error) => return Err(error),
                    };
                    if work.charge_all(&appended.as_bound()).is_err() {
                        reading.pending_read = Some(bytes);
                        return Ok(false);
                    }
                    bytes
                }
            }
        };
        if bytes.len() as u64 != length {
            return Err(StoreError::Internal(format!(
                "ledger read delivered {} of {length} bytes",
                bytes.len()
            )));
        }
        reading.buffer.drain(..reading.consumed);
        reading.consumed = 0;
        reading
            .buffer
            .try_reserve_exact(bytes.len())
            .map_err(|_| StoreError::CapacityExceeded("ledger decode buffer".into()))?;
        reading
            .hasher
            .as_mut()
            .ok_or_else(|| StoreError::Internal("ledger hasher consumed".into()))?
            .update(&bytes);
        reading.buffer.extend_from_slice(&bytes);
        reading.position += length;
        Ok(true)
    }

    /// The last element is decoded: nothing may follow it, and the identity
    /// and mutation root computed over the persisted ledger must be the
    /// root's. The root's authority, admitted when the root was completed,
    /// is admitted again against the history in force now, that signature
    /// charged here: a rotation committed meanwhile cannot leave an epoch
    /// verified against a superseded history. Returns false when the meter
    /// refuses the signature; the cursor stays at the ledger's end.
    fn finish_ledger(
        reading: &mut Reading,
        epoch: u64,
        authority: &EpochAuthority,
        work: &mut dyn Meter,
    ) -> Result<bool, StoreError> {
        if reading.consumed != reading.buffer.len() || reading.position != reading.ledger_size {
            return Err(StoreError::Rejected(format!(
                "the ledger of epoch {epoch} holds bytes after its last element"
            )));
        }
        if work
            .charge(Dimension::Signatures, VERIFICATION_SIGNATURES)
            .is_err()
        {
            return Ok(false);
        }
        let ledger = reading
            .hasher
            .take()
            .ok_or_else(|| StoreError::Internal("ledger hasher consumed".into()))?
            .finalize()?;
        let tree = reading
            .tree
            .take()
            .ok_or_else(|| StoreError::Internal("mutation tree consumed".into()))?;
        check_ledger_digests(&reading.root, &ledger, &tree.root())?;
        verify_epoch_authority(&reading.root, authority)?;
        reading.buffer = Vec::new();
        reading.phase = Phase::Edges;
        Ok(true)
    }
}
