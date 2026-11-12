//! Generations of a namespace's derived indexes (`REFERRERS`,
//! `ALLOCATIONS`) and the writes that keep them in correspondence with the
//! committed state they project.
//!
//! Each index has two physical generations in the namespace database. The
//! durable state row (`DERIVED_STATE`) names the live one and, while a
//! repair is active, the repair's phase and progress (`index_repair`):
//!
//! - `Building`: the other generation is being reconstructed from the
//!   committed source tables in bounded chunks. The live generation is
//!   known divergent and is fenced: it authorizes no destructive absence
//!   (retirement refuses, reclamation protects, referrer reads are
//!   unavailable). Every authoritative write applies its change to both
//!   generations without the existence assertions, so a change lands in the
//!   new generation whether its source row was traversed before or after
//!   it; reconstruction inserts idempotently.
//! - `Cleanup`: the reconstructed generation became live in one
//!   transaction; the old one is emptied in bounded chunks, and readers that
//!   opened it keep their snapshot. Writes touch only the live generation,
//!   with the assertions.
//!
//! Outside a repair, writes assert the state they imply (an entry to
//! establish is absent, one to release is present): a failed assertion is
//! divergence, recorded on the store for the namespace
//! (`PersistentStore::index_diverged`), and the mutation refuses to commit.
//! A namespace with a recorded divergence is fenced exactly as one whose
//! repair is building, until a repair started after the divergence was
//! recorded completes.

use redb::{
    MultimapTableDefinition, ReadableMultimapTable, ReadableTable, TableDefinition,
    WriteTransaction,
};

use kappa_store::{Kappa, NamespaceRef, StoreError};

use crate::PersistentStore;
use crate::namespace_snapshot::NamespaceSnapshot;
use crate::representation::AllocationId;
use crate::tables::{ALLOCATIONS, ALLOCATIONS_G1, DERIVED_STATE, REFERRERS, REFERRERS_G1};

const LIVE_KEY: &[u8] = b"live";
const REPAIR_KEY: &[u8] = b"repair";

/// One physical generation of the derived indexes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generation {
    Zero,
    One,
}

impl Generation {
    pub const fn other(self) -> Self {
        match self {
            Self::Zero => Self::One,
            Self::One => Self::Zero,
        }
    }

    pub const fn referrers(self) -> MultimapTableDefinition<'static, &'static [u8], &'static [u8]> {
        match self {
            Self::Zero => REFERRERS,
            Self::One => REFERRERS_G1,
        }
    }

    pub const fn allocations(self) -> TableDefinition<'static, &'static [u8], &'static [u8]> {
        match self {
            Self::Zero => ALLOCATIONS,
            Self::One => ALLOCATIONS_G1,
        }
    }

    const fn byte(self) -> u8 {
        match self {
            Self::Zero => 0,
            Self::One => 1,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, StoreError> {
        match byte {
            0 => Ok(Self::Zero),
            1 => Ok(Self::One),
            other => Err(StoreError::Internal(format!(
                "derived index generation {other} is unknown"
            ))),
        }
    }
}

/// The committed source a repair traverses, in traversal order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    Tags,
    Edges,
    Heads,
    Representations,
    Pins,
}

impl Source {
    pub const FIRST: Self = Self::Tags;

    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Tags => Some(Self::Edges),
            Self::Edges => Some(Self::Heads),
            Self::Heads => Some(Self::Representations),
            Self::Representations => Some(Self::Pins),
            Self::Pins => None,
        }
    }

    const fn byte(self) -> u8 {
        match self {
            Self::Tags => 0,
            Self::Edges => 1,
            Self::Heads => 2,
            Self::Representations => 3,
            Self::Pins => 4,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, StoreError> {
        match byte {
            0 => Ok(Self::Tags),
            1 => Ok(Self::Edges),
            2 => Ok(Self::Heads),
            3 => Ok(Self::Representations),
            4 => Ok(Self::Pins),
            other => Err(StoreError::Internal(format!(
                "derived index repair source {other} is unknown"
            ))),
        }
    }
}

/// Where an active repair stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Reconstructing `staging` from `source`, after the source key
    /// `after` (from its start when `None`).
    Building {
        staging: Generation,
        source: Source,
        after: Option<Vec<u8>>,
    },
    /// Emptying the generation `old` that the completion replaced.
    Cleanup { old: Generation },
}

/// An active repair: the divergence revision it was started for and its
/// phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repair {
    pub revision: u64,
    pub phase: Phase,
}

/// The durable state of a namespace's derived indexes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedState {
    pub live: Generation,
    pub repair: Option<Repair>,
}

impl DerivedState {
    /// The state `table` holds; a database without a state row has never
    /// been repaired and serves generation zero.
    pub fn read(
        table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    ) -> Result<Self, StoreError> {
        let live = table
            .get(LIVE_KEY)
            .map_err(crate::error::redb)?
            .map(|value| {
                let bytes = value.value();
                match bytes {
                    [byte] => Generation::from_byte(*byte),
                    _ => Err(StoreError::Internal(
                        "derived index live generation is not one byte".into(),
                    )),
                }
            })
            .transpose()?
            .unwrap_or(Generation::Zero);
        let repair = table
            .get(REPAIR_KEY)
            .map_err(crate::error::redb)?
            .map(|value| decode_repair(value.value()))
            .transpose()?;
        Ok(Self { live, repair })
    }

    /// The state of the database `txn` writes.
    pub fn in_txn(txn: &WriteTransaction) -> Result<Self, StoreError> {
        let table = txn.open_table(DERIVED_STATE).map_err(crate::error::redb)?;
        Self::read(&table)
    }

    /// Write this state in `txn`.
    pub fn write(&self, txn: &WriteTransaction) -> Result<(), StoreError> {
        let mut table = txn.open_table(DERIVED_STATE).map_err(crate::error::redb)?;
        table
            .insert(LIVE_KEY, [self.live.byte()].as_slice())
            .map_err(crate::error::redb)?;
        match &self.repair {
            Some(repair) => {
                table
                    .insert(REPAIR_KEY, encode_repair(repair).as_slice())
                    .map_err(crate::error::redb)?;
            }
            None => {
                table.remove(REPAIR_KEY).map_err(crate::error::redb)?;
            }
        }
        Ok(())
    }

    /// The generation a building repair reconstructs, if one is building.
    pub fn staging(&self) -> Option<Generation> {
        match self.repair.as_ref().map(|repair| &repair.phase) {
            Some(Phase::Building { staging, .. }) => Some(*staging),
            Some(Phase::Cleanup { .. }) | None => None,
        }
    }
}

/// `[phase:1][revision:8 BE][generation:1][source:1][after...]`: phase 0
/// building (generation = staging; `after` absent when the source is at its
/// start, flagged by a leading 0, else 1 then the key), phase 1 cleanup
/// (generation = old).
fn encode_repair(repair: &Repair) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12);
    match &repair.phase {
        Phase::Building {
            staging,
            source,
            after,
        } => {
            bytes.push(0);
            bytes.extend_from_slice(&repair.revision.to_be_bytes());
            bytes.push(staging.byte());
            bytes.push(source.byte());
            match after {
                None => bytes.push(0),
                Some(key) => {
                    bytes.push(1);
                    bytes.extend_from_slice(key);
                }
            }
        }
        Phase::Cleanup { old } => {
            bytes.push(1);
            bytes.extend_from_slice(&repair.revision.to_be_bytes());
            bytes.push(old.byte());
        }
    }
    bytes
}

fn decode_repair(bytes: &[u8]) -> Result<Repair, StoreError> {
    let malformed = || StoreError::Internal("malformed derived index repair state".into());
    let (phase, rest) = bytes.split_first().ok_or_else(malformed)?;
    let (revision, rest) = rest.split_first_chunk::<8>().ok_or_else(malformed)?;
    let revision = u64::from_be_bytes(*revision);
    match phase {
        0 => {
            let [staging, source, flag, after @ ..] = rest else {
                return Err(malformed());
            };
            let after = match flag {
                0 if after.is_empty() => None,
                1 => Some(after.to_vec()),
                _ => return Err(malformed()),
            };
            Ok(Repair {
                revision,
                phase: Phase::Building {
                    staging: Generation::from_byte(*staging)?,
                    source: Source::from_byte(*source)?,
                    after,
                },
            })
        }
        1 => match rest {
            [old] => Ok(Repair {
                revision,
                phase: Phase::Cleanup {
                    old: Generation::from_byte(*old)?,
                },
            }),
            _ => Err(malformed()),
        },
        _ => Err(malformed()),
    }
}

impl PersistentStore {
    /// The live generation of `ns`'s derived indexes, read in `txn`, for a
    /// decision that relies on their absence or completeness. Refused while
    /// the indexes are known divergent: a recorded divergence not yet
    /// repaired, or a repair still building.
    pub(crate) fn trusted_generation(
        &self,
        txn: &WriteTransaction,
        ns: &NamespaceRef,
    ) -> Result<Generation, StoreError> {
        let state = DerivedState::in_txn(txn)?;
        self.trusted(&state, ns.id())
    }

    /// [`Self::trusted_generation`] over a snapshot.
    pub(crate) fn trusted_snapshot_generation(
        &self,
        snapshot: &NamespaceSnapshot,
    ) -> Result<Generation, StoreError> {
        let state = DerivedState::read(&snapshot.table(DERIVED_STATE)?)?;
        self.trusted(&state, &snapshot.controller().id)
    }

    fn trusted(
        &self,
        state: &DerivedState,
        namespace: &[u8; 16],
    ) -> Result<Generation, StoreError> {
        if state.staging().is_some() || self.divergence_recorded(namespace) {
            return Err(StoreError::Unavailable(format!(
                "the derived indexes of namespace {} are being repaired",
                hex::encode(namespace)
            )));
        }
        Ok(state.live)
    }
}

/// Record a reference an authoritative mutation creates. Outside a
/// repair the entry must not already exist: a present entry means the
/// index diverged from the committed state it projects, and the mutation
/// must not commit over that. While a repair builds, the change is applied
/// to both generations as is.
pub fn establish(
    store: &PersistentStore,
    txn: &WriteTransaction,
    ns: &NamespaceRef,
    content: &Kappa,
    referrer: &crate::referrers::Referrer,
) -> Result<(), StoreError> {
    let state = DerivedState::in_txn(txn)?;
    let key = content.key_bytes();
    let value = referrer.encode();
    let present = txn
        .open_multimap_table(state.live.referrers())
        .map_err(crate::error::redb)?
        .insert(key.as_slice(), value.as_slice())
        .map_err(crate::error::redb)?;
    match state.staging() {
        Some(staging) => {
            txn.open_multimap_table(staging.referrers())
                .map_err(crate::error::redb)?
                .insert(key.as_slice(), value.as_slice())
                .map_err(crate::error::redb)?;
        }
        None if present => {
            return Err(store.index_diverged(
                ns.id(),
                "REFERRERS",
                format!("referrer index already held {referrer:?} for {content}"),
            ));
        }
        None => {}
    }
    Ok(())
}

/// Remove a reference an authoritative mutation retires. Outside a repair
/// the entry must exist: an absent entry means the index diverged. While a
/// repair builds, the change is applied to both generations as is.
pub fn release(
    store: &PersistentStore,
    txn: &WriteTransaction,
    ns: &NamespaceRef,
    content: &Kappa,
    referrer: &crate::referrers::Referrer,
) -> Result<(), StoreError> {
    let state = DerivedState::in_txn(txn)?;
    let key = content.key_bytes();
    let value = referrer.encode();
    let existed = txn
        .open_multimap_table(state.live.referrers())
        .map_err(crate::error::redb)?
        .remove(key.as_slice(), value.as_slice())
        .map_err(crate::error::redb)?;
    match state.staging() {
        Some(staging) => {
            txn.open_multimap_table(staging.referrers())
                .map_err(crate::error::redb)?
                .remove(key.as_slice(), value.as_slice())
                .map_err(crate::error::redb)?;
        }
        None if !existed => {
            return Err(store.index_diverged(
                ns.id(),
                "REFERRERS",
                format!("referrer index lacked {referrer:?} for {content}"),
            ));
        }
        None => {}
    }
    Ok(())
}

/// Record that the row of `identity` selects `allocation`. Outside a
/// repair the allocation must have no owner: a fresh allocation is owned by
/// no committed row, so an entry is divergence.
pub fn claim_allocation(
    store: &PersistentStore,
    txn: &WriteTransaction,
    ns: &NamespaceRef,
    allocation: &AllocationId,
    identity: &Kappa,
) -> Result<(), StoreError> {
    let state = DerivedState::in_txn(txn)?;
    let owner = identity.key_bytes();
    let previous = txn
        .open_table(state.live.allocations())
        .map_err(crate::error::redb)?
        .insert(allocation.0.as_slice(), owner.as_slice())
        .map_err(crate::error::redb)?
        .is_some();
    match state.staging() {
        Some(staging) => {
            txn.open_table(staging.allocations())
                .map_err(crate::error::redb)?
                .insert(allocation.0.as_slice(), owner.as_slice())
                .map_err(crate::error::redb)?;
        }
        None if previous => {
            return Err(store.index_diverged(
                ns.id(),
                "ALLOCATIONS",
                format!("allocation {} is already owned", allocation.hex()),
            ));
        }
        None => {}
    }
    Ok(())
}

/// Remove the ownership of `allocation` by the retired row of `identity`.
/// Outside a repair the entry must name exactly that row.
pub fn release_allocation(
    store: &PersistentStore,
    txn: &WriteTransaction,
    ns: &NamespaceRef,
    allocation: &AllocationId,
    identity: &Kappa,
) -> Result<(), StoreError> {
    let state = DerivedState::in_txn(txn)?;
    let owner = txn
        .open_table(state.live.allocations())
        .map_err(crate::error::redb)?
        .remove(allocation.0.as_slice())
        .map_err(crate::error::redb)?
        .map(|guard| guard.value().to_vec());
    match state.staging() {
        Some(staging) => {
            txn.open_table(staging.allocations())
                .map_err(crate::error::redb)?
                .remove(allocation.0.as_slice())
                .map_err(crate::error::redb)?;
        }
        None if owner.as_deref() != Some(identity.key_bytes().as_slice()) => {
            return Err(store.index_diverged(
                ns.id(),
                "ALLOCATIONS",
                format!(
                    "allocation {} ownership disagrees with the retired row",
                    allocation.hex()
                ),
            ));
        }
        None => {}
    }
    Ok(())
}

/// Whether both tables of `generation` are empty in `txn`.
pub fn generation_empty(
    txn: &WriteTransaction,
    generation: Generation,
) -> Result<bool, StoreError> {
    let referrers = txn
        .open_multimap_table(generation.referrers())
        .map_err(crate::error::redb)?;
    let allocations = txn
        .open_table(generation.allocations())
        .map_err(crate::error::redb)?;
    Ok(referrers
        .iter()
        .map_err(crate::error::redb)?
        .next()
        .is_none()
        && allocations
            .iter()
            .map_err(crate::error::redb)?
            .next()
            .is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_state_round_trips_and_refuses_malformed_encodings() -> Result<(), StoreError> {
        for repair in [
            Repair {
                revision: 7,
                phase: Phase::Building {
                    staging: Generation::One,
                    source: Source::FIRST,
                    after: None,
                },
            },
            Repair {
                revision: u64::MAX,
                phase: Phase::Building {
                    staging: Generation::Zero,
                    source: Source::Pins,
                    after: Some(b"key".to_vec()),
                },
            },
            Repair {
                revision: 0,
                phase: Phase::Cleanup {
                    old: Generation::One,
                },
            },
        ] {
            assert_eq!(decode_repair(&encode_repair(&repair))?, repair);
        }
        assert!(decode_repair(&[]).is_err());
        assert!(decode_repair(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(decode_repair(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 9, 0]).is_err());
        assert!(
            decode_repair(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 7]).is_err(),
            "an absent cursor carries no key"
        );
        Ok(())
    }
}
