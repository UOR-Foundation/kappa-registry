//! The staged opening of one epoch read (`settlement_ledger`): the seal's
//! records are located, read and completed one indivisible unit at a time,
//! each admitted at the bound its readers charge (`settlement_work`), so a
//! refusal keeps every stage before it and the next step resumes exactly
//! where the refusal fell.
//!
//! Stages, in order: the epoch index lookup; the root record located (its
//! rows, its buffer reserved at its validated extent, its allocation
//! opened); the root's chunks, one unit each, hashed as they arrive; the
//! root completed (its identity checked against the hash, the root decoded
//! and its authority verified); the state record located, read and
//! completed the same way; the ledger row located and its allocation
//! opened, retained for the read that follows. A record's identity is
//! established by the incremental hash over every byte read, never by a
//! second pass over a copy; a record that does not hash to its identity is
//! rejected before it is decoded.

use kappa_store::canonical::bounded_record;
use kappa_store::epoch_authority::EpochAuthority;
use kappa_store::epoch_publication::verify_epoch_authority;
use kappa_store::work::{Dimension, Meter, Work, WorkExhausted};
use kappa_store::{EpochRoot, Kappa, LogicalIncarnation, StoreError};
use redb::ReadOnlyTable;

use super::super::work::SettlementLimits;
use crate::content_read::{RecordEvidence, RecordReader};
use crate::content_stream::ExternalSource;
use crate::namespace_snapshot::NamespaceSnapshot;
use crate::representation::{BlobRecord, Representation};
use crate::storage::{IncarnationUse, NamespaceStorage};

/// Where the ledger's bytes are read from once the read is open.
pub(super) enum LedgerSource {
    /// The ledger row holds its bytes.
    Inline(BlobRecord),
    /// One allocation, pinned and open for the whole read.
    External(ExternalSource),
    /// A composite served range by range through the view, under
    /// `identity`.
    Composite(Kappa),
}

/// What opening reached when it finished.
pub(super) struct Opened {
    pub(super) root_identity: Kappa,
    pub(super) root: EpochRoot,
    pub(super) incarnation: LogicalIncarnation,
    pub(super) ledger: LedgerSource,
    pub(super) ledger_size: u64,
}

/// What one advance of the opener did.
pub(super) enum OpenStep {
    /// The meter refused the next unit; the stages completed stand.
    Budget,
    Opened(Opened),
}

/// The stage an opening stands at. Each variant holds exactly what the
/// stages before it established and this one has not yet consumed.
enum Stage {
    Index,
    LocateRoot,
    Root(RecordReader),
    RootComplete(RecordEvidence),
    RootAuthority,
    LocateState,
    State(RecordReader),
    StateComplete(RecordEvidence),
    Ledger,
}

/// The staged opening of one epoch read, retained with its cursor between
/// steps. Every result a stage establishes is kept here; a refused stage is
/// run again from its own start, never from the opening's.
pub(super) struct Opener {
    epoch: u64,
    stage: Stage,
    root_identity: Option<Kappa>,
    root: Option<EpochRoot>,
    incarnation: Option<LogicalIncarnation>,
    refused: Option<WorkExhausted>,
}

impl std::fmt::Debug for Opener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Opener")
            .field("epoch", &self.epoch)
            .field("stage", &self.stage_name())
            .field("root_identity", &self.root_identity)
            .field("refused", &self.refused)
            .finish()
    }
}

impl Opener {
    /// An opening of `epoch`, nothing yet looked up.
    pub(super) const fn new(epoch: u64) -> Self {
        Self {
            epoch,
            stage: Stage::Index,
            root_identity: None,
            root: None,
            incarnation: None,
            refused: None,
        }
    }

    fn stage_name(&self) -> &'static str {
        match &self.stage {
            Stage::Index => "index",
            Stage::LocateRoot => "locate-root",
            Stage::Root(_) => "read-root",
            Stage::RootComplete(_) => "decode-root",
            Stage::RootAuthority => "verify-root-authority",
            Stage::LocateState => "locate-state",
            Stage::State(_) => "read-state",
            Stage::StateComplete(_) => "decode-state",
            Stage::Ledger => "locate-ledger",
        }
    }

    fn next_work(&self, limits: SettlementLimits) -> Result<Work, StoreError> {
        Ok(match &self.stage {
            Stage::Index => limits.opening_index(),
            Stage::LocateRoot | Stage::LocateState => limits.opening_record(),
            Stage::Root(reader) | Stage::State(reader) if reader.complete() => Work::default(),
            Stage::Root(_) | Stage::State(_) => limits.opening_chunk(),
            Stage::RootComplete(bytes) => {
                limits.opening_root_completion(bytes.content.len() as u64)?
            }
            Stage::RootAuthority => limits.opening_authority(),
            Stage::StateComplete(bytes) => {
                limits.opening_state_completion(bytes.content.len() as u64)?
            }
            Stage::Ledger => limits.opening_ledger(),
        })
    }

    fn root_identity(&self) -> Result<&Kappa, StoreError> {
        self.root_identity
            .as_ref()
            .ok_or_else(|| StoreError::Internal("epoch opening lost its root identity".into()))
    }

    fn root(&self) -> Result<&EpochRoot, StoreError> {
        self.root
            .as_ref()
            .ok_or_else(|| StoreError::Internal("epoch opening lost its root".into()))
    }

    fn incarnation(&self) -> Result<LogicalIncarnation, StoreError> {
        self.incarnation
            .ok_or_else(|| StoreError::Internal("epoch opening lost its incarnation".into()))
    }

    /// Advance the opening within `work` over `snapshot` and `index`,
    /// `limits` naming each stage's unit and `authority` the history the
    /// root is verified against. Returns `Budget` when the meter refuses the
    /// next unit, with every completed stage retained.
    pub(super) fn advance(
        &mut self,
        snapshot: &NamespaceSnapshot,
        index: &ReadOnlyTable<&'static [u8], &'static [u8]>,
        limits: SettlementLimits,
        authority: &EpochAuthority,
        work: &mut dyn Meter,
    ) -> Result<OpenStep, StoreError> {
        let ns = NamespaceStorage::namespace_ref(snapshot.controller().id);
        let view = snapshot.view();
        loop {
            let required = self.next_work(limits)?;
            if let Err(refused) = work.admits(&required.as_bound()) {
                if self.refused != Some(refused) {
                    tracing::debug!(epoch = self.epoch, stage = self.stage_name(),
                        ?required, %refused, "epoch opening retained at admission refusal");
                }
                self.refused = Some(refused);
                return Ok(OpenStep::Budget);
            }
            self.refused = None;
            // The stage is taken out and put back on every path: a refusal
            // restores the stage it refused, a completion installs the next.
            match std::mem::replace(&mut self.stage, Stage::Index) {
                Stage::Index => {
                    let Ok(mut unit) = work.admit(&required.as_bound()) else {
                        return Ok(OpenStep::Budget);
                    };
                    let identity = super::read::indexed_root(
                        snapshot.transaction(),
                        &ns,
                        self.epoch,
                        &mut unit,
                    )?;
                    self.root_identity = Some(identity);
                    self.stage = Stage::LocateRoot;
                }
                Stage::LocateRoot => {
                    let Ok(mut unit) = work.admit(&required.as_bound()) else {
                        self.stage = Stage::LocateRoot;
                        return Ok(OpenStep::Budget);
                    };
                    let identity = self.root_identity()?.clone();
                    let reader = RecordReader::locate(
                        view,
                        index,
                        &identity,
                        limits.record_bytes(),
                        &mut unit,
                    )?;
                    self.stage = Stage::Root(reader);
                }
                Stage::Root(mut reader) => {
                    if reader.complete() {
                        self.stage = Stage::RootComplete(reader.finish()?);
                        continue;
                    }
                    let Ok(mut unit) = work.admit(&required.as_bound()) else {
                        self.stage = Stage::Root(reader);
                        return Ok(OpenStep::Budget);
                    };
                    reader.read_chunk(&mut unit)?;
                    self.stage = Stage::Root(reader);
                }
                Stage::RootComplete(bytes) => {
                    let Ok(mut unit) = work.admit(&required.as_bound()) else {
                        self.stage = Stage::RootComplete(bytes);
                        return Ok(OpenStep::Budget);
                    };
                    let root = EpochRoot::from_verified(
                        &bytes.content,
                        1,
                        &mut unit,
                        &view.record_storage.decoded,
                    )?;
                    if root.namespace_id() != ns.id() || root.epoch_number() != self.epoch {
                        return Err(StoreError::Conflict(
                            "epoch index coordinates differ from authenticated root".into(),
                        ));
                    }
                    self.root = Some(root);
                    self.stage = Stage::RootAuthority;
                }
                Stage::RootAuthority => {
                    let Ok(mut unit) = work.admit(&required.as_bound()) else {
                        self.stage = Stage::RootAuthority;
                        return Ok(OpenStep::Budget);
                    };
                    unit.account(Dimension::Signatures, 1)?;
                    verify_epoch_authority(self.root()?, authority)?;
                    // The transition domain is bound to the state this root
                    // authenticates, not to a filename or a mutable row.
                    self.incarnation = Some(
                        snapshot
                            .controller()
                            .logical_incarnation(IncarnationUse::Settlement)?,
                    );
                    self.stage = Stage::LocateState;
                }
                Stage::LocateState => {
                    let Ok(mut unit) = work.admit(&required.as_bound()) else {
                        self.stage = Stage::LocateState;
                        return Ok(OpenStep::Budget);
                    };
                    let state = self.root()?.state().clone();
                    let reader = RecordReader::locate(
                        view,
                        index,
                        &state,
                        kappa_store::NamespaceState::MAX_ENCODED_LEN,
                        &mut unit,
                    )?;
                    self.stage = Stage::State(reader);
                }
                Stage::State(mut reader) => {
                    if reader.complete() {
                        self.stage = Stage::StateComplete(reader.finish()?);
                        continue;
                    }
                    let Ok(mut unit) = work.admit(&required.as_bound()) else {
                        self.stage = Stage::State(reader);
                        return Ok(OpenStep::Budget);
                    };
                    reader.read_chunk(&mut unit)?;
                    self.stage = Stage::State(reader);
                }
                Stage::StateComplete(bytes) => {
                    let Ok(mut unit) = work.admit(&required.as_bound()) else {
                        self.stage = Stage::StateComplete(bytes);
                        return Ok(OpenStep::Budget);
                    };
                    let decoded = bounded_record::<kappa_store::NamespaceState>(
                        &bytes.content,
                        &mut unit,
                        &view.record_storage.decoded,
                    )?;
                    let state = decoded.value();
                    let incarnation = self.incarnation()?;
                    if state.namespace() != ns.id() || !incarnation.names(state.incarnation()) {
                        return Err(StoreError::Conflict(
                            "settlement state names another namespace instance".into(),
                        ));
                    }
                    self.stage = Stage::Ledger;
                }
                Stage::Ledger => {
                    let Ok(mut unit) = work.admit(&required.as_bound()) else {
                        self.stage = Stage::Ledger;
                        return Ok(OpenStep::Budget);
                    };
                    let ledger_root = self.root()?.ledger_root().clone();
                    let (record, row) = view.sized_record(index, &ledger_root, &mut unit)?;
                    if row > limits.record_bytes() {
                        return Err(StoreError::CapacityExceeded(format!(
                            "the ledger row of epoch {} is {row} bytes, beyond the settlement record limit {}",
                            self.epoch,
                            limits.record_bytes()
                        )));
                    }
                    let (held, record) =
                        view.resolve_alias(index, &ledger_root, record, &mut unit)?;
                    if record.compression().is_some() {
                        return Err(StoreError::Internal("invalid epoch content framing".into()));
                    }
                    let ledger_size = record.total_size();
                    let ledger = match record.representation() {
                        Representation::Inline { .. } => LedgerSource::Inline(record),
                        Representation::External { .. } => LedgerSource::External(
                            view.open_external(&held, &record, false, &mut unit)?,
                        ),
                        Representation::Composite { .. } => LedgerSource::Composite(held),
                        Representation::Alias { .. } | Representation::Manifest { .. } => {
                            return Err(StoreError::Internal(format!(
                                "ledger {held} is not addressable content"
                            )));
                        }
                    };
                    let root_identity = self.root_identity()?.clone();
                    let incarnation = self.incarnation()?;
                    let root = self.root.take().ok_or_else(|| {
                        StoreError::Internal("epoch opening lost its root".into())
                    })?;
                    return Ok(OpenStep::Opened(Opened {
                        root_identity,
                        root,
                        incarnation,
                        ledger,
                        ledger_size,
                    }));
                }
            }
        }
    }
}
