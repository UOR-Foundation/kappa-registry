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

use redb::{ReadableTable, TableHandle, WriteTransaction};

use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::identity::{HandleRecord, IdentityAssertion, Revocation, Succession, Watermark};
use kappa_store::{Kappa, StoreError};

use super::cursors::EpochConsumer;
use super::pending::{checkpoint, decode_checkpoint};
use super::stage::Staged;
use crate::control_plane::encode_assignment;
use crate::identity_local::AuthorizationTable;
use crate::identity_write::encode_subject_idx_value;
use crate::projection::{Family, Version};
use crate::projection_stage::{ProjectionStage, active_attempt, begin_attempt};
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
    stage: Option<ProjectionStage<'t>>,
}

impl<'t> Apply<'t> {
    pub(super) const fn new(
        txn: &'t WriteTransaction,
        instance: StorageInstance,
        epoch: u64,
        capacity: u64,
    ) -> Self {
        Self {
            txn,
            instance,
            epoch,
            capacity,
            stage: None,
        }
    }

    /// The stage of the attempt in progress, opened on first use: a cursor
    /// that resumes continues the attempt its earlier steps began.
    fn current(&mut self) -> Result<&mut ProjectionStage<'t>, StoreError> {
        if self.stage.is_none() {
            let attempts = self
                .txn
                .open_table(PROJECTION_ATTEMPTS)
                .map_err(crate::error::redb)?;
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
            )?);
        }
        self.stage
            .as_mut()
            .ok_or_else(|| StoreError::Internal("settlement stage not opened".into()))
    }

    /// The epoch is verified: complete its attempt and advance `SETTLED` to
    /// it, in the step's transaction. The checkpoint must be the epoch's
    /// predecessor, so effects are never completed out of order.
    pub(super) fn complete(mut self, root: &Kappa) -> Result<(), StoreError> {
        // The root's own locator is the epoch's last staged row; an epoch
        // with no other effect still stages it and completes its attempt.
        self.current()?.write(
            Family::EpochRoot,
            &root.key_bytes(),
            None,
            &Version::Put(Vec::new()),
        )?;
        let stage = self
            .stage
            .take()
            .ok_or_else(|| StoreError::Internal("settlement stage not opened".into()))?;
        stage.complete()?;
        let mut settled = self.txn.open_table(SETTLED).map_err(crate::error::redb)?;
        let located = self.instance.key();
        let previous = settled
            .get(located.as_slice())
            .map_err(crate::error::redb)?
            .map(|value| decode_checkpoint(value.value()))
            .transpose()?
            .map_or(0, |(number, _)| number);
        if previous.checked_add(1) != Some(self.epoch) {
            return Err(StoreError::Internal(format!(
                "settlement of epoch {} after checkpoint {previous}",
                self.epoch
            )));
        }
        settled
            .insert(located.as_slice(), checkpoint(self.epoch, root).as_slice())
            .map_err(crate::error::redb)?;
        Ok(())
    }
}

impl EpochConsumer for Apply<'_> {
    fn restart(&mut self) -> Result<(), StoreError> {
        self.stage = None;
        let attempt = begin_attempt(self.txn, &self.instance, self.epoch)?;
        self.stage = Some(ProjectionStage::open(
            self.txn,
            self.instance,
            self.epoch,
            attempt,
            self.capacity,
        )?);
        Ok(())
    }

    fn stage(&mut self, staged: Staged) -> Result<(), StoreError> {
        let ns = *self.instance.namespace();
        let stage = self.current()?;
        match staged {
            Staged::Admitted {
                identity,
                allocation,
                ..
            } => {
                let key = identity.key_bytes();
                stage.write(Family::Catalog, &key, None, &Version::Put(Vec::new()))?;
                if let Some(allocation) = allocation {
                    stage.write(
                        Family::AllocationOwner,
                        &allocation,
                        Some(&key),
                        &Version::Put(Vec::new()),
                    )?;
                    stage.write(
                        Family::AllocationByRow,
                        &key,
                        None,
                        &Version::Put(allocation.to_vec()),
                    )?;
                }
                Ok(())
            }
            Staged::Retired(identity) => {
                let key = identity.key_bytes();
                stage.write(Family::Catalog, &key, None, &Version::Tombstone)?;
                if let Some(Version::Put(allocation)) =
                    stage.latest(Family::AllocationByRow, &key, None)?
                {
                    stage.write(
                        Family::AllocationOwner,
                        &allocation,
                        Some(&key),
                        &Version::Tombstone,
                    )?;
                    stage.write(Family::AllocationByRow, &key, None, &Version::Tombstone)?;
                }
                Ok(())
            }
            Staged::Assignment(assignment) => stage.write(
                Family::Assignment,
                &ns,
                None,
                &Version::Put(encode_assignment(
                    assignment.plane_id()?,
                    assignment.generation,
                )),
            ),
            Staged::Directory(record) => {
                stage.write(Family::NamespaceRecord, &ns, None, &Version::Put(record))
            }
            Staged::Identity(effect) => identity(stage, &ns, effect),
        }
    }
}

/// Put `value` (or a tombstone for `None`) of `key` in `family`.
fn put_or_remove(
    stage: &mut ProjectionStage<'_>,
    family: Family,
    key: &[u8],
    value: Option<Vec<u8>>,
) -> Result<(), StoreError> {
    let version = value.map_or(Version::Tombstone, Version::Put);
    stage.write(family, key, None, &version)
}

/// A signed record under its identity, indexed by its asserter.
fn asserted(
    stage: &mut ProjectionStage<'_>,
    records: Family,
    by_asserter: Family,
    kappa: &Kappa,
    bytes: Vec<u8>,
    asserter: &Kappa,
) -> Result<(), StoreError> {
    let key = kappa.key_bytes();
    stage.write(records, &key, None, &Version::Put(bytes))?;
    stage.write(
        by_asserter,
        &asserter.key_bytes(),
        Some(&key),
        &Version::Put(Vec::new()),
    )
}

fn identity(
    stage: &mut ProjectionStage<'_>,
    ns: &[u8; 16],
    effect: IdentityEffect,
) -> Result<(), StoreError> {
    match effect {
        IdentityEffect::Assertion { kappa, bytes } => {
            let assertion: IdentityAssertion = from_canonical(&bytes)?;
            let subject = format!("{}\x00{}", assertion.subject, assertion.facet);
            stage.write(
                Family::AssertionBySubject,
                subject.as_bytes(),
                Some(&encode_subject_idx_value(&assertion.asserter, &kappa)),
                &Version::Put(Vec::new()),
            )?;
            asserted(
                stage,
                Family::Assertion,
                Family::AssertionByAsserter,
                &kappa,
                bytes,
                &assertion.asserter,
            )
        }
        IdentityEffect::Revocation { kappa, bytes } => {
            let revocation: Revocation = from_canonical(&bytes)?;
            asserted(
                stage,
                Family::Revocation,
                Family::RevocationByAsserter,
                &kappa,
                bytes,
                &revocation.asserter,
            )
        }
        IdentityEffect::Watermark { kappa, bytes } => {
            let watermark: Watermark = from_canonical(&bytes)?;
            asserted(
                stage,
                Family::Watermark,
                Family::WatermarkByAsserter,
                &kappa,
                bytes,
                &watermark.asserter,
            )
        }
        IdentityEffect::Succession { record } => succession(stage, &record),
        IdentityEffect::Binding { key, source, bytes } => {
            let present = bytes.is_some();
            put_or_remove(stage, Family::Binding, &key, bytes)?;
            stage.write(
                Family::BindingBySource,
                source.as_bytes(),
                Some(ns),
                &if present {
                    Version::Put(Vec::new())
                } else {
                    Version::Tombstone
                },
            )
        }
        IdentityEffect::Handle { key, bytes } => handle(stage, &key, bytes),
        IdentityEffect::Authorization { table, key, bytes } => {
            authorization(stage, table, &key, bytes)
        }
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
            put_or_remove(stage, family, &anchor_key, bytes)
        }
    }
}

/// A handle's anchor index follows its record: the instance's previous
/// version names the anchor whose member is removed first.
fn handle(
    stage: &mut ProjectionStage<'_>,
    key: &str,
    bytes: Option<Vec<u8>>,
) -> Result<(), StoreError> {
    if let Some(Version::Put(previous)) = stage.latest(Family::Handle, key.as_bytes(), None)? {
        let previous: HandleRecord = from_canonical(&previous)?;
        stage.write(
            Family::HandleByAnchor,
            &previous.anchor.key_bytes(),
            Some(key.as_bytes()),
            &Version::Tombstone,
        )?;
    }
    if let Some(bytes) = &bytes {
        let record: HandleRecord = from_canonical(bytes)?;
        stage.write(
            Family::HandleByAnchor,
            &record.anchor.key_bytes(),
            Some(key.as_bytes()),
            &Version::Put(Vec::new()),
        )?;
    }
    put_or_remove(stage, Family::Handle, key.as_bytes(), bytes)
}

/// The admitted ciphertext of an authorization row, cached for the key's
/// owner. The key's ownership is its claim (`identity_local::claim_locator`),
/// decided before publication; a completed copy from another instance means
/// the claim protocol was bypassed, and is refused rather than projected.
fn authorization(
    stage: &mut ProjectionStage<'_>,
    table: AuthorizationTable,
    key: &str,
    bytes: Option<Vec<u8>>,
) -> Result<(), StoreError> {
    let family = authorization_family(table)?;
    let own = *stage.instance();
    let foreign = stage
        .holders(family, key.as_bytes(), None)?
        .into_iter()
        .any(|(instance, version)| {
            instance.namespace() != own.namespace() && matches!(version, Version::Put(_))
        });
    if foreign {
        return Err(StoreError::Conflict(format!(
            "authorization key {key} is projected for another namespace"
        )));
    }
    put_or_remove(stage, family, key.as_bytes(), bytes)
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
/// is refused.
fn succession(stage: &mut ProjectionStage<'_>, record: &Succession) -> Result<(), StoreError> {
    if record.old_anchor == record.new_anchor {
        return Err(StoreError::Rejected(
            "succession cannot target itself".into(),
        ));
    }
    let old_key = record.old_anchor.key_bytes();
    let bytes = canonical_bytes(record);
    for (_, version) in stage.holders(Family::Succession, &old_key, None)? {
        if let Version::Put(existing) = version {
            if existing != bytes {
                return Err(StoreError::Conflict(
                    "anchor already has another succession record".into(),
                ));
            }
            return Ok(());
        }
    }
    let updates = {
        let view: &ProjectionStage<'_> = stage;
        kappa_store::succession_index::plan_succession_link(
            record,
            |anchor| {
                let mut depth = 0u64;
                for (_, version) in view.holders(Family::SuccessionDepth, anchor, None)? {
                    if let Version::Put(value) = version {
                        let value: [u8; 8] = value.as_slice().try_into().map_err(|_| {
                            StoreError::Internal("malformed succession depth".into())
                        })?;
                        depth = depth.max(u64::from_be_bytes(value));
                    }
                }
                Ok(depth)
            },
            |anchor| {
                for (_, version) in view.holders(Family::Succession, anchor, None)? {
                    if let Version::Put(value) = version {
                        let next: Succession = from_canonical(&value)?;
                        return Ok(Some(next.new_anchor));
                    }
                }
                Ok(None)
            },
        )?
    };
    stage.write(Family::Succession, &old_key, None, &Version::Put(bytes))?;
    for (anchor, links) in updates {
        stage.write(
            Family::SuccessionDepth,
            &anchor,
            None,
            &Version::Put(links.to_be_bytes().to_vec()),
        )?;
    }
    Ok(())
}
