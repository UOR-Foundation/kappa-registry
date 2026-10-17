//! Durable epoch signing authority: restore at open, rotation as one write
//! transaction.

use std::sync::Arc;

use redb::ReadableTable;

use kappa_store::error::StoreError;
use kappa_store::{
    Activation, ActivationDomain, AuthorityKey, AuthorityRotationError, AuthorityTransition, Axis,
    EpochAuthority, NamespaceRef, TagUpdate, VerifiedContent, VerifiedSuccession, WitnessEvidence,
    witness_standing,
};

use crate::PersistentStore;
use crate::storage_instance::Incarnation;
use crate::tables::AUTHORITY_HISTORY;

/// Prefix of the control namespace's tags naming each admitted transition.
pub const AUTHORITY_TAG_PREFIX: &str = "_authority/";

/// Value-encryption context of authority history rows, bound to the row
/// position so a transition cannot be moved within the chain.
fn row_context(position: u64) -> String {
    crate::encrypted::bound("authority", &position.to_be_bytes())
}

/// Public verification material of `authority`.
fn key_of(authority: &kappa_crypto::SigningAuthority) -> Result<AuthorityKey, StoreError> {
    let signer = authority.signer();
    AuthorityKey::new(signer.algorithm(), signer.public_key())
}

impl PersistentStore {
    /// Restore the authority history and select its current authority: the
    /// one among `configured` and `alternates` whose key is the persisted
    /// chain's last. A database without history records `configured` as
    /// its origin, unless `require_history` refuses that. Every persisted
    /// transition is re-verified, the chain must start at the recorded
    /// origin, and any persisted epoch that this history does not admit
    /// fails the subsequent epoch recovery.
    pub(crate) fn restore_authority(
        &self,
        configured: kappa_crypto::SigningAuthority,
        alternates: Vec<kappa_crypto::SigningAuthority>,
        require_history: bool,
    ) -> Result<(), StoreError> {
        let txn = self.registry.begin_write().map_err(crate::error::redb)?;
        let restored = {
            let mut table = txn
                .open_table(AUTHORITY_HISTORY)
                .map_err(crate::error::redb)?;
            let mut rows = Vec::new();
            for (expected, entry) in table.iter().map_err(crate::error::redb)?.enumerate() {
                let (key, value) = entry.map_err(crate::error::redb)?;
                if key.value() != expected as u64 {
                    return Err(StoreError::Rejected(
                        "authority history has a missing row".into(),
                    ));
                }
                rows.push(self.decrypt_bytes(&row_context(key.value()), value.value())?);
            }
            match rows.split_first() {
                Some((origin, transitions)) => {
                    let origin = AuthorityKey::from_bytes(origin)?;
                    // Each row is re-admitted with its activation evidence,
                    // bound to this lineage's origin.
                    let transitions = transitions
                        .iter()
                        .map(|row| AuthorityTransition::from_bytes(row, origin.anchor()))
                        .collect::<Result<Vec<_>, _>>()?;
                    let head = transitions
                        .last()
                        .map_or(&origin, AuthorityTransition::incoming)
                        .clone();
                    // At most one candidate holds the chain's last key; when
                    // none does, `restore` refuses the configured authority
                    // naming both anchors.
                    let mut current = configured;
                    for alternate in alternates {
                        if head == key_of(&alternate)? {
                            current = alternate;
                            break;
                        }
                    }
                    EpochAuthority::restore(origin, transitions, current)?
                }
                None if require_history => {
                    return Err(StoreError::AuthorityHistoryAbsent {
                        offered: alternates.len() + 1,
                    });
                }
                None => {
                    let authority = EpochAuthority::new(configured)?;
                    let origin =
                        self.encrypt_bytes(&row_context(0), &authority.origin().to_bytes()?)?;
                    table
                        .insert(0, origin.as_slice())
                        .map_err(crate::error::redb)?;
                    authority
                }
            }
        };
        txn.commit().map_err(crate::error::redb)?;
        self.authority.store(Arc::new(restored));
        Ok(())
    }

    /// Hand epoch signing from the current authority to `next` through the
    /// admitted dual-signed `succession`, durably.
    ///
    /// The transition is written in one write transaction, which excludes
    /// every seal. The new authority is installed only after that
    /// transaction commits, so a failed commit is never observable, and the
    /// activation gate keeps every seal from signing between the commit and
    /// the installation: each epoch is signed by the committed authority in
    /// force, and none by an authority this call retired.
    ///
    /// The succession must be effective by the authority clock's time and
    /// strictly after every epoch the store has sealed, because an outgoing
    /// authority's window ends, exclusively, at its successor's effective
    /// time; every published epoch therefore stays admissible. Namespaces
    /// need not publish first: an idle namespace's next epoch carries the
    /// whole succession path.
    ///
    /// # Errors
    ///
    /// [`AuthorityRotationError::NotCommitted`] for every failure before the
    /// durable commit: the write transaction is dropped, which aborts it, and
    /// the outgoing authority stays committed and installed.
    /// [`AuthorityRotationError::Indeterminate`] when the commit itself
    /// fails: whether the transition persisted is unknown, so this handle
    /// stops sealing (see `authority_unresolved`) until the store is
    /// reopened and its persisted history selects the authority.
    ///
    /// The transition is admitted only with `witnesses` qualifying for the
    /// activation domain of `control` and standing against their asserters'
    /// revocations and watermarks (`kappa_store::epoch_authority`). The
    /// committed history row carries the evidence, and restore re-admits
    /// it. After the commit the transition record is published in
    /// `control` under the incoming authority
    /// ([`Self::publish_activation_records`]); a failure there leaves the
    /// committed rotation standing, is logged, and is retried by the next
    /// call of that method.
    pub fn rotate_authority(
        &self,
        next: kappa_crypto::SigningAuthority,
        succession: VerifiedSuccession,
        witnesses: Vec<WitnessEvidence>,
        control: &NamespaceRef,
        clock: &dyn kappa_store::time::Clock,
    ) -> Result<(), AuthorityRotationError> {
        let not_committed = AuthorityRotationError::NotCommitted;
        // Refused first, before any storage access: an unresolved handle
        // reports its authority state whether or not its database still
        // admits write transactions. The flag is only ever set, so it is
        // checked again under the gate below.
        self.refuse_if_unresolved().map_err(not_committed)?;
        let governed = Activation {
            domain: self.activation_domain(control).map_err(not_committed)?,
            witnesses,
        };
        let txn = self
            .registry
            .begin_write()
            .map_err(|error| not_committed(crate::error::redb(error)))?;
        #[cfg(test)]
        self.hooks
            .reach(crate::test_hooks::Point::RotationWriterHeld);
        // Taken while holding the registry writer. Seals hold namespace
        // writers, never the registry's, and take this gate shared only
        // while they sign and commit; the exclusive acquisition here waits
        // for those and excludes every later one until the committed
        // authority is installed.
        let activation = self.activation.write().map_err(|_| {
            not_committed(StoreError::Internal(
                "authority activation lock poisoned".into(),
            ))
        })?;
        self.refuse_if_unresolved().map_err(not_committed)?;
        let (rotated, row, now) = self
            .prepare_rotation(&txn, next, succession, governed, clock)
            .map_err(not_committed)?;
        // Everything before this point dropped `txn` on error, aborting it.
        if let Err(error) = txn.commit() {
            self.authority_unresolved
                .store(true, std::sync::atomic::Ordering::SeqCst);
            drop(activation);
            return Err(AuthorityRotationError::Indeterminate(crate::error::redb(
                error,
            )));
        }
        tracing::debug!(
            rows = row,
            at = now.as_i64(),
            "authority rotation committed"
        );
        self.authority.store(Arc::new(rotated));
        drop(activation);
        if let Err(error) = self.publish_activation_records(control, clock) {
            tracing::warn!(%error, "committed authority activation not yet published in its control namespace");
        }
        Ok(())
    }

    /// The origin anchor of this store's authority lineage, which every
    /// rotation witness binds.
    pub fn authority_origin(&self) -> kappa_store::Kappa {
        self.authority.load().origin().anchor().clone()
    }

    /// The domain an activation in `control` binds: the control namespace
    /// and its storage instance's incarnation. Witnesses sign it. Storage
    /// of an unknown (legacy) incarnation cannot host an activation.
    pub fn activation_domain(
        &self,
        control: &NamespaceRef,
    ) -> Result<ActivationDomain, StoreError> {
        let active = self.namespaces.admit_read(control.id())?;
        match active.controller().instance.incarnation() {
            Incarnation::Known(incarnation) => Ok(ActivationDomain {
                control: *control.id(),
                incarnation,
            }),
            Incarnation::Unknown => Err(StoreError::Rejected(
                "a control namespace of unknown incarnation cannot host an activation".into(),
            )),
        }
    }

    /// Publish, in `control`, the record of every committed transition whose
    /// activation names it and that the namespace does not hold yet, under
    /// the create-only tag `_authority/{position}`. Idempotent: a record
    /// already published is left as it is.
    pub fn publish_activation_records(
        &self,
        control: &NamespaceRef,
        clock: &dyn kappa_store::time::Clock,
    ) -> Result<(), StoreError> {
        let domain = self.activation_domain(control)?;
        let authority = self.authority.load_full();
        let mut pending = Vec::new();
        for (index, transition) in authority.transitions().iter().enumerate() {
            if transition.activation().domain != domain {
                continue;
            }
            let position = index + 1;
            let name = format!("{AUTHORITY_TAG_PREFIX}{position:020}");
            match kappa_store::TagStore::tag_get_raw(self, control, &name) {
                Ok(_) => {}
                Err(StoreError::NotFound(_)) => pending.push((name, transition.to_bytes()?)),
                Err(error) => return Err(error),
            }
        }
        if pending.is_empty() {
            return Ok(());
        }
        let mut execution = kappa_store::ExecutionStore::begin_execution(self, control, clock)?;
        for (name, bytes) in pending {
            let record = VerifiedContent::compute(Axis::Sha256, &bytes)?;
            execution.blob_put(&record)?;
            execution.tag_put(
                &name,
                &TagUpdate::CreateIfAbsent {
                    kappa: record.kappa().clone(),
                },
            )?;
        }
        execution.publish().map(drop)
    }

    /// `AuthorityUnresolved` naming the installed (outgoing) authority when
    /// a rotation's commit outcome on this handle is unknown.
    fn refuse_if_unresolved(&self) -> Result<(), StoreError> {
        if self
            .authority_unresolved
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(StoreError::AuthorityUnresolved {
                outgoing: Box::new(self.authority.load().anchor().clone()),
            });
        }
        Ok(())
    }

    /// Admit the rotation against the installed authority and write its
    /// history row and time record into `txn`, without committing. Returns
    /// the rotated authority, the row position written and the authority
    /// clock's time.
    fn prepare_rotation(
        &self,
        txn: &redb::WriteTransaction,
        next: kappa_crypto::SigningAuthority,
        succession: VerifiedSuccession,
        activation: Activation,
        clock: &dyn kappa_store::time::Clock,
    ) -> Result<(EpochAuthority, u64, kappa_store::clock::ClockMs), StoreError> {
        let now = clock.now()?;
        let effective = succession.inner().effective_at_ms;
        // The bound covers every committed epoch once recovery has visited
        // every instance a restart found unsettled: settled epochs are in
        // the durable bound restored at open, and each visit joins its
        // instance's head (`settlement_driver::bounding_head`). Before
        // that, an epoch of an unvisited instance could fall inside the
        // outgoing authority's window this rotation would close.
        if let Some(refusal) = self
            .discovery_coverage()
            .unavailable("the published-time bound of an authority rotation")
        {
            return Err(refusal);
        }
        if self
            .latest_epoch_ms
            .load(std::sync::atomic::Ordering::SeqCst)
            >= effective
        {
            return Err(StoreError::Rejected(
                "authority transition must take effect after every published epoch".into(),
            ));
        }
        // Under the exclusive activation gate: no epoch, and with it no
        // revocation of a witness, commits between this check and the
        // rotation's commit.
        witness_standing(self, &activation, effective)?;
        #[cfg(test)]
        self.hooks
            .reach(crate::test_hooks::Point::RotationStandingChecked);
        let (rotated, transition) = self
            .authority
            .load()
            .rotate(next, succession, activation, now)?;
        let position = u64::try_from(rotated.transitions().len())
            .map_err(|_| StoreError::CapacityExceeded("authority history".into()))?;
        let row = self.encrypt_bytes(&row_context(position), &transition.to_bytes()?)?;
        txn.open_table(AUTHORITY_HISTORY)
            .map_err(crate::error::redb)?
            .insert(position, row.as_slice())
            .map_err(crate::error::redb)?;
        // The rotation's time bounds restart recovery like any other
        // committed time: the registry holds no committed floor of its
        // own, so the reservation ceiling is extended to cover it.
        self.reserve_time_in_txn(txn, kappa_store::clock::CausalTime::from_encoded(now))?;
        Ok((rotated, position, now))
    }

    /// Number of persisted authority history rows: the origin plus one per
    /// transition.
    #[cfg(test)]
    pub(crate) fn persisted_authority_rows(&self) -> Result<u64, StoreError> {
        use redb::{ReadableDatabase, ReadableTableMetadata};
        let txn = self.registry.begin_read().map_err(crate::error::redb)?;
        txn.open_table(AUTHORITY_HISTORY)
            .map_err(crate::error::redb)?
            .len()
            .map_err(crate::error::redb)
    }
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
