//! The governing evidence of authority activation and what binds an
//! activation to it.
//!
//! An activation commits in its control namespace: the governing epoch,
//! sealed and signed by the private candidate, records the transition under
//! the create-only tag `_authority/{position}`. Nothing else makes a
//! transition authoritative.
//!
//! - [`ActivationHold`] is the exclusive activation gate with the candidate,
//!   bound to the governing instance and the predecessor its epoch extends;
//!   only `authority` constructs one, for the activation it prepares.
//! - The intent (`ACTIVATION_INTENT`) is written before the governing epoch
//!   is published, so a restart finds the evidence of an activation whose
//!   outcome its handle never learned.
//! - The history (`AUTHORITY_HISTORY`) projects the evidence: a row is
//!   written only once its epoch committed, and every row is verified
//!   against its evidence when the store opens.

use std::sync::{Arc, RwLockWriteGuard};

use redb::ReadableTable;

use kappa_store::error::StoreError;
use kappa_store::{
    ActivationDomain, AuthorityTransition, Axis, BlobStore, EpochAuthority, Kappa, TagStore,
};

use super::{AUTHORITY_TAG_PREFIX, row_context};
use crate::PersistentStore;
use crate::custody::CustodyActivation;
use crate::error::CommitFailure;
use crate::storage::{IncarnationUse, NamespaceController, NamespaceStorage};
use crate::storage_instance::StorageInstance;
use crate::tables::{ACTIVATION_INTENT, AUTHORITY_HISTORY};

/// The key of the one activation intent.
const INTENT_KEY: &[u8] = b"pending";

/// The tag that records the transition at `position` in its control
/// namespace.
pub fn activation_tag(position: u64) -> String {
    format!("{AUTHORITY_TAG_PREFIX}{position:020}")
}

/// The exclusive activation gate, held by the activation that publishes
/// one governing epoch, with the candidate that signs it. The candidate
/// signs, verifies and commits only that epoch: of the control instance
/// the activation names, extending the predecessor its execution read.
/// Dropping the hold releases the gate with the installed authority
/// unchanged.
pub struct ActivationHold<'g> {
    _gate: RwLockWriteGuard<'g, ()>,
    candidate: Arc<EpochAuthority>,
    /// The candidate as the read views of the governing epoch see it.
    view: Arc<arc_swap::ArcSwap<EpochAuthority>>,
    domain: ActivationDomain,
    predecessor: Option<Kappa>,
    /// The intent this activation recorded: the history position it fills
    /// and the identity of its transition record.
    intent: ActivationIntent,
    /// The installed authority the candidate succeeds.
    outgoing: Kappa,
}

impl<'g> ActivationHold<'g> {
    /// The hold of the activation `intent` records, which publishes the next
    /// epoch of its domain's control namespace on `predecessor`, signed by
    /// `candidate` in succession of `outgoing`. Visible to `authority` only.
    pub(super) fn new(
        gate: RwLockWriteGuard<'g, ()>,
        candidate: impl Into<Arc<EpochAuthority>>,
        intent: ActivationIntent,
        predecessor: Option<Kappa>,
        outgoing: Kappa,
    ) -> Self {
        let candidate = candidate.into();
        Self {
            _gate: gate,
            view: Arc::new(arc_swap::ArcSwap::new(Arc::clone(&candidate))),
            candidate,
            domain: intent.domain,
            predecessor,
            intent,
            outgoing,
        }
    }

    /// What the custody of this activation's governing epoch records, should
    /// its publication be retained after its signing coordinate is consumed.
    pub(crate) fn custody(&self) -> CustodyActivation {
        CustodyActivation {
            position: self.intent.position,
            record: self.intent.record.clone(),
            outgoing: self.outgoing.clone(),
        }
    }

    pub(crate) const fn candidate(&self) -> &Arc<EpochAuthority> {
        &self.candidate
    }

    pub(crate) const fn view(&self) -> &Arc<arc_swap::ArcSwap<EpochAuthority>> {
        &self.view
    }

    /// Whether an epoch of `controller` extending `predecessor` is the
    /// governing epoch this hold binds; refused otherwise.
    pub(crate) fn admits(
        &self,
        controller: &NamespaceController,
        predecessor: Option<&Kappa>,
    ) -> Result<(), StoreError> {
        let governs = controller
            .logical_incarnation(IncarnationUse::ActivationEvidence)
            .is_ok_and(|incarnation| incarnation.names(&self.domain.incarnation));
        if controller.id != self.domain.control
            || !governs
            || predecessor != self.predecessor.as_ref()
        {
            return Err(StoreError::Conflict(format!(
                "an activation candidate signs only its governing epoch of {}",
                hex::encode(self.domain.control)
            )));
        }
        Ok(())
    }
}

/// The activation in progress: the history position it fills, the domain
/// whose control namespace publishes it, and the identity of its record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationIntent {
    pub(crate) position: u64,
    pub(crate) domain: ActivationDomain,
    pub(crate) record: Kappa,
}

impl ActivationIntent {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(40 + self.record.key_bytes().len());
        bytes.extend_from_slice(&self.position.to_be_bytes());
        bytes.extend_from_slice(&self.domain.control);
        bytes.extend_from_slice(&self.domain.incarnation);
        bytes.extend_from_slice(&self.record.key_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let malformed = || StoreError::Internal("malformed activation intent".into());
        let (position, rest) = bytes.split_first_chunk::<8>().ok_or_else(malformed)?;
        let (control, rest) = rest.split_first_chunk::<16>().ok_or_else(malformed)?;
        let (incarnation, record) = rest.split_first_chunk::<16>().ok_or_else(malformed)?;
        Ok(Self {
            position: u64::from_be_bytes(*position),
            domain: ActivationDomain {
                control: *control,
                incarnation: *incarnation,
            },
            record: Kappa::from_key_bytes(record)?,
        })
    }
}

/// The AEAD context of the activation intent.
fn intent_context() -> String {
    crate::encrypted::bound("activation_intent", INTENT_KEY)
}

impl PersistentStore {
    /// Recover a pending candidate from authenticated custody and a supplied
    /// signing capability, without making it the installed authority.
    pub(super) fn restore_retained_authority<'a>(
        &self,
        intent: &ActivationIntent,
        origin: &kappa_store::AuthorityKey,
        committed: &[AuthorityTransition],
        offered: impl Iterator<Item = &'a kappa_crypto::SigningAuthority>,
    ) -> Result<(), StoreError> {
        if intent.position <= committed.len() as u64 {
            return Ok(());
        }
        let instance = self.activation_instance(&intent.domain)?;
        if !self.holds_custody(&instance)? {
            return Ok(());
        }
        let mut meter = kappa_store::work::WorkMeter::new(self.step_limit);
        let record = self.load_custody(&instance, &mut meter)?.ok_or_else(|| {
            StoreError::Unavailable("activation custody disappeared during restoration".into())
        })?;
        let activation = record.activation.as_ref().ok_or_else(|| {
            StoreError::Rejected("activation intent names ordinary publication custody".into())
        })?;
        let outgoing = committed
            .last()
            .map_or(origin, AuthorityTransition::incoming);
        if activation.position != intent.position
            || activation.record != intent.record
            || activation.outgoing != *outgoing.anchor()
        {
            return Err(StoreError::Rejected(
                "activation custody does not match its intent and outgoing authority".into(),
            ));
        }
        let bytes = record
            .transitions
            .iter()
            .find_map(|transition| match &transition.payload {
                crate::custody::CustodyPayload::Record { identity, bytes }
                    if identity == &intent.record =>
                {
                    Some(bytes.as_slice())
                }
                _ => None,
            })
            .ok_or_else(|| {
                StoreError::Rejected(
                    "activation custody does not hold its transition record".into(),
                )
            })?;
        kappa_store::VerifiedContent::verify(&intent.record, bytes)?;
        let transition = AuthorityTransition::from_bytes(bytes, origin.anchor())?;
        if transition.activation().domain != intent.domain || transition.outgoing() != outgoing {
            return Err(StoreError::Rejected(
                "retained activation changes its domain or outgoing authority".into(),
            ));
        }
        let signing = offered
            .into_iter()
            .find(|authority| authority.anchor() == transition.incoming().anchor())
            .ok_or_else(|| {
                StoreError::Unavailable(format!(
                    "retained activation requires signing capability {}",
                    transition.incoming().anchor(),
                ))
            })?;
        let mut history = committed.to_vec();
        history.push(transition);
        let candidate = EpochAuthority::restore(origin.clone(), history, signing.clone())?;
        self.retained_authority.store(Some(Arc::new(candidate)));
        self.authority_unresolved
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// An unpublished governing epoch still owns its activation intent.
    /// Presence prevents withdrawal; validation belongs to custody resolution.
    pub(super) fn activation_has_custody(
        &self,
        intent: &ActivationIntent,
    ) -> Result<bool, StoreError> {
        self.holds_custody(&self.activation_instance(&intent.domain)?)
    }

    /// The physical storage instance holding the evidence and custody of
    /// an activation in `domain`: the control namespace's open storage,
    /// when its logical incarnation is exactly the one the domain names.
    /// The physical instance is read from that storage, never built from
    /// the domain's logical bytes. Storage of another incarnation is
    /// refused as `Rejected`; missing storage is the snapshot's `NotFound`.
    fn activation_instance(
        &self,
        domain: &ActivationDomain,
    ) -> Result<StorageInstance, StoreError> {
        let control = NamespaceStorage::namespace_ref(domain.control);
        let snapshot = self.namespace_snapshot(&control)?;
        let controller = snapshot.controller();
        let incarnation = controller.logical_incarnation(IncarnationUse::ActivationEvidence)?;
        if !incarnation.names(&domain.incarnation) {
            return Err(StoreError::Rejected(format!(
                "control namespace {} is incarnation {incarnation}, not incarnation {} its activation names",
                hex::encode(domain.control),
                hex::encode(domain.incarnation)
            )));
        }
        Ok(controller.instance)
    }

    /// The decrypted rows of the authority history, in position order, and
    /// the activation intent, read in one registry snapshot. A gap in the
    /// rows is refused.
    pub(super) fn authority_rows(
        &self,
    ) -> Result<(Vec<Vec<u8>>, Option<ActivationIntent>), StoreError> {
        let txn = self.registry.begin_read()?;
        let history = txn
            .open_table(AUTHORITY_HISTORY)
            .map_err(crate::error::redb)?;
        let mut rows = Vec::new();
        for (expected, entry) in history.iter().map_err(crate::error::redb)?.enumerate() {
            let (key, value) = entry.map_err(crate::error::redb)?;
            if key.value() != expected as u64 {
                return Err(StoreError::Rejected(
                    "authority history has a missing row".into(),
                ));
            }
            rows.push(self.decrypt_bytes(&row_context(key.value()), value.value())?);
        }
        let intents = txn
            .open_table(ACTIVATION_INTENT)
            .map_err(crate::error::redb)?;
        let intent = intents
            .get(INTENT_KEY)
            .map_err(crate::error::redb)?
            .map(|value| {
                self.decrypt_bytes(&intent_context(), value.value())
                    .and_then(|bytes| ActivationIntent::decode(&bytes))
            })
            .transpose()?;
        Ok((rows, intent))
    }

    /// Record the origin row of a store without history.
    pub(super) fn record_origin(&self, origin: &[u8]) -> Result<(), StoreError> {
        let mut txn = self.registry.begin_write()?;
        txn.set_durability(redb::Durability::Immediate)
            .map_err(crate::error::redb)?;
        let row = self.encrypt_bytes(&row_context(0), origin)?;
        txn.open_table(AUTHORITY_HISTORY)
            .map_err(crate::error::redb)?
            .insert(0, row.as_slice())
            .map_err(crate::error::redb)?;
        match txn.commit() {
            Ok(()) => Ok(()),
            // The open that records the origin fails either way; the next
            // open reads the row if it persisted and records it otherwise.
            Err(CommitFailure::Known(error) | CommitFailure::Unknown(error)) => Err(error),
        }
    }

    /// Record `intent` durably before its governing epoch is published.
    /// Refused while another intent is pending: its outcome is resolved by
    /// `project_activations` or the next open first.
    pub(super) fn record_activation_intent(
        &self,
        intent: &ActivationIntent,
    ) -> Result<(), StoreError> {
        let mut txn = self.registry.begin_write()?;
        txn.set_durability(redb::Durability::Immediate)
            .map_err(crate::error::redb)?;
        {
            let mut intents = txn
                .open_table(ACTIVATION_INTENT)
                .map_err(crate::error::redb)?;
            if intents
                .get(INTENT_KEY)
                .map_err(crate::error::redb)?
                .is_some()
            {
                return Err(StoreError::Conflict(
                    "an earlier activation's outcome is unresolved; project the activations first"
                        .into(),
                ));
            }
            let value = self.encrypt_bytes(&intent_context(), &intent.encode())?;
            intents
                .insert(INTENT_KEY, value.as_slice())
                .map_err(crate::error::redb)?;
        }
        match txn.commit() {
            Ok(()) => Ok(()),
            // The activation stops before its governing epoch either way.
            // An intent that persisted names no evidence: the next
            // projection or open finds none and withdraws it.
            Err(CommitFailure::Known(error) | CommitFailure::Unknown(error)) => Err(error),
        }
    }

    /// Remove `intent` if it is still the pending one: its governing epoch
    /// is known not to have committed.
    pub(super) fn withdraw_activation_intent(
        &self,
        intent: &ActivationIntent,
    ) -> Result<(), StoreError> {
        let mut txn = self.registry.begin_write()?;
        txn.set_durability(redb::Durability::Immediate)
            .map_err(crate::error::redb)?;
        Self::remove_intent_in(self, &txn, intent)?;
        match txn.commit() {
            Ok(()) => Ok(()),
            // An intent that remains is withdrawn again by the next
            // projection or open: its outcome is already decided.
            Err(CommitFailure::Known(error) | CommitFailure::Unknown(error)) => Err(error),
        }
    }

    /// Project the transition `bytes` at `position` into the history, and
    /// remove `intent` with it when it is the pending one, in one durable
    /// registry transaction. A row already at `position` must be the same
    /// transition.
    pub(super) fn project_activation(
        &self,
        position: u64,
        bytes: &[u8],
        intent: Option<&ActivationIntent>,
    ) -> Result<(), StoreError> {
        let mut txn = self.registry.begin_write()?;
        txn.set_durability(redb::Durability::Immediate)
            .map_err(crate::error::redb)?;
        {
            let mut history = txn
                .open_table(AUTHORITY_HISTORY)
                .map_err(crate::error::redb)?;
            let existing = history
                .get(position)
                .map_err(crate::error::redb)?
                .map(|value| self.decrypt_bytes(&row_context(position), value.value()))
                .transpose()?;
            match existing {
                Some(existing) if existing == bytes => {}
                Some(_) => {
                    return Err(StoreError::Conflict(format!(
                        "authority history row {position} holds another transition"
                    )));
                }
                None => {
                    let row = self.encrypt_bytes(&row_context(position), bytes)?;
                    history
                        .insert(position, row.as_slice())
                        .map_err(crate::error::redb)?;
                }
            }
        }
        if let Some(intent) = intent {
            Self::remove_intent_in(self, &txn, intent)?;
        }
        match txn.commit() {
            Ok(()) => Ok(()),
            // The row is the committed evidence's projection: a row that
            // persisted is the same transition the next projection writes,
            // and an intent that remains is withdrawn once its position is
            // projected.
            Err(CommitFailure::Known(error) | CommitFailure::Unknown(error)) => Err(error),
        }
    }

    /// Remove the pending intent in `txn` when it is `intent`.
    fn remove_intent_in(
        &self,
        txn: &redb::WriteTransaction,
        intent: &ActivationIntent,
    ) -> Result<(), StoreError> {
        let mut intents = txn
            .open_table(ACTIVATION_INTENT)
            .map_err(crate::error::redb)?;
        let pending = intents
            .get(INTENT_KEY)
            .map_err(crate::error::redb)?
            .map(|value| {
                self.decrypt_bytes(&intent_context(), value.value())
                    .and_then(|bytes| ActivationIntent::decode(&bytes))
            })
            .transpose()?;
        if pending.as_ref() == Some(intent) {
            intents.remove(INTENT_KEY).map_err(crate::error::redb)?;
        }
        Ok(())
    }

    /// The evidence the control namespace of `domain` holds for the
    /// transition at `position` of the lineage from `origin`: the record's
    /// bytes, as committed, and the transition re-admitted from them. `None`
    /// when the namespace holds no record there. Evidence of another
    /// instance of the namespace, a record naming another domain, and
    /// storage that cannot be read are refused, never taken as absence.
    pub(super) fn activation_evidence(
        &self,
        position: u64,
        domain: &ActivationDomain,
        origin: &Kappa,
    ) -> Result<Option<(Vec<u8>, AuthorityTransition)>, StoreError> {
        let control = NamespaceStorage::namespace_ref(domain.control);
        self.activation_instance(domain)?;
        let tag = match self.tag_get_raw(&control, &activation_tag(position)) {
            Ok(tag) => tag,
            Err(StoreError::NotFound(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let bytes = self.blob_get_in(&control, &tag.kappa)?;
        if Kappa::compute(Axis::Sha256, &bytes)? != tag.kappa {
            return Err(StoreError::Rejected(format!(
                "the record of authority transition {position} does not hash to its tag"
            )));
        }
        let transition = AuthorityTransition::from_bytes(&bytes, origin)?;
        if transition.activation().domain != *domain {
            return Err(StoreError::Rejected(format!(
                "the record of authority transition {position} activates another domain"
            )));
        }
        Ok(Some((bytes, transition)))
    }
}
