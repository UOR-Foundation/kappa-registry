//! Epochs of a namespace view: sealing into the candidate, the epoch
//! number index, global lookup by root through the epoch projection, and
//! authority rotation.

use std::sync::Arc;

use kappa_store::epoch_publication::{
    EpochPublication, EpochPublicationInput, verify_persisted_epoch,
};
use kappa_store::time::Clock;
use kappa_store::traits::epoch::EpochStore;
use kappa_store::{
    Activation, AuthorityRotationError, VerifiedSuccession, WitnessEvidence, witness_standing,
};
use kappa_types::edge::Edge;
use kappa_types::epoch::EpochMutation;
use kappa_types::epoch_root::EpochRoot;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::tag::TagUpdate;
use kappa_types::{ActivationDomain, Axis, VerifiedContent};

use super::InMemoryStore;
use super::blob_read;
use super::execution::WriteCx;
use super::locate::incomplete;
use super::view::NamespaceView;

/// Bytes an epoch root may hold.
const ROOT_LIMIT: u64 = 1 << 20;

impl InMemoryStore {
    /// The authenticated epoch root `kappa` of `view`, admitted against its
    /// persisted ledger before use.
    pub(crate) fn epoch_in(
        &self,
        view: &NamespaceView,
        kappa: &Kappa,
    ) -> Result<EpochRoot, StoreError> {
        let bytes =
            blob_read::verified(view, kappa, Some(ROOT_LIMIT)).map_err(|error| match error {
                StoreError::NotFound(_) => StoreError::NotFound(format!("epoch root {kappa}")),
                other => other,
            })?;
        let root =
            EpochRoot::from_bytes(&bytes).map_err(|e| StoreError::Internal(e.to_string()))?;
        let ledger = blob_read::verified(view, root.ledger_root(), None)?;
        verify_persisted_epoch(&root, &self.authority.load(), &ledger)?;
        Ok(root)
    }

    /// The domain an activation published in `control` binds: the control
    /// namespace and its incarnation. Witnesses sign it.
    pub fn activation_domain(
        &self,
        control: &NamespaceRef,
    ) -> Result<ActivationDomain, StoreError> {
        let incarnation = self.slot(control.id())?.view.load().incarnation;
        let mut bytes = [0u8; 16];
        bytes[8..].copy_from_slice(&incarnation.to_be_bytes());
        Ok(ActivationDomain {
            control: *control.id(),
            incarnation: bytes,
        })
    }

    /// Hand epoch signing from the current authority to `next` through the
    /// admitted dual-signed `succession`, activated by `witnesses` and
    /// published in the control namespace `control`.
    ///
    /// The control namespace's writer is taken first, then the exclusive
    /// activation gate, the order every publication takes its writer and
    /// then the gate shared, so the rotation is ordered against every
    /// publication: each epoch is signed by the authority in force when it
    /// sealed, and none by an authority this call retired. Under the gate
    /// the witnesses' standing is checked, the incoming authority is
    /// installed, and the transition record is published in `control` as
    /// that authority's first epoch, carrying the succession path. If that
    /// publication fails the outgoing authority is reinstalled before the
    /// gate is released, so no seal ever observed the incoming one.
    ///
    /// The succession must be effective by the authority clock's time and
    /// strictly after the newest epoch any namespace sealed, so every
    /// published epoch stays admissible. Namespaces do not need to publish
    /// first: an idle namespace's next epoch carries the whole succession
    /// path from its head's signer.
    ///
    /// # Errors
    ///
    /// Always [`AuthorityRotationError::NotCommitted`]: this backend's
    /// installation is the in-memory swap with its publication, and a
    /// failure restores the outgoing authority.
    pub fn rotate_authority(
        &self,
        next: kappa_crypto::SigningAuthority,
        succession: VerifiedSuccession,
        witnesses: Vec<WitnessEvidence>,
        control: &NamespaceRef,
        clock: &dyn Clock,
    ) -> Result<(), AuthorityRotationError> {
        self.rotate_under_gate(next, succession, witnesses, control, clock)
            .map_err(AuthorityRotationError::NotCommitted)
    }

    fn rotate_under_gate(
        &self,
        next: kappa_crypto::SigningAuthority,
        succession: VerifiedSuccession,
        witnesses: Vec<WitnessEvidence>,
        control: &NamespaceRef,
        clock: &dyn Clock,
    ) -> Result<(), StoreError> {
        let mut execution = self.open_execution(control, clock)?;
        if execution
            .candidate()
            .record
            .as_ref()
            .is_none_or(|record| record.tombstoned)
        {
            return Err(StoreError::NotFound(format!("control namespace {control}")));
        }
        let gate = self
            .activation
            .write()
            .map_err(|_| StoreError::Internal("authority activation lock poisoned".into()))?;
        let effective = succession.inner().effective_at_ms;
        if self
            .latest_epoch()
            .is_some_and(|latest| latest >= effective)
        {
            return Err(StoreError::Rejected(
                "authority transition must take effect after every published epoch".into(),
            ));
        }
        let activation = Activation {
            domain: self.activation_domain(control)?,
            witnesses,
        };
        witness_standing(self, &activation, effective)?;
        let outgoing = self.authority.load_full();
        let (rotated, transition) =
            outgoing.rotate(next, succession, activation, execution.issued_at())?;
        let position = rotated.transitions().len();
        let record = VerifiedContent::compute(Axis::Sha256, &transition.to_bytes()?)?;
        execution.write(|cx| {
            cx.publish_record(&record)?;
            cx.tag_put(
                &format!("{AUTHORITY_TAG_PREFIX}{position:020}"),
                &TagUpdate::CreateIfAbsent {
                    kappa: record.kappa().clone(),
                },
            )
            .map(drop)
        })?;
        self.authority.store(Arc::new(rotated));
        if let Err(error) = execution.publish_under_activation() {
            self.authority.store(outgoing);
            return Err(error);
        }
        drop(gate);
        Ok(())
    }
}

/// Prefix of the control namespace's tags naming each admitted transition.
pub const AUTHORITY_TAG_PREFIX: &str = "_authority/";

impl WriteCx<'_> {
    /// Seal the candidate's ledger and tag state into a signed epoch. The
    /// ledger, root, linking edges, epoch index and head become visible
    /// together when the candidate is stored. The records the seal produces
    /// are admitted without recording mutations: the ledger is fixed.
    pub fn seal(&mut self, signer_override: Option<&Kappa>) -> Result<(u64, Kappa), StoreError> {
        let predecessor = self
            .view
            .epoch
            .clone()
            .map(|kappa| self.store.epoch_in(self.view, &kappa))
            .transpose()?;
        let mutations: Vec<EpochMutation> = self.view.ledger.iter().cloned().collect();
        // Callers hold the activation gate shared, which rotation takes
        // exclusively, so this snapshot is the authority in force for the
        // whole seal and store.
        let authority = self.store.authority.load();
        let publication = EpochPublication::prepare(
            EpochPublicationInput {
                namespace: self.ns,
                predecessor: predecessor.as_ref(),
                state_root: *self.view.digest.value(),
                tag_count: self.view.tags.len() as u64,
                mutations: &mutations,
                now: self.now,
                signer_override,
            },
            &authority,
        )?;
        self.publish_content(publication.ledger())?;
        self.publish_content(publication.root_blob())?;
        if let Some(path) = publication.rotation_record() {
            self.publish_content(path)?;
        }
        self.publish_content(publication.edge_blob())?;
        self.view.edges.insert(Edge {
            kappa: publication.edge_blob().kappa().clone(),
            input: publication.edge().clone(),
        });
        for (link, content) in publication.retained_links() {
            self.publish_content(content)?;
            self.view.edges.insert(Edge {
                kappa: content.kappa().clone(),
                input: link.clone(),
            });
        }
        let root = publication.into_root();
        let number = root.epoch_number();
        if self
            .view
            .epochs
            .insert(number, root.kappa().clone())
            .is_some()
        {
            return Err(StoreError::Internal(format!(
                "epoch {number} of {} sealed twice",
                self.ns
            )));
        }
        let sealed_ms = root.timestamp_ms();
        self.view.latest_epoch_ms = Some(
            self.view
                .latest_epoch_ms
                .map_or(sealed_ms, |latest| latest.max(sealed_ms)),
        );
        // The head reference moves with the pointer: the previous root is
        // retained by the new root's predecessor edge, the new root by being
        // the head.
        if let Some(previous) = self.view.epoch.replace(root.kappa().clone())
            && !self.view.release(&previous)
        {
            return Err(StoreError::Internal(format!(
                "reference index lacked the epoch head {previous}"
            )));
        }
        self.view.reference(root.kappa());
        self.view.ledger.clear();
        Ok((number, root.kappa().clone()))
    }
}

impl EpochStore for InMemoryStore {
    fn epoch_state(&self, ns: &NamespaceRef) -> Result<([u8; 32], u64), StoreError> {
        // One view supplies both values.
        let view = self.view(ns.id());
        Ok((*view.digest.value(), view.tags.len() as u64))
    }

    fn epoch_current(&self, ns: &NamespaceRef) -> Result<(u64, Kappa), StoreError> {
        let view = self.view(ns.id());
        let kappa = view
            .epoch
            .clone()
            .ok_or_else(|| StoreError::NotFound(format!("epoch for {ns}")))?;
        let root = self.epoch_in(&view, &kappa)?;
        if root.namespace_id() != ns.id() {
            return Err(StoreError::Internal(
                "epoch pointer crosses namespace identity".into(),
            ));
        }
        Ok((root.epoch_number(), kappa))
    }

    /// The candidate whose epoch index names `kappa` under the root's own
    /// epoch number decides: one index lookup per candidate.
    fn epoch_get(&self, kappa: &Kappa) -> Result<EpochRoot, StoreError> {
        let mut found: Option<Result<EpochRoot, StoreError>> = None;
        let complete = self.located(&self.projections.epochs, kappa, |_, view| {
            if !view.admitted.contains_key(kappa) {
                return false;
            }
            match self.epoch_in(view, kappa) {
                Ok(root) if view.epochs.get(&root.epoch_number()) == Some(kappa) => {
                    found = Some(Ok(root));
                    true
                }
                Ok(_) => false,
                Err(error) => {
                    found = Some(Err(error));
                    true
                }
            }
        });
        match found {
            Some(result) => result,
            None if complete => Err(StoreError::NotFound(format!("epoch root {kappa}"))),
            None => Err(incomplete(&format_args!("epoch root {kappa}"))),
        }
    }

    fn epoch_get_by_number(
        &self,
        ns: &NamespaceRef,
        epoch_number: u64,
    ) -> Result<Kappa, StoreError> {
        let view = self.view(ns.id());
        view.epochs.get(&epoch_number).cloned().ok_or_else(|| {
            let current = view.epochs.keys().next_back().copied().unwrap_or(0);
            StoreError::NotFound(format!("epoch {epoch_number} of {ns} (current {current})"))
        })
    }
}
