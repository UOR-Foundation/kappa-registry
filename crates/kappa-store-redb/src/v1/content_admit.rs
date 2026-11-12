//! Logical admission of content and its blob metadata as transitions.
//!
//! The domain functions here decide what an execution admits: the
//! canonical holder of prepared or composed bytes when no row selects it
//! yet, each alias under another mandatory axis that no row holds, an
//! explicit record, a blob metadata change. Each is applied through the
//! transition boundary (`transition_apply`) as its canonical evidence
//! (`ContentAdmissionRecord`, `MetadataTransition`), and the boundary
//! calls the row helpers here, which install through the native mechanics
//! of `content_install` and record nothing themselves.

use kappa_store::transition::RecordTransition;
use kappa_store::{CompositionEvidence, Kappa, StoreError, VerifiedContent};
use kappa_types::content::{
    ContentAdmission, ContentAdmissionEvidence, ContentAdmissionRecord, ContentAlias,
    ContentCommitment, ContentComponent, ContentComposition, MetadataTransition,
};

use crate::blob_rows::record_in_txn;
use crate::content_install::{Install, Installed, PreparedContent, canonical_order};
use crate::representation::{BlobRecord, Component, Representation};
use crate::transition_apply::{RedbPayload, TxnWriter};

impl TxnWriter<'_> {
    fn install(&self) -> Install<'_> {
        Install {
            store: self.store,
            txn: self.txn,
            ns: self.ns,
            limits: self.store.representation_limits,
        }
    }

    fn admission(&self, identity: &Kappa, size: u64) -> ContentAdmission {
        ContentAdmission::new(*self.ns.id(), *self.incarnation(), identity.clone(), size)
    }

    /// Admit each of `aliases` as a selector of `holder`: an alias a row
    /// already holds is kept when it selects the same bytes (refused
    /// otherwise); a new one is applied as its `ContentAlias` transition.
    fn admit_aliases(
        &self,
        holder: &Kappa,
        size: u64,
        aliases: &[Kappa],
    ) -> Result<(), StoreError> {
        for alias in aliases.iter().filter(|alias| *alias != holder) {
            if record_in_txn(self.store, self.txn, alias)?.is_some() {
                self.install().alias_row(holder, size, alias)?;
                continue;
            }
            let record = ContentAdmissionRecord::new(
                self.admission(alias, size),
                ContentAdmissionEvidence::Alias(ContentAlias::new(
                    alias.clone(),
                    holder.clone(),
                    size,
                )?),
            )?;
            self.apply(
                RecordTransition::ContentAlias(record),
                RedbPayload::NoResources,
            )?;
        }
        Ok(())
    }

    /// Admit prepared content: its canonical holder's admission when no row
    /// selects it yet (verified bytes for an inline representation, the
    /// chunk commitment of an external one), then each alias.
    pub(crate) fn admit_prepared(
        &self,
        prepared: PreparedContent,
    ) -> Result<Installed, StoreError> {
        if !prepared.owned_by_store(self.store) {
            return Err(StoreError::Rejected(
                "prepared content belongs to another store".into(),
            ));
        }
        let size = prepared.record().total_size();
        let (holder, aliases) =
            canonical_order(prepared.identity().clone(), prepared.aliases().to_vec());
        let installed = if record_in_txn(self.store, self.txn, &holder)?.is_some() {
            Installed::Existing
        } else {
            let evidence = match prepared.record().representation() {
                Representation::External {
                    chunk_size,
                    chunk_root,
                    ..
                } => ContentAdmissionEvidence::Chunked(ContentCommitment::new(
                    holder.clone(),
                    *chunk_size,
                    *chunk_root,
                )?),
                Representation::Inline { .. } => ContentAdmissionEvidence::VerifiedBytes,
                Representation::Alias { .. }
                | Representation::Manifest { .. }
                | Representation::Composite { .. } => {
                    return Err(StoreError::Internal(
                        "prepared content must be inline or external".into(),
                    ));
                }
            };
            let record = ContentAdmissionRecord::new(self.admission(&holder, size), evidence)?;
            self.apply(
                RecordTransition::ContentPublish(record),
                RedbPayload::PreparedContent(Box::new(prepared)),
            )?;
            Installed::New
        };
        self.admit_aliases(&holder, size, &aliases)?;
        Ok(installed)
    }

    /// Admit the composite `evidence` describes over components this
    /// namespace admitted: its holder's `ContentCompose` transition when no
    /// row selects it yet, then each alias. The evidence was produced by the
    /// shared preparation that streamed and verified the exact frozen
    /// selection; this installs representation metadata only and never
    /// assembles the payload.
    pub(crate) fn admit_composite(
        &self,
        evidence: &CompositionEvidence,
    ) -> Result<Installed, StoreError> {
        let size = evidence.total_bytes();
        let (holder, aliases) =
            canonical_order(evidence.identity().clone(), evidence.aliases().to_vec());
        let installed = if record_in_txn(self.store, self.txn, &holder)?.is_some() {
            Installed::Existing
        } else {
            let composition = ContentComposition::new(
                holder.clone(),
                evidence
                    .components()
                    .iter()
                    .map(|(identity, length)| ContentComponent {
                        identity: identity.clone(),
                        length: *length,
                    })
                    .collect(),
                size,
            )?;
            let record = ContentAdmissionRecord::new(
                self.admission(&holder, size),
                ContentAdmissionEvidence::Composition(composition),
            )?;
            self.apply(
                RecordTransition::ContentCompose(record),
                RedbPayload::NoResources,
            )?;
            Installed::New
        };
        self.admit_aliases(&holder, size, &aliases)?;
        Ok(installed)
    }

    /// Admit verified bytes the execution holds as an explicit record. An
    /// identity a row already holds is not admitted again.
    pub(crate) fn admit_record(&self, content: &VerifiedContent) -> Result<bool, StoreError> {
        if record_in_txn(self.store, self.txn, content.kappa())?.is_some() {
            return Ok(false);
        }
        let record = ContentAdmissionRecord::new(
            self.admission(content.kappa(), content.len() as u64),
            ContentAdmissionEvidence::VerifiedBytes,
        )?;
        let owned = VerifiedContent::verify(content.kappa(), content.content())?;
        self.apply(
            RecordTransition::RecordPublish(record),
            RedbPayload::ExplicitRecord(owned),
        )?;
        Ok(true)
    }

    /// Admit metadata `key` of `identity` set to `value`, or deleted. A
    /// deletion of metadata the namespace does not hold is a no-op and
    /// records no mutation.
    pub(crate) fn admit_blob_meta(
        &self,
        identity: &Kappa,
        key: &str,
        value: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        if value.is_none() && !self.blob_meta_held(identity, key)? {
            return Ok(());
        }
        let meta = MetadataTransition::blob_meta(
            *self.ns.id(),
            *self.incarnation(),
            identity.clone(),
            key.to_owned(),
            value.map(<[u8]>::to_vec),
        );
        self.apply(RecordTransition::Metadata(meta), RedbPayload::NoResources)
            .map(drop)
    }

    fn blob_meta_held(&self, identity: &Kappa, key: &str) -> Result<bool, StoreError> {
        let table = self
            .txn
            .open_table(crate::tables::BLOB_META)
            .map_err(crate::error::redb)?;
        match self.metered(|work| {
            crate::epoch_blob::blob_meta_from_table(self.store, &table, identity, key, work)
        }) {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    // -- Row helpers (called only by `apply`) --------------------------------

    /// Install the prepared row of the holder `record` admits, parking its
    /// allocation pin with the transaction's other pins until the
    /// publication settles.
    pub(crate) fn apply_prepared_admission(
        &self,
        record: &ContentAdmissionRecord,
        prepared: PreparedContent,
    ) -> Result<(), StoreError> {
        let (_, row, pin, _) = prepared.into_parts();
        self.install()
            .row(record.admission().identity(), &row, pin.is_some())?;
        if let Some(pin) = pin {
            self.store
                .controller(self.ns)?
                .writer_pins
                .lock()
                .map_err(|_| StoreError::Internal("writer pin set poisoned".into()))?
                .push(pin);
        }
        Ok(())
    }

    /// Install the verified record bytes `record` admits.
    pub(crate) fn apply_record_admission(
        &self,
        record: &ContentAdmissionRecord,
        content: &VerifiedContent,
    ) -> Result<(), StoreError> {
        if !crate::epoch_blob::blob_put_in_txn(self.store, self.txn, self.ns, content)? {
            return Err(StoreError::Internal(format!(
                "content {} admitted twice",
                record.admission().identity()
            )));
        }
        Ok(())
    }

    /// Install the alias row `record` admits, selecting its target.
    pub(crate) fn apply_alias_admission(
        &self,
        record: &ContentAdmissionRecord,
    ) -> Result<(), StoreError> {
        let ContentAdmissionEvidence::Alias(alias) = record.evidence() else {
            return Err(StoreError::Internal(
                "alias admission without alias evidence".into(),
            ));
        };
        if !self.install().alias_row(
            alias.target(),
            alias.length(),
            record.admission().identity(),
        )? {
            return Err(StoreError::Internal(format!(
                "alias {} admitted twice",
                record.admission().identity()
            )));
        }
        Ok(())
    }

    /// Install the composite row `record` admits: one level when its
    /// components fit a descriptor, otherwise manifest nodes of at most
    /// `fanout` leaves, each installed under its descriptor identity as a
    /// store-produced record, under a composite of nodes. Two levels bound
    /// the membership at `fanout * fanout`.
    pub(crate) fn apply_composite_admission(
        &self,
        record: &ContentAdmissionRecord,
    ) -> Result<(), StoreError> {
        let ContentAdmissionEvidence::Composition(composition) = record.evidence() else {
            return Err(StoreError::Internal(
                "composite admission without composition evidence".into(),
            ));
        };
        let leaves: Vec<Component> = composition
            .components()
            .iter()
            .map(|component| Component {
                identity: component.identity.clone(),
                length: component.length,
            })
            .collect();
        let row = self.composite_row(leaves)?;
        if row.total_size() != record.admission().logical_size() {
            return Err(StoreError::Internal(
                "composite descriptor disagrees with the admitted length".into(),
            ));
        }
        self.install()
            .row(record.admission().identity(), &row, false)
    }

    fn composite_row(&self, leaves: Vec<Component>) -> Result<BlobRecord, StoreError> {
        let limits = self.store.representation_limits;
        let fanout = limits.guaranteed_fanout();
        if leaves.len() <= fanout {
            return BlobRecord::composite(leaves, true, limits);
        }
        if leaves.len() > fanout.saturating_mul(fanout) {
            return Err(StoreError::CapacityExceeded(format!(
                "composite of {} components exceeds the two-level capacity {}",
                leaves.len(),
                fanout.saturating_mul(fanout)
            )));
        }
        let mut nodes = Vec::with_capacity(leaves.len().div_ceil(fanout));
        for group in leaves.chunks(fanout) {
            let node = BlobRecord::manifest(group.to_vec(), limits)?;
            let node_identity = node.manifest_identity()?;
            // A manifest node is content-addressed by its descriptor: an
            // existing row under that identity is the same node. It owns no
            // allocation, so there is no pin to hold.
            let prepared = PreparedContent::unallocated(node_identity.clone(), node)?
                .owned_by(&self.store.protection);
            crate::content_install::install_internal_in_txn(
                self.store, self.txn, self.ns, prepared, limits,
            )?;
            let length = group
                .iter()
                .try_fold(0u64, |total, c| total.checked_add(c.length))
                .ok_or_else(|| StoreError::CapacityExceeded("manifest length overflows".into()))?;
            nodes.push(Component {
                identity: node_identity,
                length,
            });
        }
        BlobRecord::composite(nodes, false, limits)
    }

    /// Hold `value` under `identity`'s metadata `key`, or remove the key,
    /// which the namespace must hold.
    pub(crate) fn apply_blob_meta(
        &self,
        identity: &Kappa,
        key: &str,
        value: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        match value {
            Some(value) => {
                crate::epoch_blob::blob_meta_put_in_txn(self.store, self.txn, identity, key, value)
            }
            None => {
                if !self.blob_meta_held(identity, key)? {
                    return Err(StoreError::Internal(format!(
                        "blob metadata deletion names {identity}:{key}, which the namespace does not hold"
                    )));
                }
                crate::epoch_blob::blob_meta_delete_in_txn(self.txn, identity, key)
            }
        }
    }
}
