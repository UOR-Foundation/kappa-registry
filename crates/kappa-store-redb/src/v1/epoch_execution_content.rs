//! Content installation, composition and retirement inside an epoch
//! execution's write transaction.

use kappa_store::{Kappa, StoreError};

use super::EpochExecution;

impl EpochExecution<'_> {
    /// Consume content prepared before acquiring this execution's writer.
    pub fn install_content(
        &mut self,
        prepared: crate::PreparedContent,
    ) -> Result<kappa_store::IngestResult, StoreError> {
        self.ensure_active()?;
        let identity = prepared.identity().clone();
        let aliases = prepared.aliases().to_vec();
        let result = crate::content_install::install_in_txn(
            self.store,
            &self.transaction,
            &self.namespace,
            prepared,
            self.now,
            self.store.representation_limits,
        );
        let (installed, pin) = self.admit_result(result)?;
        self.content_pins.extend(pin);
        Ok(kappa_store::IngestResult::new(
            identity,
            installed == crate::content_install::Installed::New,
        )
        .with_additional(aliases))
    }

    /// Install the composite `evidence` describes, building manifest nodes
    /// when the membership exceeds one descriptor, and its aliases. The
    /// evidence was produced by the shared preparation that streamed and
    /// verified the exact frozen selection; this installs representation
    /// metadata only and never assembles the payload. A newly installed
    /// composite records its logical composition as `ContentCompose`
    /// evidence in the ledger.
    pub fn compose_content(
        &mut self,
        evidence: &kappa_store::CompositionEvidence,
    ) -> Result<kappa_store::IngestResult, StoreError> {
        self.ensure_active()?;
        let result = self.compose_in_txn(evidence);
        let (installed, pin) = self.admit_result(result)?;
        self.content_pins.extend(pin);
        Ok(installed)
    }

    /// The descriptor of the composite: one level when the components fit
    /// a descriptor, otherwise manifest nodes of at most `fanout` leaves,
    /// each installed under its descriptor identity, under a composite of
    /// nodes. Two levels bound the membership at `fanout * fanout`.
    fn composite_record(
        &self,
        evidence: &kappa_store::CompositionEvidence,
    ) -> Result<crate::representation::BlobRecord, StoreError> {
        let limits = self.store.representation_limits;
        let fanout = limits.guaranteed_fanout();
        let leaves: Vec<crate::representation::Component> = evidence
            .components()
            .iter()
            .map(|(identity, length)| crate::representation::Component {
                identity: identity.clone(),
                length: *length,
            })
            .collect();
        if leaves.len() <= fanout {
            return crate::representation::BlobRecord::composite(leaves, true, limits);
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
            let node = crate::representation::BlobRecord::manifest(group.to_vec(), limits)?;
            let node_identity = node.manifest_identity()?;
            let prepared = crate::PreparedContent::unallocated(node_identity.clone(), node)?
                .owned_by(&self.store.protection);
            // A manifest node is content-addressed by its descriptor: an
            // existing row under that identity is the same node, so new and
            // existing are equally valid. It owns no allocation, so there
            // is no pin to hold.
            crate::content_install::install_in_txn(
                self.store,
                &self.transaction,
                &self.namespace,
                prepared,
                self.now,
                limits,
            )?;
            let length = group
                .iter()
                .try_fold(0u64, |total, c| total.checked_add(c.length))
                .ok_or_else(|| StoreError::CapacityExceeded("manifest length overflows".into()))?;
            nodes.push(crate::representation::Component {
                identity: node_identity,
                length,
            });
        }
        crate::representation::BlobRecord::composite(nodes, false, limits)
    }

    fn compose_in_txn(
        &self,
        evidence: &kappa_store::CompositionEvidence,
    ) -> Result<(kappa_store::IngestResult, Option<crate::allocation::Pin>), StoreError> {
        let identity = evidence.identity();
        let aliases = evidence.aliases();
        let record = self.composite_record(evidence)?;
        if record.total_size() != evidence.total_bytes() {
            return Err(StoreError::Internal(
                "composite descriptor disagrees with the evidenced length".into(),
            ));
        }
        // The aliases are installed by the installer, which also selects the
        // canonical representation holder among the identities.
        let prepared = crate::PreparedContent::unallocated(identity.clone(), record)?
            .with_aliases(aliases.to_vec())
            .owned_by(&self.store.protection);
        let (installed, _) = crate::content_install::install_in_txn(
            self.store,
            &self.transaction,
            &self.namespace,
            prepared,
            self.now,
            self.store.representation_limits,
        )?;
        let new = installed == crate::content_install::Installed::New;
        // A new composite row is a new retention of its components: the
        // logical composition it rests on is recorded in this epoch's ledger
        // under the identity that holds the row.
        let pin = if new {
            let (holder, _) =
                crate::content_install::canonical_order(identity.clone(), aliases.to_vec());
            let composition = kappa_types::content::ContentComposition::new(
                holder,
                evidence
                    .components()
                    .iter()
                    .map(
                        |(identity, length)| kappa_types::content::ContentComponent {
                            identity: identity.clone(),
                            length: *length,
                        },
                    )
                    .collect(),
                evidence.total_bytes(),
            )?;
            let content = kappa_store::VerifiedContent::compute(
                kappa_store::Axis::Sha256,
                &kappa_store::canonical::canonical_bytes(&composition),
            )?;
            let pin = self.install_record(&content)?;
            self.store.record_mutation_in_txn(
                &self.transaction,
                &self.namespace,
                kappa_store::MutationOp::ContentCompose,
                content.kappa().clone(),
                self.now,
                None,
            )?;
            pin
        } else {
            None
        };
        Ok((
            kappa_store::IngestResult::new(identity.clone(), new).with_additional(aliases.to_vec()),
            pin,
        ))
    }

    /// Retire the representation of `identity` in this execution's
    /// transaction, so the retirement commits with its epoch. A retained or
    /// absent identity is reported without latching; only failures latch.
    /// The allocation is reclaimed when the epoch settles (its ownership
    /// projection is released there), subject to other owners, pins and a
    /// claim.
    pub fn retire_content(
        &mut self,
        identity: &Kappa,
    ) -> Result<kappa_store::execution::Retirement, StoreError> {
        use crate::content_reclaim::Retired;
        use kappa_store::execution::Retirement;
        self.ensure_active()?;
        let result = crate::content_reclaim::retire_in_txn(
            self.store,
            &self.transaction,
            &self.namespace,
            self.now,
            identity,
        );
        Ok(match self.admit_result(result)? {
            Retired::Row(_) => Retirement::Retired,
            Retired::Retained => Retirement::Retained,
            Retired::Absent => Retirement::Absent,
        })
    }
}
