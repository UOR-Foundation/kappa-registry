//! Content admission, composition and retirement inside an epoch
//! execution's write transaction, each applied through the transition
//! boundary (`content_admit`, `content_reclaim`).

use kappa_store::{Kappa, StoreError};

use super::EpochExecution;
use crate::content_install::Installed;

impl EpochExecution<'_> {
    /// Admit content prepared before acquiring this execution's writer. The
    /// allocation pin of newly admitted external content is parked with the
    /// transaction's pins until the publication settles.
    pub fn install_content(
        &mut self,
        prepared: crate::PreparedContent,
    ) -> Result<kappa_store::IngestResult, StoreError> {
        let identity = prepared.identity().clone();
        let aliases = prepared.aliases().to_vec();
        let installed = self.with_writer(|writer| writer.admit_prepared(prepared))?;
        Ok(
            kappa_store::IngestResult::new(identity, installed == Installed::New)
                .with_additional(aliases),
        )
    }

    /// Admit the composite `evidence` describes and its aliases.
    pub fn compose_content(
        &mut self,
        evidence: &kappa_store::CompositionEvidence,
    ) -> Result<kappa_store::IngestResult, StoreError> {
        let installed = self.with_writer(|writer| writer.admit_composite(evidence))?;
        Ok(
            kappa_store::IngestResult::new(
                evidence.identity().clone(),
                installed == Installed::New,
            )
            .with_additional(evidence.aliases().to_vec()),
        )
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
        let retired =
            self.with_writer(|writer| crate::content_reclaim::retire_in_txn(writer, identity))?;
        Ok(match retired {
            Retired::Row(_) => Retirement::Retired,
            Retired::Retained => Retirement::Retained,
            Retired::Absent => Retirement::Absent,
        })
    }
}
