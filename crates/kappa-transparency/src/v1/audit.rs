//! Construction of audit proofs between two committed epochs.

use kappa_types::canonical::canonical_bytes;
use kappa_types::merkle_index;

use crate::error::DirectoryError;
use crate::proof::{AuditProof, EpochBinding, TransitionProof, path_bytes};
use crate::record::Transition;

/// Transitions one audit page carries at most.
pub const AUDIT_PAGE: usize = 1024;

/// `value` as a position in the log held in memory. Every caller has
/// already bounded it by that log's length, so a refusal here names a
/// committed size this platform cannot address.
fn position(value: u64) -> Result<usize, DirectoryError> {
    usize::try_from(value).map_err(|_| {
        DirectoryError::Rejected(format!(
            "log position {value} exceeds this platform's address space"
        ))
    })
}

/// The audit proof from `from` to `to` over `log`, the log committed at
/// `to`, starting at `offset` (at least the earlier log's size).
pub(crate) fn build(
    from: EpochBinding,
    to: EpochBinding,
    log: &[Transition],
    offset: u64,
) -> Result<AuditProof, DirectoryError> {
    let first = from.commitment.log_size;
    let second = to.commitment.log_size;
    if log.len() as u64 != second {
        return Err(DirectoryError::Verification(
            "log held for the later epoch differs from its committed size".into(),
        ));
    }
    if first > second {
        return Err(DirectoryError::Rejected(
            "earlier epoch commits a longer log than the later one".into(),
        ));
    }
    if offset < first || offset > second {
        return Err(DirectoryError::Rejected(
            "audit offset is outside the range the epochs span".into(),
        ));
    }
    let leaves: Vec<Vec<u8>> = log.iter().map(canonical_bytes).collect();
    let refs: Vec<&[u8]> = leaves.iter().map(Vec::as_slice).collect();
    let consistency = if first == 0 {
        Vec::new()
    } else {
        merkle_index::consistency_proof(&refs, position(first)?)
            .ok_or_else(|| DirectoryError::Verification("no consistency proof".into()))?
    };
    let start = position(offset)?;
    let end = start.saturating_add(AUDIT_PAGE).min(log.len());
    let mut transitions = Vec::with_capacity(end - start);
    for (index, transition) in (start..end).zip(&log[start..end]) {
        let path = merkle_index::inclusion_proof(&refs, index).ok_or_else(|| {
            DirectoryError::Verification(format!("no inclusion proof for transition {index}"))
        })?;
        transitions.push(TransitionProof {
            transition: transition.clone(),
            index: index as u64,
            path: path_bytes(&path),
        });
    }
    let next = ((end as u64) < second).then_some(end as u64);
    Ok(AuditProof {
        from,
        to,
        consistency: path_bytes(&consistency),
        offset,
        transitions,
        next,
    })
}
