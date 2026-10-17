//! One execution per namespace batch of reconciled tags.

use tracing::warn;

use kappa_store::time::Clock;
use kappa_store::{ExecutionStore, StoreError, publish_if_changed};
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::tag::TagUpdate;

use super::wire::TagEntryWire;

/// Result of applying one namespace's reconciled tags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamespaceBatchOutcome {
    /// Tags whose local value now equals the peer's: written by this batch,
    /// or already holding the peer's value.
    pub applied: u32,
    /// Tags not applied: unparseable identities, exhausted tag versions, or
    /// every tag of a batch whose execution failed.
    pub skipped: u32,
    pub errors: Vec<String>,
    /// Epoch that published the batch; `None` when nothing changed or the
    /// batch failed.
    pub epoch: Option<u64>,
}

/// Apply one namespace's reconciled tags in a single execution.
///
/// Changed tags publish together in one epoch; a batch whose tags already
/// hold the peer's values publishes nothing. Per-tag conditions are checked
/// with reads before writing, so an unparseable identity or an exhausted tag
/// version skips that tag without affecting the rest. A store failure
/// discards the whole batch: nothing from it is published. Each namespace is
/// its own batch, so one namespace's failure never affects another's.
///
/// Holds the store's single writer for the duration; call on a blocking
/// worker.
pub fn apply_namespace_batch<S: ExecutionStore + ?Sized>(
    store: &S,
    ns_ref: &NamespaceRef,
    ns_name: &str,
    tags: &[TagEntryWire],
    clock: &dyn Clock,
) -> NamespaceBatchOutcome {
    let mut outcome = NamespaceBatchOutcome::default();
    let mut parsed = Vec::with_capacity(tags.len());
    for tag in tags {
        match Kappa::parse(&tag.kappa) {
            Ok(kappa) => parsed.push((tag.name.as_str(), kappa)),
            Err(e) => {
                warn!(
                    tag = tag.name.as_str(),
                    error = %e,
                    "unparseable kappa in pull response"
                );
                outcome.skipped += 1;
            }
        }
    }
    if parsed.is_empty() {
        return outcome;
    }
    match write_batch(store, ns_ref, &parsed, clock) {
        Ok(written) => {
            outcome.applied += written.applied;
            for name in written.exhausted {
                warn!(
                    namespace = ns_name,
                    tag = name.as_str(),
                    "tag version exhausted"
                );
                outcome.skipped += 1;
                outcome
                    .errors
                    .push(format!("{ns_name}/{name}: tag version exhausted"));
            }
            outcome.epoch = written.epoch;
        }
        Err(e) => {
            warn!(
                namespace = ns_name,
                error = %e,
                "reconciled namespace batch failed, nothing applied"
            );
            outcome.skipped += saturating_count(parsed.len());
            outcome.errors.push(format!("{ns_name}: {e}"));
        }
    }
    outcome
}

struct Written {
    applied: u32,
    exhausted: Vec<String>,
    epoch: Option<u64>,
}

fn write_batch<S: ExecutionStore + ?Sized>(
    store: &S,
    ns_ref: &NamespaceRef,
    parsed: &[(&str, Kappa)],
    clock: &dyn Clock,
) -> Result<Written, StoreError> {
    let mut written = Written {
        applied: 0,
        exhausted: Vec::new(),
        epoch: None,
    };
    let published = publish_if_changed(store, ns_ref, clock, |execution| {
        let mut changed = false;
        for (name, kappa) in parsed {
            match execution.tag_get_raw(name)? {
                Some(entry) if entry.kappa == *kappa && entry.symref.is_none() => {
                    written.applied += 1;
                }
                // A write would fail and latch the execution; skip only this tag.
                Some(entry) if entry.version == u64::MAX => {
                    written.exhausted.push((*name).to_string());
                }
                Some(_) | None => {
                    execution.tag_put(
                        name,
                        &TagUpdate::Set {
                            kappa: kappa.clone(),
                        },
                    )?;
                    written.applied += 1;
                    changed = true;
                }
            }
        }
        Ok(changed)
    })?;
    written.epoch = published.map(|published| published.epoch_number);
    Ok(written)
}

fn saturating_count(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}
