//! Fixtures over staged resources: open, stage, prepare and complete
//! through published executions, and the compositions a namespace's
//! current epoch recorded.

use kappa_store::canonical::from_canonical;
use kappa_store::resource;
use kappa_store::{Axis, ClockMs, Kappa, NamespaceRef, ResourceKind, StoreError};

use super::{bounds, computed, publish, Staging};

pub fn asserter() -> Kappa {
    Kappa::sha256(b"staging tests")
}

/// Open a resource of `kind` bound to the context `"context"`, in one
/// published execution.
pub fn open(
    store: &(impl Staging + ?Sized),
    ns: &NamespaceRef,
    kind: ResourceKind,
    max_bytes: u64,
    now: ClockMs,
) -> Result<String, StoreError> {
    publish(store, ns, now, |e| {
        Ok(resource::open(
            e,
            &asserter(),
            kind,
            max_bytes,
            now.add_physical_ms(60_000),
            Some(b"context".to_vec()),
        )?
        .id())
    })
}

/// Stage `bytes` at `position` in one published execution; the head's
/// total after.
pub fn stage(
    store: &(impl Staging + ?Sized),
    ns: &NamespaceRef,
    id: &str,
    bytes: &[u8],
    position: u64,
    receipt: Option<Vec<u8>>,
    now: ClockMs,
) -> Result<u64, StoreError> {
    let prepared = computed(store, bytes)?;
    publish(store, ns, now, |e| {
        let (head, _) = resource::stage(e, &asserter(), id, prepared, position, receipt)?;
        Ok(head.total_bytes)
    })
}

/// Prepare and complete `id` for `request` under `primary`: freeze, hash
/// outside the writer, complete. Returns the assembled identity and its
/// aliases.
pub fn complete(
    store: &(impl Staging + ?Sized),
    ns: &NamespaceRef,
    id: &str,
    request: &Kappa,
    selected: &[u64],
    primary: Axis,
    now: ClockMs,
) -> Result<(Kappa, Vec<Kappa>), StoreError> {
    let generation = publish(store, ns, now, |e| {
        let prepared = resource::prepare(e, &asserter(), id, request, selected)?;
        assert!(prepared.frozen, "a first preparation freezes");
        Ok(prepared.generation)
    })?;
    let evidence =
        resource::prepare_composition(store, ns, id, &generation, primary, bounds().deadline)?;
    publish(store, ns, now, |e| {
        let completed =
            resource::complete(e, &asserter(), id, &evidence, Some(b"receipt".to_vec()))?;
        assert!(!completed.replayed);
        Ok((
            completed.installed.kappa,
            completed.installed.additional_kappas,
        ))
    })
}

/// The compositions the namespace's current epoch recorded in its ledger.
pub fn recorded_compositions(
    store: &(impl Staging + ?Sized),
    ns: &NamespaceRef,
) -> Result<Vec<kappa_types::content::ContentComposition>, Box<dyn std::error::Error>> {
    let (_, current) = store.epoch_current(ns)?;
    let root = store.epoch_get(&current)?;
    let ledger: Vec<kappa_store::EpochMutation> =
        from_canonical(&store.blob_get(root.ledger_root())?)?;
    let mut compositions = Vec::new();
    for mutation in ledger
        .iter()
        .filter(|mutation| mutation.op == kappa_store::MutationOp::ContentCompose)
    {
        assert_eq!(mutation.context, None);
        compositions.push(from_canonical(&store.blob_get(&mutation.kappa)?)?);
    }
    Ok(compositions)
}
