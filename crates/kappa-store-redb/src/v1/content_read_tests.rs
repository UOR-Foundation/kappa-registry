use std::sync::Arc;
use std::sync::atomic::Ordering;

use kappa_store::StoreError;

/// A view retains its read grant through every clone and releases it with
/// the last; a controller of another store with the same identity is not
/// counted.
#[test]
fn a_retained_view_keeps_its_namespace_active_until_it_drops() -> Result<(), StoreError> {
    let controller = crate::test_support::controller_for_tests()?;
    let before = controller.active.load(Ordering::Acquire);
    let store = crate::test_support::persistent_store()
        .map_err(|error| StoreError::Internal(error.to_string()))?
        .into_store();
    drop(store.namespaces.admit_publish(
        &controller.id,
        &crate::storage::Opening::Create {
            plane: Arc::clone(store.control_planes().local()),
        },
    )?);
    let active = store.namespaces.admit_read(&controller.id)?;
    let own = Arc::clone(active.controller());
    assert!(
        !Arc::ptr_eq(&own, &controller),
        "the stores share a controller"
    );
    let held = own.active.load(Ordering::Acquire);
    let view = store.read_view_retaining(active);
    let copy = view.clone();
    assert_eq!(own.active.load(Ordering::Acquire), held);
    drop(view);
    assert_eq!(
        own.active.load(Ordering::Acquire),
        held,
        "a clone still retains the grant"
    );
    drop(copy);
    assert_eq!(own.active.load(Ordering::Acquire), held - 1);
    assert_eq!(controller.active.load(Ordering::Acquire), before);
    Ok(())
}
