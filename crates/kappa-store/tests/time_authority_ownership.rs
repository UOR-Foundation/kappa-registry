use kappa_store::time::TimeAuthorityLease;
use std::sync::{Arc, atomic::AtomicBool};

#[test]
fn ownership_is_exclusive_and_released_with_lifetime() -> Result<(), kappa_types::StoreError> {
    let gate = Arc::new(AtomicBool::new(false));
    let lease = TimeAuthorityLease::acquire(gate.clone())?;
    assert!(TimeAuthorityLease::acquire(gate.clone()).is_err());
    drop(lease);
    let recovered_owner = TimeAuthorityLease::acquire(gate.clone())?;
    assert!(TimeAuthorityLease::acquire(gate).is_err());
    drop(recovered_owner);
    Ok(())
}
