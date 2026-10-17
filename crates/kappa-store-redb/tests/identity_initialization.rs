use kappa_fixture::FixtureRoot;
use kappa_store::traits::identity::IdentityStore;
use kappa_store_redb::test_support::PersistentSpec;
use kappa_types::Kappa;

#[test]
fn fresh_and_reopened_stores_support_empty_identity_reads() -> Result<(), Box<dyn std::error::Error>>
{
    let spec = PersistentSpec::new()
        .in_root(&FixtureRoot::temporary()?)
        .db_file("registry.redb");
    let anchor = Kappa::sha256(b"identity initialization anchor");
    for _ in 0..2 {
        let store = spec.clone().acquire()?;
        assert!(store.device_binding_list(&anchor)?.is_empty());
        assert!(store.prekey_binding_list(&anchor)?.is_empty());
        assert!(store.locator_get(&anchor)?.is_none());
        assert!(store.revocation_commitment_get(&anchor)?.is_none());
    }
    Ok(())
}
