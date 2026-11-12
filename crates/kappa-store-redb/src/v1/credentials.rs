//! SigV4 reads the same governed credentials as every other consumer.
//! Creation and rotation are shared `kappa_store::identity_ops` operations;
//! deactivation is `ExecutionWrites::credential_delete`.

impl kappa_crypto::sigv4::CredentialLookup for crate::PersistentStore {
    fn lookup_credential(
        &self,
        access_key_id: &str,
        now: kappa_store::ClockMs,
    ) -> Result<kappa_crypto::sigv4::CredentialResult, kappa_store::StoreError> {
        kappa_store::identity_ops::access_key_lookup(self, access_key_id, now)
    }
}
