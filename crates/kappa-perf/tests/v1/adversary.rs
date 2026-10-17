//! A store wrapper that serves an honest store's history with adversarial
//! substitutions, for replay tests that must show each substitution is
//! caught by the replay responsible for detecting it.

use kappa_store::traits::blob::BlobReader;
use kappa_store::{Axis, BlobStore, EpochRoot, EpochStore, Kappa, NamespaceRef, StoreError};

/// Serves an honest store's history with adversarial substitutions.
pub struct Adversary<'a, S> {
    pub inner: &'a S,
    /// `epoch_get` of the first identity returns the second root.
    pub substitute: Option<(Kappa, EpochRoot)>,
    /// When nonempty, the whole numbered history and head: epoch `n` is
    /// `chain[n - 1]`. Ledgers and records still come from `inner`.
    pub chain: Vec<EpochRoot>,
    /// `blob_get` returns these bytes with the first byte flipped.
    pub tampered_blob: Option<Kappa>,
    /// `epoch_get_by_number` answers this number with that identity.
    pub renumbered: Option<(u64, Kappa)>,
}

impl<'a, S> Adversary<'a, S> {
    pub const fn honest(inner: &'a S) -> Self {
        Self {
            inner,
            substitute: None,
            chain: Vec::new(),
            tampered_blob: None,
            renumbered: None,
        }
    }
}

impl<S: EpochStore> EpochStore for Adversary<'_, S> {
    fn epoch_state(&self, ns: &NamespaceRef) -> Result<([u8; 32], u64), StoreError> {
        self.inner.epoch_state(ns)
    }

    fn epoch_current(&self, ns: &NamespaceRef) -> Result<(u64, Kappa), StoreError> {
        self.chain.last().map_or_else(
            || self.inner.epoch_current(ns),
            |head| Ok((head.epoch_number(), head.kappa().clone())),
        )
    }

    fn epoch_get(&self, kappa: &Kappa) -> Result<EpochRoot, StoreError> {
        if let Some(root) = self.chain.iter().find(|root| root.kappa() == kappa) {
            return Ok(root.clone());
        }
        match &self.substitute {
            Some((served_for, root)) if served_for == kappa => Ok(root.clone()),
            _ => self.inner.epoch_get(kappa),
        }
    }

    fn epoch_get_by_number(
        &self,
        ns: &NamespaceRef,
        epoch_number: u64,
    ) -> Result<Kappa, StoreError> {
        if !self.chain.is_empty() {
            return usize::try_from(epoch_number)
                .ok()
                .and_then(|number| number.checked_sub(1))
                .and_then(|index| self.chain.get(index))
                .map(|root| root.kappa().clone())
                .ok_or_else(|| StoreError::NotFound(format!("epoch {epoch_number}")));
        }
        match &self.renumbered {
            Some((number, kappa)) if *number == epoch_number => Ok(kappa.clone()),
            _ => self.inner.epoch_get_by_number(ns, epoch_number),
        }
    }
}

impl<S: BlobStore> BlobStore for Adversary<'_, S> {
    fn blob_get(&self, kappa: &Kappa) -> Result<Vec<u8>, StoreError> {
        let mut bytes = self.inner.blob_get(kappa)?;
        if self.tampered_blob.as_ref() == Some(kappa) {
            let first = bytes
                .first_mut()
                .ok_or_else(|| StoreError::Internal("empty tamper target".into()))?;
            *first ^= 0x01;
        }
        Ok(bytes)
    }

    fn blob_get_range(
        &self,
        kappa: &Kappa,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        self.inner.blob_get_range(kappa, offset, length)
    }

    fn blob_open(&self, kappa: &Kappa) -> Result<Box<dyn BlobReader>, StoreError> {
        self.inner.blob_open(kappa)
    }

    fn blob_exists(&self, kappa: &Kappa) -> Result<bool, StoreError> {
        self.inner.blob_exists(kappa)
    }

    fn blob_get_in(&self, ns: &NamespaceRef, kappa: &Kappa) -> Result<Vec<u8>, StoreError> {
        let mut bytes = self.inner.blob_get_in(ns, kappa)?;
        if self.tampered_blob.as_ref() == Some(kappa) {
            let first = bytes
                .first_mut()
                .ok_or_else(|| StoreError::Internal("empty tamper target".into()))?;
            *first ^= 0x01;
        }
        Ok(bytes)
    }

    fn blob_open_in(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
    ) -> Result<Box<dyn BlobReader>, StoreError> {
        self.inner.blob_open_in(ns, kappa)
    }

    fn blob_exists_in(&self, ns: &NamespaceRef, kappa: &Kappa) -> Result<bool, StoreError> {
        self.inner.blob_exists_in(ns, kappa)
    }

    fn blob_size_in(&self, ns: &NamespaceRef, kappa: &Kappa) -> Result<u64, StoreError> {
        self.inner.blob_size_in(ns, kappa)
    }

    fn blob_get_range_in(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        self.inner.blob_get_range_in(ns, kappa, offset, length)
    }

    fn blob_meta_get_in(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
        key: &str,
    ) -> Result<Vec<u8>, StoreError> {
        self.inner.blob_meta_get_in(ns, kappa, key)
    }

    fn blob_owners(&self, kappa: &Kappa) -> Result<Vec<NamespaceRef>, StoreError> {
        self.inner.blob_owners(kappa)
    }

    fn blob_size(&self, kappa: &Kappa) -> Result<u64, StoreError> {
        self.inner.blob_size(kappa)
    }

    fn blob_list(
        &self,
        prefix: Option<&[u8]>,
        page: &kappa_store::PageRequest,
    ) -> Result<kappa_store::Page<Kappa>, StoreError> {
        self.inner.blob_list(prefix, page)
    }

    fn blob_components(&self, kappa: &Kappa) -> Result<Vec<Kappa>, StoreError> {
        self.inner.blob_components(kappa)
    }

    fn blob_meta_get(&self, kappa: &Kappa, key: &str) -> Result<Vec<u8>, StoreError> {
        self.inner.blob_meta_get(kappa, key)
    }

    fn blob_get_compressed(&self, kappa: &Kappa) -> Result<(Vec<u8>, String), StoreError> {
        self.inner.blob_get_compressed(kappa)
    }

    fn blob_get_decompressed(&self, kappa: &Kappa) -> Result<Vec<u8>, StoreError> {
        self.inner.blob_get_decompressed(kappa)
    }

    fn mandatory_axes(&self) -> Vec<Axis> {
        self.inner.mandatory_axes()
    }
}
