//! `BlobStore` over committed representations: reads only.
//!
//! Every write goes through an execution ([`crate::epoch_execution`]) after
//! preparation ([`crate::content_prepare`]); every read selects a committed
//! representation ([`crate::content_read`]) in the database of a namespace
//! that admitted it. A read that names no namespace runs through
//! `store_access::with_holder`: candidates come from keyed lookups (the
//! completed catalog projection, `projection::Family::Catalog`, and the
//! unsettled identity index), so content is found
//! from the commit that admitted it, not from its settlement, and the row
//! the read uses in the namespace database is the evidence.

use kappa_cursor::FallibleCursor;
use redb::ReadableDatabase;

use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::blob::{BlobReader, BlobStore};

use crate::PersistentStore;
use crate::content_read::ReadView;
use crate::epoch_blob::blob_meta_from_table;
use crate::projection::Family;
use crate::projection_cursor::ProjectionKeyCursor;
use crate::storage::NamespaceStorage;
use crate::tables::{BLOB_INDEX, BLOB_META};

/// The complete logical bytes of `kappa` through `view`, verified against
/// the identity. A compressed representation is served by
/// `blob_get_compressed`; here it is refused rather than returned as
/// bytes the identity does not name.
fn full_read(view: &ReadView, kappa: &Kappa) -> Result<Vec<u8>, StoreError> {
    let txn = view.db.begin_read().map_err(crate::error::redb)?;
    let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
    let record = view.record_from_table(&index, kappa)?;
    if record.compression().is_some() {
        return Err(StoreError::Rejected(format!(
            "blob {kappa} is stored compressed; read it through blob_get_decompressed"
        )));
    }
    let bytes = view.read_stored(&index, kappa, &record, None)?;
    kappa_store::VerifiedContent::verify(kappa, &bytes)?;
    Ok(bytes)
}

pub(super) fn meta_key(kappa: &Kappa, key: &str) -> Vec<u8> {
    let kb = kappa.key_bytes();
    let mut out = Vec::with_capacity(kb.len() + 1 + key.len());
    out.extend_from_slice(&kb);
    out.push(b':');
    out.extend_from_slice(key.as_bytes());
    out
}

impl BlobStore for PersistentStore {
    /// Every identity a completed epoch of any namespace admitted, from the
    /// settled catalog.
    fn blob_cursor(
        &self,
    ) -> Result<Box<dyn kappa_cursor::FallibleCursor<Error = StoreError> + '_>, StoreError> {
        Ok(Box::new(ProjectionKeyCursor::new(
            self.projection()?,
            Family::Catalog,
        )?))
    }

    fn blob_get(&self, kappa: &Kappa) -> Result<Vec<u8>, StoreError> {
        self.with_holder(kappa, |view| full_read(view, kappa))
    }

    fn blob_get_range(
        &self,
        kappa: &Kappa,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        self.with_holder(kappa, |view| view.range(kappa, offset, length))
    }

    fn blob_open(&self, kappa: &Kappa) -> Result<Box<dyn BlobReader>, StoreError> {
        self.with_holder(kappa, |view| view.open(kappa))
    }

    fn blob_exists(&self, kappa: &Kappa) -> Result<bool, StoreError> {
        match self.with_holder(kappa, |view| view.record(kappa).map(drop)) {
            Ok(()) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn blob_size(&self, kappa: &Kappa) -> Result<u64, StoreError> {
        Ok(self.blob_record(kappa)?.total_size())
    }

    fn blob_list(
        &self,
        prefix: Option<&[u8]>,
        page: &kappa_types::PageRequest,
    ) -> Result<kappa_types::Page<Kappa>, StoreError> {
        if page.limit == 0 {
            return Ok(kappa_types::Page::empty());
        }
        let after = page
            .after
            .as_deref()
            .map(Kappa::parse)
            .transpose()?
            .map(|key| key.key_bytes());
        let prefix = prefix.unwrap_or_default();
        let mut cursor = ProjectionKeyCursor::new(self.projection()?, Family::Catalog)?;
        let lower = after
            .as_deref()
            .filter(|after| *after >= prefix)
            .unwrap_or(prefix);
        cursor.seek(lower)?;
        if cursor
            .key()?
            .zip(after.as_deref())
            .is_some_and(|(key, after)| key == after)
        {
            cursor.advance()?;
        }
        let mut results = Vec::with_capacity(page.limit.min(1000));
        while let Some(key) = cursor.key()? {
            if !key.starts_with(prefix) {
                break;
            }
            results.push(Kappa::from_key_bytes(key)?);
            if results.len() > page.limit {
                break;
            }
            cursor.advance()?;
        }
        Ok(kappa_types::Page::from_oversized(
            results,
            page.limit,
            ToString::to_string,
        ))
    }

    /// The identities a committed representation is assembled from, by the
    /// one rule the referrer index is built and rebuilt with.
    fn blob_components(&self, kappa: &Kappa) -> Result<Vec<Kappa>, StoreError> {
        Ok(crate::content_install::referenced(
            &self.blob_record(kappa)?,
        ))
    }

    /// Metadata of `kappa` in a namespace whose committed row holds it,
    /// read in the same transaction as that row.
    fn blob_meta_get(&self, kappa: &Kappa, key: &str) -> Result<Vec<u8>, StoreError> {
        self.with_holder(kappa, |view| {
            let txn = view.db.begin_read().map_err(crate::error::redb)?;
            let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
            view.record_from_table(&index, kappa)?;
            let table = txn.open_table(BLOB_META).map_err(crate::error::redb)?;
            blob_meta_from_table(self, &table, kappa, key)
        })
    }

    /// The compressed bytes and algorithm of `kappa`. A namespace holding
    /// it uncompressed holds no compressed representation, so it does not
    /// answer; with no namespace holding one, the read is `NotFound`.
    fn blob_get_compressed(&self, kappa: &Kappa) -> Result<(Vec<u8>, String), StoreError> {
        self.with_holder(kappa, |view| {
            let txn = view.db.begin_read().map_err(crate::error::redb)?;
            let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
            let record = view.record_from_table(&index, kappa)?;
            let (held, record) = view.resolve_alias(&index, kappa, record)?;
            let algorithm = record
                .compression()
                .ok_or_else(|| StoreError::NotFound(format!("blob {kappa} is not compressed")))?
                .to_string();
            let data = view.read_stored(&index, &held, &record, None)?;
            Ok((data, algorithm))
        })
    }

    fn blob_get_decompressed(&self, kappa: &Kappa) -> Result<Vec<u8>, StoreError> {
        let (compressed, algorithm) = self.blob_get_compressed(kappa)?;
        crate::decompress::decompress(&compressed, &algorithm)
    }

    /// Reads bound to the namespace `ns` admitted the representation in;
    /// no catalog lookup, and a representation another namespace holds is
    /// absent here.
    fn blob_get_in(&self, ns: &NamespaceRef, kappa: &Kappa) -> Result<Vec<u8>, StoreError> {
        full_read(&self.read_view_ns(ns)?, kappa)
    }

    fn blob_open_in(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
    ) -> Result<Box<dyn BlobReader>, StoreError> {
        self.read_view_ns(ns)?.open(kappa)
    }

    fn blob_exists_in(&self, ns: &NamespaceRef, kappa: &Kappa) -> Result<bool, StoreError> {
        match self.read_view_ns(ns)?.record(kappa) {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn blob_size_in(&self, ns: &NamespaceRef, kappa: &Kappa) -> Result<u64, StoreError> {
        Ok(self.read_view_ns(ns)?.record(kappa)?.total_size())
    }

    fn blob_get_range_in(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        self.read_view_ns(ns)?.range(kappa, offset, length)
    }

    fn blob_meta_get_in(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
        key: &str,
    ) -> Result<Vec<u8>, StoreError> {
        let view = self.read_view_ns(ns)?;
        let txn = view.db.begin_read().map_err(crate::error::redb)?;
        let table = txn.open_table(BLOB_META).map_err(crate::error::redb)?;
        blob_meta_from_table(self, &table, kappa, key)
    }

    fn blob_owners(&self, kappa: &Kappa) -> Result<Vec<NamespaceRef>, StoreError> {
        Ok(self
            .holders(kappa)?
            .into_iter()
            .map(NamespaceStorage::namespace_ref)
            .collect())
    }
}
