//! The `BlobStore` contract over namespace views.
//!
//! A namespace-bound read (`_in`) reads the named namespace's published
//! view and nothing else. A read that names no namespace finds candidate
//! namespaces through the content projection (`locate`) and serves the
//! first, in namespace order, whose published view admits the identity;
//! one healthy holder satisfies it. Absence is reported only when every
//! candidate was examined; a lookup that exhausts its examination bound
//! first reports the identity unavailable.

use std::io::Read;
use std::sync::Arc;

use kappa_store::traits::blob::{BlobReader, BlobStore};
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::page::{Page, PageRequest};
use kappa_types::verified::VerifiedContent;
use kappa_types::work::Dimension;

use super::InMemoryStore;
use super::blob_read;
use super::locate::{Holders, incomplete};
use super::view::{NamespaceId, NamespaceView, Representation};

impl InMemoryStore {
    /// The published views admitting `kappa`, in namespace order; `visit`
    /// returns true to stop. Returns whether the walk stopped or examined
    /// every candidate.
    pub(crate) fn holders(
        &self,
        kappa: &Kappa,
        mut visit: impl FnMut(NamespaceId, &Arc<NamespaceView>) -> bool,
    ) -> bool {
        self.located(&self.projections.content, kappa, |namespace, view| {
            view.holds(kappa) && visit(namespace, view)
        })
    }

    /// The first published view admitting `kappa`.
    fn holder(&self, kappa: &Kappa) -> Result<Arc<NamespaceView>, StoreError> {
        let mut found = None;
        let complete = self.holders(kappa, |_, view| {
            found = Some(Arc::clone(view));
            true
        });
        match found {
            Some(view) => Ok(view),
            None if complete => Err(StoreError::NotFound(kappa.to_string())),
            None => Err(incomplete(kappa)),
        }
    }

    /// The published view of `ns`, which must admit `kappa`.
    fn admitting(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
    ) -> Result<Arc<NamespaceView>, StoreError> {
        let view = self.view(ns.id());
        if view.holds(kappa) {
            Ok(view)
        } else {
            Err(StoreError::NotFound(format!("{kappa} in namespace {ns}")))
        }
    }
}

impl BlobStore for InMemoryStore {
    fn blob_get(&self, kappa: &Kappa) -> Result<Vec<u8>, StoreError> {
        let view = self.holder(kappa)?;
        Ok(
            blob_read::verified(&view, kappa, None, &mut self.read_meter())?
                .into_parts()
                .1,
        )
    }

    fn blob_get_range(
        &self,
        kappa: &Kappa,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        let view = self.holder(kappa)?;
        blob_read::range(&view, kappa, offset, length, self.read_meter())
    }

    /// A stream over `kappa` on one read operation's meter, which resolves
    /// the representation and then moves into the reader.
    fn blob_open(&self, kappa: &Kappa) -> Result<Box<dyn BlobReader>, StoreError> {
        let view = self.holder(kappa)?;
        blob_read::open(&view, kappa, self.read_meter())
    }

    fn blob_exists(&self, kappa: &Kappa) -> Result<bool, StoreError> {
        match self.holder(kappa) {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn blob_size(&self, kappa: &Kappa) -> Result<u64, StoreError> {
        let view = self.holder(kappa)?;
        blob_read::size(&view, kappa)
    }

    fn blob_list(
        &self,
        prefix: Option<&[u8]>,
        page: &PageRequest,
    ) -> Result<Page<Kappa>, StoreError> {
        let start = page.after.as_deref().map(Kappa::parse).transpose()?;
        self.listing(
            &self.projections.content,
            start.as_ref(),
            page.limit,
            Holders::First,
            |kappa, view, out| {
                if prefix.is_none_or(|prefix| kappa.key_bytes().starts_with(prefix))
                    && view.holds(kappa)
                {
                    out.push(kappa.clone());
                }
            },
            ToString::to_string,
        )
    }

    fn blob_components(&self, kappa: &Kappa) -> Result<Vec<Kappa>, StoreError> {
        let view = self.holder(kappa)?;
        Ok(
            match view.held(kappa).map(|admission| &admission.representation) {
                Some(Representation::Alias(holder)) => vec![holder.clone()],
                Some(Representation::Composite(components)) => components
                    .iter()
                    .map(|(component, _)| component.clone())
                    .collect(),
                Some(
                    Representation::File(_)
                    | Representation::Compressed { .. }
                    | Representation::Inline { .. },
                )
                | None => Vec::new(),
            },
        )
    }

    fn blob_meta_get(&self, kappa: &Kappa, key: &str) -> Result<Vec<u8>, StoreError> {
        let mut found = None;
        let complete = self.holders(kappa, |_, view| {
            found = view
                .blob_meta
                .get(&(kappa.clone(), key.to_owned()))
                .cloned();
            found.is_some()
        });
        match found {
            Some(value) => Ok(value),
            None if complete => Err(StoreError::NotFound(format!("meta {kappa}:{key}"))),
            None => Err(incomplete(&format_args!("meta {kappa}:{key}"))),
        }
    }

    /// The compressed bytes and algorithm of `kappa` on one read
    /// operation's meter: the handle, the stored bytes read with one probe
    /// byte, their buffer and their hash charged before the file is opened.
    fn blob_get_compressed(&self, kappa: &Kappa) -> Result<(Vec<u8>, String), StoreError> {
        let mut meter = self.read_meter();
        let view = self.holder(kappa)?;
        let (storage, algorithm) =
            blob_read::compressed(&view, kappa, &mut meter)?.ok_or_else(|| {
                StoreError::NotFound(format!("{kappa} has no compressed representation"))
            })?;
        let stored = storage.bytes();
        let capacity = usize::try_from(stored).map_err(|_| {
            StoreError::CapacityExceeded(format!("compressed {kappa} exceeds the address space"))
        })?;
        meter.charge_all(&[
            (Dimension::Handles, 1),
            (Dimension::BytesRead, stored.saturating_add(1)),
            (Dimension::BytesAllocated, stored),
            (Dimension::BytesHashed, stored),
        ])?;
        let mut compressed = Vec::with_capacity(capacity);
        std::fs::File::open(storage.path())
            .map_err(|error| StoreError::Internal(format!("compressed {kappa}: {error}")))?
            .take(stored.saturating_add(1))
            .read_to_end(&mut compressed)?;
        if compressed.len() as u64 != stored {
            return Err(StoreError::Internal(format!(
                "compressed allocation of {kappa} holds {} bytes where {stored} were stored",
                compressed.len()
            )));
        }
        // The allocation is identified by the compressed bytes themselves.
        let verified = VerifiedContent::verify_owned(storage.storage(), compressed)
            .map_err(|error| StoreError::Internal(format!("compressed {kappa}: {error}")))?;
        Ok((verified.into_parts().1, algorithm))
    }

    /// The decoded bytes of compressed `kappa`, on one read operation's
    /// meter that resolves the representation, decodes it and hashes it.
    fn blob_get_decompressed(&self, kappa: &Kappa) -> Result<Vec<u8>, StoreError> {
        let mut meter = self.read_meter();
        let view = self.holder(kappa)?;
        if blob_read::compressed(&view, kappa, &mut meter)?.is_none() {
            return Err(StoreError::NotFound(format!(
                "{kappa} has no compressed representation"
            )));
        }
        Ok(blob_read::verified(&view, kappa, None, &mut meter)?
            .into_parts()
            .1)
    }

    fn blob_get_in(&self, ns: &NamespaceRef, kappa: &Kappa) -> Result<Vec<u8>, StoreError> {
        let view = self.admitting(ns, kappa)?;
        Ok(
            blob_read::verified(&view, kappa, None, &mut self.read_meter())?
                .into_parts()
                .1,
        )
    }

    fn blob_open_in(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
    ) -> Result<Box<dyn BlobReader>, StoreError> {
        let view = self.admitting(ns, kappa)?;
        blob_read::open(&view, kappa, self.read_meter())
    }

    fn blob_exists_in(&self, ns: &NamespaceRef, kappa: &Kappa) -> Result<bool, StoreError> {
        Ok(self.view(ns.id()).holds(kappa))
    }

    fn blob_size_in(&self, ns: &NamespaceRef, kappa: &Kappa) -> Result<u64, StoreError> {
        let view = self.admitting(ns, kappa)?;
        blob_read::size(&view, kappa)
    }

    fn blob_get_range_in(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        let view = self.admitting(ns, kappa)?;
        blob_read::range(&view, kappa, offset, length, self.read_meter())
    }

    fn blob_meta_get_in(
        &self,
        ns: &NamespaceRef,
        kappa: &Kappa,
        key: &str,
    ) -> Result<Vec<u8>, StoreError> {
        self.admitting(ns, kappa)?
            .blob_meta
            .get(&(kappa.clone(), key.to_owned()))
            .cloned()
            .ok_or_else(|| StoreError::NotFound(format!("meta {kappa}:{key} in namespace {ns}")))
    }

    fn blob_owners(&self, kappa: &Kappa) -> Result<Vec<NamespaceRef>, StoreError> {
        let mut owners = Vec::new();
        let complete = self.holders(kappa, |namespace, view| {
            owners.push(Self::reference(&namespace, view));
            false
        });
        if complete {
            Ok(owners)
        } else {
            Err(incomplete(&format_args!("owners of {kappa}")))
        }
    }
}
