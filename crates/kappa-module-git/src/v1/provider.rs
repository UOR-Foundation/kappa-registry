use std::io::Read;
use std::sync::Arc;

use gix_error::{ExnResult, ResultExt};
use gix_hash::oid;
use gix_object::Data;

use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::blob::BlobStore;

use crate::envelope;

/// Provides git objects of one repository namespace from a BlobStore to
/// gitoxide's pack generation and traversal algorithms.
pub struct KappaStoreObjectProvider {
    store: Arc<dyn BlobStore>,
    namespace: NamespaceRef,
    hash_kind: gix_hash::Kind,
}

impl KappaStoreObjectProvider {
    pub fn new(
        store: Arc<dyn BlobStore>,
        namespace: NamespaceRef,
        hash_kind: gix_hash::Kind,
    ) -> Self {
        Self {
            store,
            namespace,
            hash_kind,
        }
    }

    pub fn hash_len(&self) -> usize {
        self.hash_kind.len_in_bytes()
    }

    pub fn hash_prefix(&self) -> &'static str {
        envelope::hash_prefix(self.hash_kind)
    }

    pub fn kind(&self) -> gix_hash::Kind {
        self.hash_kind
    }

    fn oid_to_kappa(&self, id: &oid) -> Result<Kappa, envelope::EnvelopeError> {
        let kappa_str = envelope::oid_to_kappa(&id.to_owned())?;
        Kappa::parse(&kappa_str).map_err(|e| envelope::EnvelopeError::InvalidOid(e.to_string()))
    }
}

impl gix_pack::Find for KappaStoreObjectProvider {
    fn contains(&self, id: &oid) -> bool {
        let kappa = match self.oid_to_kappa(id) {
            Ok(k) => k,
            Err(_) => return false,
        };
        self.store
            .blob_exists_in(&self.namespace, &kappa)
            .unwrap_or(false)
    }

    /// The object stored under `id`'s kappa, decoded from its git envelope
    /// into `buffer`. An absent object is `Ok(None)`. A store failure keeps
    /// its `StoreError` as the cause; an envelope that is malformed, or whose
    /// declared size disagrees with its content, is corruption.
    fn try_find_cached<'a>(
        &self,
        id: &oid,
        buffer: &'a mut Vec<u8>,
        _pack_cache: &mut dyn gix_pack::cache::DecodeEntry,
    ) -> ExnResult<Option<(Data<'a>, Option<gix_pack::data::entry::Location>)>> {
        let kappa = self.oid_to_kappa(id).or_raise_erased(|| {
            gix_error::validation(format!("object id {id} has no kappa address"))
        })?;

        let mut reader = match self.store.blob_open_in(&self.namespace, &kappa) {
            Ok(reader) => reader,
            Err(StoreError::NotFound(_)) => return Ok(None),
            Err(error) => {
                return Err(error).or_raise_erased(|| {
                    gix_error::Message::new(format!("object {id} could not be opened at {kappa}"))
                });
            }
        };

        buffer.clear();
        reader.read_to_end(buffer).or_raise_erased(|| {
            gix_error::Message::new(format!("object {id} could not be read from {kappa}"))
        })?;

        let (kind, content_len) = envelope::unwrap(buffer)
            .map(|(kind, content)| (kind, content.len()))
            .or_raise_erased(|| {
                gix_error::corruption(format!("object {id} at {kappa} is not a git envelope"))
            })?;
        let content_start = buffer.len() - content_len;
        buffer.copy_within(content_start.., 0);
        buffer.truncate(content_len);

        Ok(Some((Data::new(&buffer[..], kind, self.hash_kind), None)))
    }

    fn location_by_oid(
        &self,
        _id: &oid,
        _buf: &mut Vec<u8>,
    ) -> Option<gix_pack::data::entry::Location> {
        None
    }

    fn pack_offsets_and_oid(
        &self,
        _pack_id: u32,
    ) -> Option<Vec<(gix_pack::data::Offset, gix_hash::ObjectId)>> {
        None
    }

    fn entry_by_location(
        &self,
        _location: &gix_pack::data::entry::Location,
    ) -> Option<gix_pack::find::Entry> {
        None
    }
}
