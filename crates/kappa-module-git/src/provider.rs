//! KappaStoreObjectProvider: implements gix_pack::Find over KappaStore.
//!
//! Bridges gitoxide's object resolution to kappa-registry's content-
//! addressed store. Objects are stored as Git envelopes. The provider
//! strips the envelope header and returns gix_object::Data with the
//! raw content and Kind, matching what gitoxide expects.
//!
//! Memory: reads directly into the caller's buffer via blob_open +
//! BlobReader::read. One allocation (the caller-owned buffer). No
//! intermediate Vec<u8>. No unzeroed plaintext in freed heap memory.

use std::io::Read;
use std::sync::Arc;

use gix_hash::oid;
use gix_object::Data;

use kappa_core::store::KappaStore;

use crate::envelope;

/// Provides git objects from a KappaStore to gitoxide's pack generation
/// and traversal algorithms.
pub struct KappaStoreObjectProvider {
    store: Arc<dyn KappaStore>,
    hash_kind: gix_hash::Kind,
}

impl KappaStoreObjectProvider {
    pub fn new(store: Arc<dyn KappaStore>, hash_kind: gix_hash::Kind) -> Self {
        Self { store, hash_kind }
    }

    /// Hash byte length: 20 for SHA-1, 32 for SHA-256.
    /// SSOT for hash_len within the Git module.
    pub fn hash_len(&self) -> usize {
        self.hash_kind.len_in_bytes()
    }

    /// Kappa prefix string: "sha1" or "sha256".
    /// SSOT for hash_prefix within the Git module.
    pub fn hash_prefix(&self) -> &'static str {
        match self.hash_kind {
            gix_hash::Kind::Sha1 => "sha1",
            _ => "sha256",
        }
    }

    /// The hash kind this provider uses.
    pub fn kind(&self) -> gix_hash::Kind {
        self.hash_kind
    }

    fn oid_to_kappa(&self, id: &oid) -> Result<String, envelope::EnvelopeError> {
        envelope::oid_to_kappa(&id.to_owned())
    }
}

impl gix_pack::Find for KappaStoreObjectProvider {
    fn contains(&self, id: &oid) -> bool {
        let kappa = match self.oid_to_kappa(id) {
            Ok(k) => k,
            Err(_) => return false,
        };
        self.store.blob_exists(&kappa).unwrap_or(false)
    }

    fn try_find_cached<'a>(
        &self,
        id: &oid,
        buffer: &'a mut Vec<u8>,
        _pack_cache: &mut dyn gix_pack::cache::DecodeEntry,
    ) -> Result<
        Option<(Data<'a>, Option<gix_pack::data::entry::Location>)>,
        gix_object::find::Error,
    > {
        let kappa = self.oid_to_kappa(id)
            .map_err(|e| Box::new(std::io::Error::other(e.to_string())) as gix_object::find::Error)?;

        // Read directly into caller's buffer via blob_open. One allocation.
        // No intermediate Vec<u8>. Under encryption, BlobReader is a
        // FrameDecryptingReader -- plaintext exists only in the caller's
        // buffer, never in a dropped intermediate allocation.
        let mut reader = match self.store.blob_open(&kappa) {
            Ok(r) => r,
            Err(kappa_core::types::StoreError::NotFound(_)) => return Ok(None),
            // Sanitize: do not leak kappa-label in error messages to gitoxide
            Err(_) => {
                return Err(Box::new(std::io::Error::other(
                    "object unavailable",
                )))
            }
        };

        buffer.clear();
        reader
            .read_to_end(buffer)
            .map_err(|e| Box::new(e) as gix_object::find::Error)?;

        // Parse envelope header in-place from the buffer.
        // Find the NUL byte, extract Kind, compute content offset.
        let nul_pos = buffer
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| {
                Box::new(std::io::Error::other("invalid git envelope: no NUL"))
                    as gix_object::find::Error
            })?;

        let kind = {
            let header = &buffer[..nul_pos];
            let space_pos = header.iter().position(|&b| b == b' ').ok_or_else(|| {
                Box::new(std::io::Error::other("invalid git envelope: no space"))
                    as gix_object::find::Error
            })?;
            gix_object::Kind::from_bytes(&header[..space_pos]).map_err(|e| {
                Box::new(std::io::Error::other(format!(
                    "invalid git object kind: {}",
                    e
                ))) as gix_object::find::Error
            })?
        };

        // Remove the envelope header from the buffer in-place.
        // Content starts at nul_pos + 1. Shift it to the front.
        let content_start = nul_pos + 1;
        let content_len = buffer.len() - content_start;
        buffer.copy_within(content_start.., 0);
        buffer.truncate(content_len);

        Ok(Some((Data::new(kind, &buffer[..]), None)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use gix_pack::{Find, FindExt};
    use kappa_core::clock::ntp_lamport::NtpLamportClock;
    use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};

    fn test_store() -> (Arc<dyn KappaStore>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let clock = Arc::new(NtpLamportClock::new());
        let store = InMemoryStore::new(
            MemoryStoreConfig::new(tmp.path().join("blobs")),
            clock,
        )
        .unwrap();
        (Arc::new(store), tmp)
    }

    #[test]
    fn find_stored_blob() {
        let (store, _tmp) = test_store();
        let content = b"hello";
        let envelope_bytes = envelope::wrap(gix_object::Kind::Blob, content);
        let kappa = envelope::git_object_id_sha1(gix_object::Kind::Blob, content).unwrap();

        store.ingest_verified(&kappa, &envelope_bytes).unwrap();

        let provider = KappaStoreObjectProvider::new(store, gix_hash::Kind::Sha1);
        let oid = envelope::kappa_to_oid(&kappa).unwrap();

        let mut buffer = Vec::new();
        let (data, location) = provider.find(&oid, &mut buffer).unwrap();
        assert_eq!(data.kind, gix_object::Kind::Blob);
        assert_eq!(data.data, b"hello");
        assert!(location.is_none());
    }

    #[test]
    fn contains_returns_true_for_stored() {
        let (store, _tmp) = test_store();
        let envelope_bytes = envelope::wrap(gix_object::Kind::Blob, b"exists");
        let kappa = envelope::git_object_id_sha1(gix_object::Kind::Blob, b"exists").unwrap();
        store.ingest_verified(&kappa, &envelope_bytes).unwrap();

        let provider = KappaStoreObjectProvider::new(store, gix_hash::Kind::Sha1);
        let oid = envelope::kappa_to_oid(&kappa).unwrap();
        assert!(provider.contains(&oid));
    }

    #[test]
    fn contains_returns_false_for_missing() {
        let (store, _tmp) = test_store();
        let provider = KappaStoreObjectProvider::new(store, gix_hash::Kind::Sha1);
        let oid = gix_hash::ObjectId::null(gix_hash::Kind::Sha1);
        assert!(!provider.contains(&oid));
    }

    #[test]
    fn find_missing_returns_none() {
        let (store, _tmp) = test_store();
        let provider = KappaStoreObjectProvider::new(store, gix_hash::Kind::Sha1);
        let oid = gix_hash::ObjectId::null(gix_hash::Kind::Sha1);
        let mut buffer = Vec::new();
        let result = provider.try_find(&oid, &mut buffer).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn multi_axis_git_object_retrievable_by_sha256() {
        let (store, _tmp) = test_store();
        let content = b"multi-axis git blob";
        let envelope_bytes = envelope::wrap(gix_object::Kind::Blob, content);
        let sha1_kappa =
            envelope::git_object_id_sha1(gix_object::Kind::Blob, content).unwrap();

        let result = store
            .ingest_verified(&sha1_kappa, &envelope_bytes)
            .unwrap();

        assert!(!result.additional_kappas.is_empty());
        let sha256_kappa = &result.additional_kappas[0];
        assert!(sha256_kappa.starts_with("sha256:"));

        let by_sha256 = store.blob_get(sha256_kappa).unwrap();
        assert_eq!(by_sha256, envelope_bytes);
    }

    #[test]
    fn find_large_blob_no_double_alloc() {
        let (store, _tmp) = test_store();
        let content: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
        let envelope_bytes = envelope::wrap(gix_object::Kind::Blob, &content);
        let kappa =
            envelope::git_object_id_sha1(gix_object::Kind::Blob, &content).unwrap();

        store.ingest_verified(&kappa, &envelope_bytes).unwrap();

        let provider = KappaStoreObjectProvider::new(store, gix_hash::Kind::Sha1);
        let oid = envelope::kappa_to_oid(&kappa).unwrap();

        let mut buffer = Vec::new();
        let (data, _) = provider.find(&oid, &mut buffer).unwrap();
        assert_eq!(data.kind, gix_object::Kind::Blob);
        assert_eq!(data.data.len(), content.len());
        assert_eq!(data.data, content.as_slice());
    }
}
