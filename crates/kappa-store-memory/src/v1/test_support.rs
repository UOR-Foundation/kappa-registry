//! The one acquisition path for in-memory stores in tests and benchmarks.
//!
//! [`StoreSpec`] selects the store's authority, scope and blob path.
//! [`StoreSpec::acquire`] builds the store through
//! [`MemoryStoreConfig`] with the scope retained by the store itself: every
//! handle to it, `Arc<InMemoryStore>` or `Arc<dyn KappaStore>`, keeps the
//! scope alive, and [`FixtureRoot::close`] refuses while one remains.

use std::path::{Path, PathBuf};

use kappa_fixture::{FixtureRoot, SetupError};

use super::{InMemoryStore, MemoryStoreConfig};

/// Publication retention a fixture store is given by default.
///
/// A test selects its own through `StoreSpec::retention`. This is a test
/// scenario's capacity, large enough for the publications the fixtures and
/// benchmarks drive, not an operator default.
pub const FIXTURE_PUBLICATION_RETENTION: u64 = 1 << 30;

/// Inputs that select one store.
pub struct StoreSpec {
    authority: Option<kappa_crypto::SigningAuthority>,
    root: Option<FixtureRoot>,
    blob_dir: PathBuf,
    retention: u64,
}

impl Default for StoreSpec {
    fn default() -> Self {
        Self::new()
    }
}

impl StoreSpec {
    /// Fixture authority from seed byte 1, a fresh temporary scope, blobs at
    /// `blobs`, and [`FIXTURE_PUBLICATION_RETENTION`].
    pub fn new() -> Self {
        Self {
            authority: None,
            root: None,
            blob_dir: PathBuf::from("blobs"),
            retention: FIXTURE_PUBLICATION_RETENTION,
        }
    }

    /// Bytes of publication evidence the store may retain.
    #[must_use]
    pub const fn retention(mut self, bytes: u64) -> Self {
        self.retention = bytes;
        self
    }

    /// The retention this specification selects, for reports that record
    /// the configuration they measured.
    pub const fn selected_retention(&self) -> u64 {
        self.retention
    }

    /// Sign epochs with `authority`.
    #[must_use]
    pub fn authority(mut self, authority: kappa_crypto::SigningAuthority) -> Self {
        self.authority = Some(authority);
        self
    }

    /// Place the store in `root`, shared with the caller's other resources.
    #[must_use]
    pub fn in_root(mut self, root: &FixtureRoot) -> Self {
        self.root = Some(root.clone());
        self
    }

    /// Blob directory relative to the scope; validated by
    /// [`FixtureRoot::resolve`].
    #[must_use]
    pub fn blob_dir(mut self, relative: impl Into<PathBuf>) -> Self {
        self.blob_dir = relative.into();
        self
    }

    pub fn acquire(self) -> Result<TestStore, SetupError> {
        let authority = match self.authority {
            Some(authority) => authority,
            None => kappa_crypto::testing::fixture_authority(1)?,
        };
        let root = match self.root {
            Some(root) => root,
            None => FixtureRoot::temporary()?,
        };
        let blob_root = root.resolve(&self.blob_dir)?;
        let config = MemoryStoreConfig::new(blob_root.clone(), authority, self.retention)
            .retaining(root.owner());
        let store = InMemoryStore::new(config)?;
        Ok(TestStore {
            store,
            blob_root,
            root,
        })
    }
}

/// An acquired store with its blob root and scope.
pub struct TestStore {
    store: InMemoryStore,
    blob_root: PathBuf,
    root: FixtureRoot,
}

impl TestStore {
    pub const fn store(&self) -> &InMemoryStore {
        &self.store
    }

    /// The store alone. It retains its scope, so this is safe to share as
    /// `Arc<InMemoryStore>` or `Arc<dyn KappaStore>`.
    pub fn into_store(self) -> InMemoryStore {
        self.store
    }

    /// The directory the store writes blob files to.
    pub fn blob_root(&self) -> &Path {
        &self.blob_root
    }

    /// The scope containing the store, for sibling resources.
    pub const fn root(&self) -> &FixtureRoot {
        &self.root
    }
}

impl std::ops::Deref for TestStore {
    type Target = InMemoryStore;
    fn deref(&self) -> &InMemoryStore {
        &self.store
    }
}

/// A store with every [`StoreSpec::new`] default.
pub fn test_store() -> Result<TestStore, SetupError> {
    StoreSpec::new().acquire()
}

/// A store signing with `authority`, otherwise default.
pub fn test_store_with_authority(
    authority: kappa_crypto::SigningAuthority,
) -> Result<TestStore, SetupError> {
    StoreSpec::new().authority(authority).acquire()
}
