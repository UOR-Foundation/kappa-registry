//! The one acquisition path for persistent stores in tests and benchmarks.
//!
//! [`PersistentSpec`] selects authority, scope and placement, and the
//! backend options tests vary; [`PersistentSpec::acquire`] builds the store
//! through [`PersistentStoreConfig`] with the scope retained by the store and
//! by its encryption domain, so escaping store handles and encrypted readers
//! keep the scope alive. The default authority is the fixture authority from
//! seed byte 1, the identity the in-memory fixture signs with, so parity
//! tests compare identically signed histories.
//!
//! A spec placed in a caller's [`FixtureRoot`] is a reopenable description:
//! acquiring it again after the previous store dropped opens the same
//! database under the same authority, which is how restart tests reopen.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kappa_fixture::{FixtureRoot, SetupError};

use crate::{PersistentStore, PersistentStoreConfig};

/// Factory for a custom storage backend, called once per acquisition.
pub type BackendFactory = Arc<dyn Fn() -> Box<dyn redb::StorageBackend> + Send + Sync>;

/// Inputs that select one persistent store.
#[derive(Clone)]
pub struct PersistentSpec {
    authority: Option<kappa_crypto::SigningAuthority>,
    alternates: Vec<kappa_crypto::SigningAuthority>,
    require_history: bool,
    root: Option<FixtureRoot>,
    dir: PathBuf,
    db_file: String,
    encryption_key: Option<[u8; 32]>,
    fsync: bool,
    backend: Option<BackendFactory>,
    namespace_backend: Option<crate::storage::NamespaceBackend>,
}

impl Default for PersistentSpec {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistentSpec {
    /// Fixture authority, a fresh temporary scope, blobs at `blobs` and the
    /// database at `store.redb` in the scope, production defaults otherwise.
    pub fn new() -> Self {
        Self {
            authority: None,
            alternates: Vec::new(),
            require_history: false,
            root: None,
            dir: PathBuf::from("."),
            db_file: "store.redb".into(),
            encryption_key: None,
            fsync: true,
            backend: None,
            namespace_backend: None,
        }
    }

    /// Store the database of namespace `id` through `backend`, so that one
    /// namespace's commits can be faulted while the registry and every
    /// other namespace use ordinary files.
    #[must_use]
    pub fn namespace_backend(mut self, id: [u8; 16], backend: BackendFactory) -> Self {
        self.namespace_backend = Some(Arc::new(move |namespace: &[u8; 16]| {
            (*namespace == id).then(|| backend())
        }));
        self
    }

    /// Sign and admit epochs with `authority`.
    #[must_use]
    pub fn authority(mut self, authority: kappa_crypto::SigningAuthority) -> Self {
        self.authority = Some(authority);
        self
    }

    /// Further authorities the persisted history may select, as
    /// [`PersistentStoreConfig::with_alternates`].
    #[must_use]
    pub fn alternates(mut self, alternates: Vec<kappa_crypto::SigningAuthority>) -> Self {
        self.alternates = alternates;
        self
    }

    /// Refuse a database without history, as
    /// [`PersistentStoreConfig::requiring_history`].
    #[must_use]
    pub const fn requiring_history(mut self) -> Self {
        self.require_history = true;
        self
    }

    /// Place the store in `root`; required to reopen the same database.
    #[must_use]
    pub fn in_root(mut self, root: &FixtureRoot) -> Self {
        self.root = Some(root.clone());
        self
    }

    /// Directory of this store relative to the scope, holding `blobs` and
    /// the database. Distinct directories give distinct stores in one scope.
    #[must_use]
    pub fn dir(mut self, relative: impl Into<PathBuf>) -> Self {
        self.dir = relative.into();
        self
    }

    /// Database file name inside the store directory.
    #[must_use]
    pub fn db_file(mut self, name: impl Into<String>) -> Self {
        self.db_file = name.into();
        self
    }

    #[must_use]
    pub const fn encryption_key(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(key);
        self
    }

    #[must_use]
    pub const fn fsync(mut self, fsync: bool) -> Self {
        self.fsync = fsync;
        self
    }

    /// Store the database through `backend` instead of the file backend.
    #[must_use]
    pub fn backend(mut self, backend: BackendFactory) -> Self {
        self.backend = Some(backend);
        self
    }

    pub fn acquire(self) -> Result<TestPersistentStore, SetupError> {
        let authority = match self.authority {
            Some(authority) => authority,
            None => kappa_crypto::testing::fixture_authority(1)?,
        };
        let root = match self.root {
            Some(root) => root,
            None => FixtureRoot::temporary()?,
        };
        let dir = root.resolve(&self.dir)?;
        let blob_root = dir.join("blobs");
        let db_path = dir.join(&self.db_file);
        let mut config = PersistentStoreConfig::new(blob_root.clone(), db_path.clone(), authority)
            .with_alternates(self.alternates)
            .retaining(root.owner());
        if self.require_history {
            config = config.requiring_history();
        }
        config.encryption_key = self.encryption_key;
        config.fsync = self.fsync;
        if let Some(backend) = self.backend {
            config.backend = Some(Box::new(move || backend()));
        }
        config.namespace_backend = self.namespace_backend;
        let store = PersistentStore::new(config)?;
        Ok(TestPersistentStore {
            store,
            blob_root,
            db_path,
            root,
        })
    }
}

/// An acquired persistent store with its paths and scope.
pub struct TestPersistentStore {
    store: PersistentStore,
    blob_root: PathBuf,
    db_path: PathBuf,
    root: FixtureRoot,
}

impl TestPersistentStore {
    pub const fn store(&self) -> &PersistentStore {
        &self.store
    }

    /// The store alone. It retains its scope, so this is safe to share as
    /// `Arc<PersistentStore>` or `Arc<dyn KappaStore>`.
    pub fn into_store(self) -> PersistentStore {
        self.store
    }

    pub fn blob_root(&self) -> &Path {
        &self.blob_root
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub const fn root(&self) -> &FixtureRoot {
        &self.root
    }
}

impl std::ops::Deref for TestPersistentStore {
    type Target = PersistentStore;
    fn deref(&self) -> &PersistentStore {
        &self.store
    }
}

/// A persistent store with every [`PersistentSpec::new`] default.
pub fn persistent_store() -> Result<TestPersistentStore, SetupError> {
    PersistentSpec::new().acquire()
}

#[cfg(test)]
#[path = "test_support_writer.rs"]
mod writer;
#[cfg(test)]
pub(crate) use writer::{TestWriter, controller_for_tests, retirement_principal};

/// Fault injection beneath redb (`fault`): the backend, its control, the
/// faults, the crash model and the trace it records.
#[path = "test_support/fault.rs"]
pub mod fault;
pub use fault::{
    Fault, FaultBackend, FaultControl, Fired, Loss, OpOutcome, Role, SECTOR, StorageOp,
};

#[cfg(test)]
#[path = "test_support/fault_tests.rs"]
mod fault_tests;
