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
    credential_cache: bool,
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
            credential_cache: false,
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

    #[must_use]
    pub const fn credential_cache(mut self, enabled: bool) -> Self {
        self.credential_cache = enabled;
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
        config.enable_credential_cache = self.credential_cache;
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

/// A storage failure the [`FaultBackend`] injects while armed.
///
/// redb 4.3 buffers page and header writes and hands them to the backend
/// inside `flush`, which then calls `sync_data`; the ordinary one-phase
/// durable commit flushes once, after switching the primary header slot.
/// Each fault therefore lands at a distinct, known point of that commit:
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Refuse every write before it modifies the file. Armed before a
    /// commit, the new header never reaches the file: the transaction is
    /// not persisted, though the writer only learns that its commit failed.
    RefuseWrites,
    /// Fail `sync_data` without synchronizing. The writes preceding it
    /// already reached the file and may persist; the outcome is unknown.
    FailSyncBefore,
    /// Synchronize, then report failure. The transaction is durable while
    /// the writer is told its commit failed.
    FailSyncAfter,
    /// Refuse `set_len` before resizing the file.
    RefuseSetLen,
}

/// One storage operation the [`FaultBackend`] received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageOp {
    Write { offset: u64, len: usize },
    Sync,
    SetLen(u64),
}

/// What became of a [`StorageOp`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpOutcome {
    Performed,
    /// Refused before any effect on the file.
    Refused,
    /// Performed, then reported as failed.
    PerformedThenFailed,
}

#[derive(Default)]
struct FaultState {
    armed: Option<Fault>,
    trace: Vec<(StorageOp, OpOutcome)>,
}

/// The switch and the operation trace of a [`FaultBackend`]. A fault stays
/// armed until disarmed, so a failed handle's teardown meets it too.
#[derive(Clone, Default)]
pub struct FaultControl(Arc<std::sync::Mutex<FaultState>>);

impl FaultControl {
    fn state(&self) -> std::sync::MutexGuard<'_, FaultState> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Arm `fault` and start a fresh trace.
    pub fn arm(&self, fault: Fault) {
        let mut state = self.state();
        state.armed = Some(fault);
        state.trace.clear();
    }

    pub fn disarm(&self) {
        self.state().armed = None;
    }

    /// Every operation since the last [`FaultControl::arm`], in order.
    pub fn trace(&self) -> Vec<(StorageOp, OpOutcome)> {
        self.state().trace.clone()
    }

    /// Decide `op` under the armed fault, run `effect` unless refused, and
    /// record the outcome.
    fn apply(
        &self,
        op: StorageOp,
        effect: impl FnOnce() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let armed = self.state().armed;
        let (before, after) = match (armed, op) {
            (Some(Fault::RefuseWrites), StorageOp::Write { .. })
            | (Some(Fault::FailSyncBefore), StorageOp::Sync)
            | (Some(Fault::RefuseSetLen), StorageOp::SetLen(_)) => (true, false),
            (Some(Fault::FailSyncAfter), StorageOp::Sync) => (false, true),
            _ => (false, false),
        };
        if before {
            self.state().trace.push((op, OpOutcome::Refused));
            return Err(std::io::Error::other(format!(
                "injected {armed:?} at {op:?}"
            )));
        }
        let result = effect();
        let outcome = match (&result, after) {
            (Err(_), _) => return result,
            (Ok(()), true) => OpOutcome::PerformedThenFailed,
            (Ok(()), false) => OpOutcome::Performed,
        };
        self.state().trace.push((op, outcome));
        if after {
            return Err(std::io::Error::other(format!(
                "injected {armed:?} after {op:?}"
            )));
        }
        Ok(())
    }
}

/// File storage with deterministic, armable failure injection and an
/// operation trace.
///
/// Every backend a factory makes shares the file and the
/// control, so reacquiring the same spec reopens the same database.
pub struct FaultBackend {
    file: Arc<std::sync::Mutex<std::fs::File>>,
    control: FaultControl,
}

impl FaultBackend {
    /// A factory over the database file at `path`, created if absent, and
    /// the control of every backend it makes.
    pub fn factory(path: &Path) -> Result<(BackendFactory, FaultControl), SetupError> {
        let file = Arc::new(std::sync::Mutex::new(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)?,
        ));
        let control = FaultControl::default();
        let shared = control.clone();
        let factory: BackendFactory = Arc::new(move || {
            Box::new(Self {
                file: Arc::clone(&file),
                control: shared.clone(),
            })
        });
        Ok((factory, control))
    }

    fn file(&self) -> std::io::Result<std::sync::MutexGuard<'_, std::fs::File>> {
        self.file
            .lock()
            .map_err(|_| std::io::Error::other("file lock poisoned"))
    }
}

impl std::fmt::Debug for FaultBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaultBackend")
            .field("armed", &self.control.state().armed)
            .finish_non_exhaustive()
    }
}

impl redb::StorageBackend for FaultBackend {
    fn len(&self) -> std::io::Result<u64> {
        Ok(self.file()?.metadata()?.len())
    }

    fn read(&self, offset: u64, output: &mut [u8]) -> std::io::Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = self.file()?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(output)
    }

    fn write(&self, offset: u64, input: &[u8]) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        self.control.apply(
            StorageOp::Write {
                offset,
                len: input.len(),
            },
            || {
                let mut file = self.file()?;
                file.seek(SeekFrom::Start(offset))?;
                file.write_all(input)
            },
        )
    }

    fn set_len(&self, length: u64) -> std::io::Result<()> {
        self.control
            .apply(StorageOp::SetLen(length), || self.file()?.set_len(length))
    }

    fn sync_data(&self) -> std::io::Result<()> {
        self.control
            .apply(StorageOp::Sync, || self.file()?.sync_all())
    }
}
