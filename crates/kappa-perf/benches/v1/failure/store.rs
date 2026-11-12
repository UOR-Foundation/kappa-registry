//! The store under fault: construction through the public configuration on
//! either I/O path, the typed condition tokens every fault family names
//! its records with, and the acknowledged history recovery is verified
//! against. Maintenance passes are `maintenance`; gated recording is
//! `recording`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kappa_fixture::FixtureRoot;
use kappa_handler::clock::WallClock;
use kappa_perf::bench::fixture::{create_ns, tag_name, tag_target};
use kappa_perf::bench::osc;
use kappa_perf::calibrate::OscId;
use kappa_store::work::{Dimension, WorkLimit};
use kappa_store::{
    EpochStore, ExecutionStore, Kappa, NamespaceRef, StoreError, TagUpdate, replay_to,
};
use kappa_store_redb::test_support::{BackendFactory, FaultBackend, FaultControl, Role};
use kappa_store_redb::{PersistentStore, PersistentStoreConfig};
use rustix::fs::{Advice, fadvise};

use crate::maintenance::settle_to_completion;

/// What the tier asks of every fault family.
pub struct Scale {
    pub pending: &'static [usize],
    pub budgets: &'static [u64],
    pub cycles: u64,
    pub seed: u64,
}

/// The default step byte budget (`PersistentStoreConfig`).
const STEP_BYTES: u64 = 256 * 1024 * 1024;

/// The signatures a budget admits: enough that the entry allowance is the
/// binding one, as the store's recovery tests choose it.
pub const SIGNATURES: u64 = 4096;

/// One allowance shared by discovery, epoch reconstruction and compaction,
/// the shape the store's own recovery tests bound settlement with:
/// `entries` on Entries, Handles and Candidates, `signatures` on
/// Signatures, the default bytes on every byte dimension.
pub const fn budget(entries: u64, signatures: u64) -> WorkLimit {
    WorkLimit::unbounded()
        .with(Dimension::Entries, entries)
        .with(Dimension::Handles, entries)
        .with(Dimension::Candidates, entries)
        .with(Dimension::Signatures, signatures)
        .with(Dimension::BytesRead, STEP_BYTES)
        .with(Dimension::BytesDecoded, STEP_BYTES)
        .with(Dimension::BytesAllocated, STEP_BYTES)
        .with(Dimension::BytesHashed, STEP_BYTES)
}

/// The `fault` condition tokens, one per injected fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultToken {
    None,
    Crash,
    CrashPartial,
    SyncBefore,
    SyncAfter,
    RefuseWrites,
    LostStorage,
    EmptyDatabase,
}

impl FaultToken {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Crash => "crash",
            Self::CrashPartial => "crash_partial",
            Self::SyncBefore => "sync_before",
            Self::SyncAfter => "sync_after",
            Self::RefuseWrites => "refuse_writes",
            Self::LostStorage => "lost_storage",
            Self::EmptyDatabase => "empty_database",
        }
    }
}

/// The `io` condition tokens: which backend the store's databases were
/// opened through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Io {
    /// redb's own file backend: the production path.
    File,
    /// The fault backend over the same files.
    Fault,
}

impl Io {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Fault => "fault",
        }
    }
}

/// An identifier from typed parts: `osc:{quantity}/{operation}?k=v&...`.
/// `OscId` canonicalizes key order and refuses unregistered conditions.
pub fn id(quantity: &str, operation: &str, conditions: &[(&str, &str)]) -> Result<OscId, String> {
    let query: Vec<String> = conditions
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    osc(&format!("osc:{quantity}/{operation}?{}", query.join("&"))).map_err(|e| e.to_string())
}

/// Where one store under measurement lives and how it is reopened.
pub struct Site {
    root: FixtureRoot,
    dir: PathBuf,
    pub control: FaultControl,
    registry: BackendFactory,
    namespace: BackendFactory,
    pub ns: NamespaceRef,
    /// A second namespace on the same store, always on the file backend,
    /// for what one namespace's fault inflicts on another.
    pub sibling: NamespaceRef,
    pub clock: WallClock,
    /// Content never written: a miss on it is the coverage oracle.
    pub absent: Kappa,
}

impl Site {
    /// Create the store at `{root}/{name}` on the file backend, publish
    /// the namespaces, settle completely, and register the registry and
    /// `ns`'s database with one fault control for later `Io::Fault` opens.
    pub fn prepare(root: &FixtureRoot, name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = root.resolve(Path::new(name))?;
        std::fs::create_dir_all(&dir)?;
        let clock = WallClock::new();
        let (ns, sibling) = {
            let store = PersistentStore::new(plain_config(root, &dir)?)?;
            let ns = create_ns(&store, &clock, &format!("{name}-faulted"))?;
            let sibling = create_ns(&store, &clock, &format!("{name}-sibling"))?;
            settle_to_completion(&store, &budget(4096, SIGNATURES), &absent_identity())?;
            (ns, sibling)
        };
        let (registry, control) = FaultBackend::factory(&dir.join("store.redb"))?;
        let namespace = control.factory_for(
            &namespace_directory(&dir, &ns).join("state.redb"),
            Role::Namespace,
        )?;
        Ok(Self {
            root: root.clone(),
            dir,
            control,
            registry,
            namespace,
            ns,
            sibling,
            clock,
            absent: absent_identity(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The faulted namespace's storage directory.
    pub fn namespace_dir(&self) -> PathBuf {
        namespace_directory(&self.dir, &self.ns)
    }

    /// Open the store on `io` with `configure` applied before opening. On
    /// `Io::Fault` the registry and `ns`'s database go through the fault
    /// control; the sibling stays on the file backend. The filesystem
    /// faults open on `Io::File`: the fault backend's factory holds the
    /// original database's open file, so a namespace opened through it
    /// would read that inode whatever the directory now holds.
    pub fn open(
        &self,
        io: Io,
        configure: impl FnOnce(&mut PersistentStoreConfig),
    ) -> Result<PersistentStore, Box<dyn std::error::Error>> {
        let mut config = plain_config(&self.root, &self.dir)?;
        if io == Io::Fault {
            let registry = Arc::clone(&self.registry);
            config.backend = Some(Box::new(move || registry()));
            let namespace = Arc::clone(&self.namespace);
            let faulted = *self.ns.id();
            config.namespace_backend = Some(Arc::new(move |id: &[u8; 16]| {
                (*id == faulted).then(|| namespace())
            }));
        }
        configure(&mut config);
        Ok(PersistentStore::new(config)?)
    }

    /// Drop every cached page of the databases that exist, so a reopen
    /// reads them from the device: recovery's cost, not the page cache's.
    pub fn evict_page_cache(&self) -> Result<(), Box<dyn std::error::Error>> {
        for path in [
            self.dir.join("store.redb"),
            self.namespace_dir().join("state.redb"),
        ] {
            if path.try_exists()? {
                let file = std::fs::File::open(&path)?;
                file.sync_all()?;
                fadvise(&file, 0, None, Advice::DontNeed)?;
            }
        }
        Ok(())
    }
}

fn plain_config(
    root: &FixtureRoot,
    dir: &Path,
) -> Result<PersistentStoreConfig, Box<dyn std::error::Error>> {
    Ok(PersistentStoreConfig::new(
        dir.join("blobs"),
        dir.join("store.redb"),
        kappa_crypto::testing::fixture_authority(1)?,
    )
    .retaining(root.owner()))
}

/// `{store}/namespaces/{hex(id)}`, the namespace's storage directory.
pub fn namespace_directory(store_dir: &Path, ns: &NamespaceRef) -> PathBuf {
    store_dir.join("namespaces").join(hex::encode(ns.id()))
}

fn absent_identity() -> Kappa {
    Kappa::sha256(b"failure bench: never published")
}

/// Publish one tag epoch of `ns`: `tag_name(index)` set to
/// `tag_target(index, round)`. Returns the epoch number the store
/// acknowledged, which is the ground truth recovery must reproduce.
pub fn publish(
    store: &PersistentStore,
    clock: &WallClock,
    ns: &NamespaceRef,
    index: usize,
    round: u64,
) -> Result<u64, StoreError> {
    let mut execution = store.begin_execution(ns, clock)?;
    execution.tag_put(
        &tag_name(index),
        &TagUpdate::Set {
            kappa: tag_target(index, round),
        },
    )?;
    Ok(execution.publish()?.epoch_number)
}

/// Publish `count` tag epochs of `ns` for `round`, returning what the
/// store acknowledged.
pub fn publish_acknowledged(
    store: &PersistentStore,
    clock: &WallClock,
    ns: &NamespaceRef,
    count: usize,
    round: u64,
) -> Result<Acknowledged, StoreError> {
    let mut acknowledged = Acknowledged {
        epochs: Vec::with_capacity(count),
        round,
        tags: count,
    };
    for index in 0..count {
        acknowledged
            .epochs
            .push(publish(store, clock, ns, index, round)?);
    }
    Ok(acknowledged)
}

/// What the store acknowledged before a fault: every publication whose
/// `publish` returned `Ok`, in order.
#[derive(Debug, Default)]
pub struct Acknowledged {
    pub epochs: Vec<u64>,
    pub round: u64,
    pub tags: usize,
}

impl Acknowledged {
    pub fn last(&self) -> Result<u64, Box<dyn std::error::Error>> {
        self.epochs
            .last()
            .copied()
            .ok_or_else(|| "nothing was acknowledged before the fault".into())
    }
}

/// What may be durable of the publication the fault interrupted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tail {
    /// Nothing of it: the head is the last acknowledged epoch.
    Lost,
    /// Either: the head is the last acknowledged epoch or the one after.
    MaySurvive,
    /// All of it: the head is the one after the last acknowledged epoch.
    Survives,
}

/// Require `store` to hold exactly the acknowledged history: the head as
/// `tail` allows, every acknowledged tag with its value, the interrupted
/// publication's tag present exactly when its epoch is, and the chain
/// replaying and verifying from genesis to the head.
pub fn verify_recovered(
    store: &PersistentStore,
    ns: &NamespaceRef,
    acknowledged: &Acknowledged,
    tail: Tail,
) -> Result<u64, Box<dyn std::error::Error>> {
    let last = acknowledged.last()?;
    let (head, _) = store.epoch_current(ns)?;
    let allowed = match tail {
        Tail::Lost => head == last,
        Tail::MaySurvive => head == last || head == last + 1,
        Tail::Survives => head == last + 1,
    };
    if !allowed {
        return Err(
            format!("head {head} after recovery; last acknowledged {last}, tail {tail:?}").into(),
        );
    }
    let state = replay_to(store, ns, head)?;
    for index in 0..acknowledged.tags {
        let expected = tag_target(index, acknowledged.round);
        match state.tags.get(&tag_name(index)) {
            Some(found) if *found == expected => {}
            other => {
                return Err(format!(
                    "tag {} after recovery is {other:?}, acknowledged {expected}",
                    tag_name(index)
                )
                .into());
            }
        }
    }
    let interrupted = tag_name(acknowledged.tags);
    let written = tag_target(acknowledged.tags, acknowledged.round);
    let present = state.tags.get(&interrupted) == Some(&written);
    if present != (head == last + 1) {
        return Err(format!(
            "epoch {head}: tag {interrupted} of the interrupted publication is {}, its epoch {}",
            if present { "present" } else { "absent" },
            if head == last + 1 {
                "survived"
            } else {
                "did not survive"
            }
        )
        .into());
    }
    Ok(head)
}
