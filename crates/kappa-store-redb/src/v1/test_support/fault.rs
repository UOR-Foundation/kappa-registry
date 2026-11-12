//! Fault injection beneath redb: a `StorageBackend` over a real file that
//! refuses or misreports operations while a fault is armed, traces every
//! operation, and can crash, taking back the writes no performed sync
//! covers, sector by sector.
//!
//! One [`FaultControl`] is shared by every database of a store (the
//! registry and each namespace), because a crash reaches every file of a
//! process at one instant. Each file carries a [`Role`], so a crash can be
//! placed at the nth sync of the registry or of the namespace.
//!
//! The crash model follows what devices and filesystems do before a sync
//! (Pillai et al., ALICE, OSDI 2014; TigerBeetle `testing/storage.zig`,
//! which corrupts each pending write's target independently): the file is
//! divided into [`SECTOR`]-byte sectors, the bytes each sector held at its
//! first unsynced touch are recorded, and a crash keeps or loses each
//! touched sector on its own. A header sector that persisted while the page
//! sectors it points to did not is therefore a case the crash produces,
//! and it is the case redb's recovery exists for.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use kappa_fixture::SetupError;

use super::BackendFactory;

/// Bytes of one sector: the unit a crash keeps or loses, redb's page
/// granularity and the common device sector.
pub const SECTOR: u64 = 4096;

/// Which database of a store a file is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Registry,
    Namespace,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Namespace => "namespace",
        }
    }
}

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
    /// Crash at the `nth` sync (1-based, since arming) of a file of `role`,
    /// before it synchronizes: that commit's writes reached the page cache
    /// and nothing of them reached the medium, and every later write, sync
    /// and resize on every file of the control is refused until
    /// [`FaultControl::restore`]. The caller then selects what the crash
    /// loses with [`FaultControl::crash`].
    CrashAtSync { role: Role, nth: u32 },
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

/// What a crash loses of the sectors no performed sync covers
/// ([`FaultControl::crash`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Loss {
    /// Every unsynced sector.
    All,
    /// Each unsynced sector lost with probability `percent`, drawn from
    /// `seed` in `(file, sector)` order, independently of every other.
    Independent { percent: u8, seed: u64 },
}

/// Counts over the trace since the last [`FaultControl::arm`], and the
/// bytes a crash took back: the record that an injected fault fired. A
/// measurement taken under a fault whose counts are all zero measured
/// nothing injected.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fired {
    pub performed: u64,
    pub refused: u64,
    pub performed_then_failed: u64,
    pub lost_bytes: u64,
}

impl Fired {
    /// The sum of two counts, for a record over several cycles.
    #[must_use]
    pub const fn plus(self, other: Self) -> Self {
        Self {
            performed: self.performed.saturating_add(other.performed),
            refused: self.refused.saturating_add(other.refused),
            performed_then_failed: self
                .performed_then_failed
                .saturating_add(other.performed_then_failed),
            lost_bytes: self.lost_bytes.saturating_add(other.lost_bytes),
        }
    }
}

/// `SplitMix64`, for the deterministic choice of lost sectors. The same
/// generator, seeded the same, makes the same choices in the same order:
/// a test computes the expected file from it.
pub struct SplitMix(pub u64);

impl SplitMix {
    pub const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..100`.
    pub const fn percent(&mut self) -> u8 {
        (self.next_u64() % 100) as u8
    }
}

/// One file of a control, by registration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FileId(usize);

/// One sector of one file.
type SectorKey = (FileId, u64);

type SharedFile = Arc<std::sync::Mutex<std::fs::File>>;

fn lock_file(file: &SharedFile) -> std::io::Result<std::sync::MutexGuard<'_, std::fs::File>> {
    file.lock()
        .map_err(|_| std::io::Error::other("file lock poisoned"))
}

struct Registered {
    file: SharedFile,
}

#[derive(Default)]
struct FaultState {
    files: Vec<Registered>,
    armed: Option<Fault>,
    trace: Vec<(StorageOp, OpOutcome)>,
    /// Syncs met per role since the last arm, for [`Fault::CrashAtSync`].
    syncs_since_arm: BTreeMap<Role, u32>,
    /// Record the bytes every sector held at its first unsynced touch,
    /// until a performed sync of its file. Independent of `armed`: a sync
    /// fault and unsynced tracking compose.
    track_unsynced: bool,
    /// The pre-touch bytes of every sector no performed sync covers.
    unsynced: BTreeMap<SectorKey, Vec<u8>>,
    /// Each file's length before its first unsynced write or resize.
    length_before: BTreeMap<FileId, u64>,
    /// The process is dead to every file of this control: every write,
    /// sync and resize is refused and traced until
    /// [`FaultControl::restore`].
    crashed: bool,
    /// The sectors `crash` selected to undo.
    lost: BTreeMap<SectorKey, Vec<u8>>,
    /// Backends the control's factories made that redb has not closed.
    open_handles: usize,
}

/// The switch, the operation trace and the crash control shared by every
/// [`FaultBackend`] of one store. A fault stays armed until disarmed, so a
/// failed handle's teardown meets it too.
#[derive(Clone)]
pub struct FaultControl {
    state: Arc<std::sync::Mutex<FaultState>>,
}

impl Default for FaultControl {
    fn default() -> Self {
        Self::new()
    }
}

impl FaultControl {
    /// A control with no files yet; add them with [`Self::factory_for`].
    pub fn new() -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(FaultState::default())),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, FaultState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A factory over the database file at `path`, created if absent, in
    /// `role`, whose backends share this control: how one store's registry
    /// and namespace databases come under one crash
    /// (`PersistentSpec::backend` and `PersistentSpec::namespace_backend`).
    pub fn factory_for(&self, path: &Path, role: Role) -> Result<BackendFactory, SetupError> {
        let file: SharedFile = Arc::new(std::sync::Mutex::new(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)?,
        ));
        let id = {
            let mut state = self.state();
            state.files.push(Registered {
                file: Arc::clone(&file),
            });
            FileId(state.files.len() - 1)
        };
        let control = self.clone();
        Ok(Arc::new(move || {
            control.state().open_handles += 1;
            Box::new(FaultBackend {
                control: control.clone(),
                file: Arc::clone(&file),
                id,
                role,
            })
        }))
    }

    /// Arm `fault` and start a fresh trace.
    pub fn arm(&self, fault: Fault) {
        let mut state = self.state();
        state.armed = Some(fault);
        state.trace.clear();
        state.syncs_since_arm.clear();
    }

    pub fn disarm(&self) {
        self.state().armed = None;
    }

    /// Every operation since the last [`FaultControl::arm`], in order.
    pub fn trace(&self) -> Vec<(StorageOp, OpOutcome)> {
        self.state().trace.clone()
    }

    /// Record, or stop recording, what every sector held at its first
    /// unsynced touch. Turning it off forgets the record.
    pub fn track_unsynced(&self, on: bool) {
        let mut state = self.state();
        state.track_unsynced = on;
        if !on {
            state.unsynced.clear();
            state.length_before.clear();
        }
    }

    /// Whether a crash is in effect ([`Fault::CrashAtSync`] fired, or
    /// [`Self::crash`] was called) and not yet restored.
    pub fn crashed(&self) -> bool {
        self.state().crashed
    }

    /// Crash: refuse every further write, sync and resize on every backend
    /// of this control, and select the unsynced sectors to undo under
    /// `loss`. Returns the bytes that will be lost. After a
    /// [`Fault::CrashAtSync`] fired, this only selects. The caller drops
    /// the store (its teardown writes are refused and traced), calls
    /// [`Self::restore`], then reacquires through the same factories.
    pub fn crash(&self, loss: Loss) -> u64 {
        let mut state = self.state();
        state.crashed = true;
        let mut rng = SplitMix(match loss {
            Loss::All => 0,
            Loss::Independent { seed, .. } => seed,
        });
        let unsynced = std::mem::take(&mut state.unsynced);
        let mut lost_bytes = 0u64;
        for (key, pristine) in unsynced {
            let lose = match loss {
                Loss::All => true,
                Loss::Independent { percent, .. } => rng.percent() < percent,
            };
            if lose {
                lost_bytes += pristine.len() as u64;
                state.lost.insert(key, pristine);
            } else {
                // A kept sector stays recorded: its file keeps the length it
                // needed, and a later sync or restore accounts for it.
                state.unsynced.insert(key, pristine);
            }
        }
        lost_bytes
    }

    /// Undo the sectors [`Self::crash`] selected and return each file whose
    /// every unsynced sector was lost to the length it had before its first
    /// unsynced write, so every file holds exactly what had reached the
    /// medium. Refused unless a crash is in effect and redb has closed
    /// every backend: undoing beneath a live `Database` is not a crash, it
    /// is corruption of a running process.
    pub fn restore(&self) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        let mut state = self.state();
        if !state.crashed {
            return Err(std::io::Error::other(
                "restore without a crash: nothing was lost",
            ));
        }
        if state.open_handles != 0 {
            return Err(std::io::Error::other(format!(
                "restore with {} backend handle(s) still open: close the Database first",
                state.open_handles
            )));
        }
        let lost = std::mem::take(&mut state.lost);
        let mut touched: Vec<FileId> = Vec::new();
        for ((id, sector), pristine) in lost {
            let file = &state.files[id.0].file;
            let mut file = lock_file(file)?;
            file.seek(SeekFrom::Start(sector * SECTOR))?;
            file.write_all(&pristine)?;
            if !touched.contains(&id) {
                touched.push(id);
            }
        }
        let length_before = std::mem::take(&mut state.length_before);
        for (id, length) in length_before {
            let kept_any = state.unsynced.keys().any(|(kept, _)| *kept == id);
            if !kept_any {
                lock_file(&state.files[id.0].file)?.set_len(length)?;
            }
            if !touched.contains(&id) {
                touched.push(id);
            }
        }
        for id in touched {
            lock_file(&state.files[id.0].file)?.sync_all()?;
        }
        state.unsynced.clear();
        state.crashed = false;
        Ok(())
    }

    /// Counts over the trace since the last [`Self::arm`], plus the bytes
    /// the last crash selected and not yet restored.
    pub fn fired(&self) -> Fired {
        let state = self.state();
        let mut fired = Fired::default();
        for (_, outcome) in &state.trace {
            match outcome {
                OpOutcome::Performed => fired.performed += 1,
                OpOutcome::Refused => fired.refused += 1,
                OpOutcome::PerformedThenFailed => fired.performed_then_failed += 1,
            }
        }
        fired.lost_bytes = state
            .lost
            .values()
            .map(|pristine| pristine.len() as u64)
            .sum();
        fired
    }

    /// Decide `op` of a file of `role` under the crash state and the armed
    /// fault, run `effect` unless refused, and record the outcome.
    fn apply(
        &self,
        role: Role,
        op: StorageOp,
        effect: impl FnOnce() -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let (armed, crashed) = {
            let mut state = self.state();
            if op == StorageOp::Sync {
                let seen = state.syncs_since_arm.entry(role).or_insert(0);
                *seen = seen.saturating_add(1);
                let seen = *seen;
                if let Some(Fault::CrashAtSync {
                    role: crash_role,
                    nth,
                }) = state.armed
                    && crash_role == role
                    && seen == nth
                {
                    state.crashed = true;
                    state.armed = None;
                }
            }
            (state.armed, state.crashed)
        };
        if crashed {
            self.state().trace.push((op, OpOutcome::Refused));
            return Err(std::io::Error::other(format!("crashed: refused {op:?}")));
        }
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

/// File storage with deterministic, armable failure injection, an
/// operation trace, and a crash that takes back unsynced sectors.
///
/// Every backend a factory makes shares its file, and every factory of a
/// control shares the control, so reacquiring the same spec reopens the
/// same databases under the same faults.
pub struct FaultBackend {
    control: FaultControl,
    file: SharedFile,
    id: FileId,
    role: Role,
}

impl FaultBackend {
    /// A new control and a factory over the database file at `path`,
    /// created if absent, as the control's [`Role::Registry`] file. Further
    /// files of the same store come under the same control through
    /// [`FaultControl::factory_for`].
    pub fn factory(path: &Path) -> Result<(BackendFactory, FaultControl), SetupError> {
        let control = FaultControl::new();
        let factory = control.factory_for(path, Role::Registry)?;
        Ok((factory, control))
    }

    fn file(&self) -> std::io::Result<std::sync::MutexGuard<'_, std::fs::File>> {
        lock_file(&self.file)
    }

    /// Record, for every sector `offset..offset + len` touches that is not
    /// yet recorded, the bytes it holds now (zero past the file's end), and
    /// the file's length before its first unsynced touch.
    ///
    /// Lock order is the control's state, then a file, as in
    /// [`FaultControl::restore`]; taking them the other way round here
    /// would let a restore and a write each hold the lock the other waits on.
    fn record_sectors(&self, offset: u64, len: usize) -> std::io::Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        let end = offset.saturating_add(len as u64);
        let first = offset / SECTOR;
        let last = end.div_ceil(SECTOR);
        let mut state = self.control.state();
        let mut file = self.file()?;
        let length = file.metadata()?.len();
        state.length_before.entry(self.id).or_insert(length);
        for sector in first..last {
            if state.unsynced.contains_key(&(self.id, sector)) {
                continue;
            }
            let start = sector * SECTOR;
            let mut pristine = vec![0u8; SECTOR as usize];
            if start < length {
                let available = usize::try_from((length - start).min(SECTOR)).unwrap_or(0);
                file.seek(SeekFrom::Start(start))?;
                file.read_exact(&mut pristine[..available])?;
            }
            state.unsynced.insert((self.id, sector), pristine);
        }
        Ok(())
    }
}

impl std::fmt::Debug for FaultBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.control.state();
        f.debug_struct("FaultBackend")
            .field("role", &self.role)
            .field("armed", &state.armed)
            .field("crashed", &state.crashed)
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
        let tracked = self.control.state().track_unsynced;
        self.control.apply(
            self.role,
            StorageOp::Write {
                offset,
                len: input.len(),
            },
            || {
                if tracked {
                    self.record_sectors(offset, input.len())?;
                }
                let mut file = self.file()?;
                file.seek(SeekFrom::Start(offset))?;
                file.write_all(input)
            },
        )
    }

    fn set_len(&self, length: u64) -> std::io::Result<()> {
        self.control
            .apply(self.role, StorageOp::SetLen(length), || {
                if self.control.state().track_unsynced {
                    let current = self.file()?.metadata()?.len();
                    self.control
                        .state()
                        .length_before
                        .entry(self.id)
                        .or_insert(current);
                }
                self.file()?.set_len(length)
            })
    }

    fn sync_data(&self) -> std::io::Result<()> {
        // A performed sync of this file, reported failed or not, makes
        // every prior write of this file durable: nothing of it is a
        // crash's to take back. Other files' unsynced sectors stay exposed.
        self.control.apply(self.role, StorageOp::Sync, || {
            self.file()?.sync_all()?;
            let mut state = self.control.state();
            state.unsynced.retain(|(id, _), _| *id != self.id);
            state.length_before.remove(&self.id);
            Ok(())
        })
    }

    fn close(&self) -> std::io::Result<()> {
        let mut state = self.control.state();
        state.open_handles = state.open_handles.saturating_sub(1);
        Ok(())
    }
}
