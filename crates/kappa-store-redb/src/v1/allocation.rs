//! External allocations: the files that hold content too large for an
//! inline row, their exclusive creation, their protection, and their
//! deletion.
//!
//! An allocation lives at `{blob_root}/objects/{hex[0..2]}/{hex}`, named by
//! its [`AllocationId`] alone. An unencrypted store keeps `{hex}.chunks`
//! beside it (see [`crate::chunk_integrity`]); an encrypted store
//! authenticates each chunk through its AEAD tag instead. The identity is
//! pinned before the file exists, creation is `create_new`, and a collision
//! releases the pin and draws another identity, so reclamation can never
//! observe an unprotected allocation that a preparation still owns, and an
//! allocation never adopts or overwrites another's file.
//!
//! Deletion authority is epoch-derived and namespace-local: the installing
//! namespace's `ALLOCATIONS` table maps every allocation a committed
//! External row selects to its identity, written and removed with the row.
//! Which namespace that is, the allocation records itself: installation
//! writes `{hex}.owner` beside the payload ([`Owner`], the storage
//! instance and the identity) before the row, on the allocation's own
//! shard, so no
//! shared writer is taken and a reclaimer finds the deciding namespace
//! without a scan. An allocation is deletable only when its owner's
//! committed rows do not select it, it holds no pin, and the deleter holds
//! its [`ReclaimClaim`]. Identities are never reused and every install uses
//! a fresh allocation, so a row that is absent never comes back and at most
//! one namespace ever installs a given allocation.
//!
//! Protection state is sharded by the first byte of the identity so pins
//! taken by concurrent readers of different allocations do not serialize.
//! A poisoned shard fences every allocation in it: pins and claims are
//! refused with a reported error, never silently leaked.
//!
//! Durability lives in [`crate::durability`]; no writer is held anywhere
//! in this module.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use kappa_types::{Kappa, StoreError};

use crate::representation::AllocationId;
use crate::storage_instance::StorageInstance;
use crate::unsettled::Charge;

#[cfg(test)]
#[path = "allocation_tests.rs"]
mod tests;

const SHARD_COUNT: usize = 256;
const LOCK_SHARDS: usize = 64;

pub fn objects_root(blob_root: &Path) -> PathBuf {
    blob_root.join("objects")
}

pub fn allocation_path(blob_root: &Path, allocation: &AllocationId) -> PathBuf {
    let hex = allocation.hex();
    objects_root(blob_root).join(&hex[..2]).join(hex)
}

pub fn chunk_list_path(blob_root: &Path, allocation: &AllocationId) -> PathBuf {
    let hex = allocation.hex();
    objects_root(blob_root)
        .join(&hex[..2])
        .join(format!("{hex}.chunks"))
}

/// The owner marker beside the payload: which namespace installed the
/// allocation and under which identity.
pub fn owner_path(blob_root: &Path, allocation: &AllocationId) -> PathBuf {
    let hex = allocation.hex();
    objects_root(blob_root)
        .join(&hex[..2])
        .join(format!("{hex}.owner"))
}

/// What a directory entry under `objects/` is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    Payload,
    Sidecar,
    Owner,
}

/// Classify a file name inside a shard: a payload, its sidecar, its owner
/// marker, or none of them. Each is reported on its own, so a deletion
/// interrupted between the unlinks is found by whichever file remains.
pub fn classify(file_name: &str) -> Option<(AllocationId, Entry)> {
    if let Some(stem) = file_name.strip_suffix(".chunks") {
        return AllocationId::parse_hex(stem).map(|id| (id, Entry::Sidecar));
    }
    if let Some(stem) = file_name.strip_suffix(".owner") {
        return AllocationId::parse_hex(stem).map(|id| (id, Entry::Owner));
    }
    AllocationId::parse_hex(file_name).map(|id| (id, Entry::Payload))
}

/// The durable record of who installed an allocation: the storage instance
/// whose transaction wrote the row and the identity the row is keyed by.
/// Encoded as `[instance key][identity key_bytes]`, the same entry the
/// settled ownership projection keys by; the instance key is 32 bytes, or
/// 16 for a record written before incarnations existed
/// (`storage_instance`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owner {
    pub(crate) instance: StorageInstance,
    pub(crate) identity: Kappa,
}

impl Owner {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let instance = self.instance.key();
        let key = self.identity.key_bytes();
        let mut entry = Vec::with_capacity(instance.len() + key.len());
        entry.extend_from_slice(&instance);
        entry.extend_from_slice(&key);
        entry
    }

    /// Decode an owner record. No version byte separates the two layouts:
    /// the instance key is 16 or 32 bytes, and the identity key that
    /// follows has the exact length its axis discriminant fixes, so a
    /// record is the layout whose remainder is a valid identity key. No two
    /// axis digest lengths differ by 16 (asserted in the tests), so at most
    /// one layout fits; a record both would fit is refused, never guessed.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let at = |split: usize| {
            let (instance, identity) = (bytes.get(..split)?, bytes.get(split..)?);
            Some((instance, Kappa::from_key_bytes(identity).ok()?))
        };
        let (instance, identity) = match (at(16), at(32)) {
            (Some(legacy), None) => legacy,
            (None, Some(current)) => current,
            (Some(_), Some(_)) => {
                return Err(StoreError::Internal(
                    "allocation owner record fits both layouts".into(),
                ));
            }
            (None, None) => {
                return Err(StoreError::Internal(format!(
                    "allocation owner record of {} bytes names no instance and identity",
                    bytes.len()
                )));
            }
        };
        Ok(Self {
            instance: StorageInstance::from_key(instance)?,
            identity,
        })
    }
}

/// Write the owner marker of `allocation`, exclusively: an allocation is
/// installed once, by one namespace, so a marker naming another installer
/// is a second installation and is refused. A marker naming exactly
/// `owner` is that installation's own, left by an attempt whose transaction
/// did not commit and which a retained publication's replay installs again
/// (`custody`). The marker and its directory entry are synced when `fsync`,
/// so it survives a crash that the row's commit survives: a reused marker is
/// synced exactly as a new one, since its presence says nothing about
/// whether an earlier attempt's sync completed.
pub fn write_owner_marker(
    blob_root: &Path,
    allocation: &AllocationId,
    owner: &Owner,
    fsync: bool,
) -> Result<(), StoreError> {
    let path = owner_path(blob_root, allocation);
    let file = match private_create_new().open(&path) {
        Ok(mut file) => {
            std::io::Write::write_all(&mut file, &owner.encode())?;
            file
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            match read_owner_marker(blob_root, allocation)? {
                Some(held) if held == *owner => File::open(&path)?,
                _ => {
                    return Err(StoreError::Internal(format!(
                        "allocation {} already records another installer",
                        allocation.hex()
                    )));
                }
            }
        }
        Err(error) => return Err(StoreError::Io(error)),
    };
    if fsync {
        file.sync_all()?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

/// The largest owner marker: a 32-byte instance key and the longest
/// identity key, an axis discriminant and a 64-byte (SHA-512) digest.
pub const MAX_OWNER_MARKER_BYTES: u64 = 32 + 1 + 64;

/// The owner marker of `allocation`: `None` when no installation ever
/// wrote one. At most [`MAX_OWNER_MARKER_BYTES`] are read; a longer file
/// is refused without being read further.
pub fn read_owner_marker(
    blob_root: &Path,
    allocation: &AllocationId,
) -> Result<Option<Owner>, StoreError> {
    let mut file = match File::open(owner_path(blob_root, allocation)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StoreError::Io(error)),
    };
    // The format has a fixed maximum. One extra byte distinguishes an
    // oversized marker without allocating or reading the rest of the file.
    let mut bytes = [0u8; MAX_OWNER_MARKER_BYTES as usize + 1];
    let mut length = 0;
    while length < bytes.len() {
        match std::io::Read::read(&mut file, &mut bytes[length..]) {
            Ok(0) => break,
            Ok(read) => length += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(StoreError::Io(error)),
        }
    }
    if length as u64 > MAX_OWNER_MARKER_BYTES {
        return Err(StoreError::Internal(format!(
            "allocation {} owner marker exceeds {MAX_OWNER_MARKER_BYTES} bytes",
            allocation.hex()
        )));
    }
    Owner::decode(&bytes[..length]).map(Some)
}

/// Create every shard directory and make the whole directory chain from
/// the filesystem root's first existing ancestor down to the shards
/// durable. Runs once at open, before any preparation, so a batch later
/// needs only the entries it adds.
pub fn precreate_shards(blob_root: &Path) -> Result<(), StoreError> {
    let root = objects_root(blob_root);
    let mut created = Vec::new();
    let mut probe = Some(root.as_path());
    while let Some(path) = probe {
        if path.exists() {
            break;
        }
        created.push(path.to_path_buf());
        probe = path.parent();
    }
    fs::create_dir_all(&root)?;
    for shard in 0..SHARD_COUNT {
        let dir = root.join(format!("{shard:02x}"));
        fs::create_dir_all(&dir)?;
        File::open(&dir)?.sync_all()?;
    }
    File::open(&root)?.sync_all()?;
    // Every directory this call created has a new entry in its parent.
    for path in created {
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

/// Private file options for payloads and sidecars alike.
pub fn private_create_new() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
}

/// Protection of allocations while preparations or readers hold them.
/// Reclamation refuses to claim a pinned allocation, and a claimed
/// allocation refuses new pins, so neither can pass the other.
pub struct Protection {
    shards: Vec<Mutex<Shard>>,
}

#[derive(Default)]
struct Shard {
    pinned: BTreeMap<AllocationId, usize>,
    claimed: BTreeSet<AllocationId>,
}

impl Default for Protection {
    fn default() -> Self {
        Self {
            shards: (0..LOCK_SHARDS)
                .map(|_| Mutex::new(Shard::default()))
                .collect(),
        }
    }
}

/// A live pin. Dropping releases it, and the unsettled charge it carries.
pub struct Pin {
    protection: Arc<Protection>,
    allocation: AllocationId,
    /// Physical bytes the allocation occupies (payload and sidecar), as
    /// measured by the preparation that wrote them; zero for a pin taken
    /// over an allocation this holder did not write. The unsettled budget
    /// charges this, so no storage is inspected at commit.
    bytes: u64,
    /// The unsettled charge the preparation reserved for this allocation
    /// (`crate::unsettled`), carried until the publication parks it.
    charge: Option<Charge>,
}

impl Pin {
    pub(crate) const fn allocation(&self) -> &AllocationId {
        &self.allocation
    }

    pub(crate) const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Record the physical bytes the preparation wrote under this pin.
    pub(crate) const fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes = bytes;
        self
    }

    /// Carry the preparation's unsettled charge.
    pub(crate) fn charged(mut self, charge: Charge) -> Self {
        self.charge = Some(charge);
        self
    }

    pub(crate) const fn is_charged(&self) -> bool {
        self.charge.is_some()
    }

    /// Move the carried charge out, to be parked with the pin.
    pub(crate) const fn take_charge(&mut self) -> Option<Charge> {
        self.charge.take()
    }
}

impl Drop for Pin {
    fn drop(&mut self) {
        if let Ok(mut shard) = self.protection.shard(&self.allocation).lock() {
            match shard.pinned.get_mut(&self.allocation) {
                Some(count) if *count > 1 => *count -= 1,
                Some(_) => {
                    shard.pinned.remove(&self.allocation);
                }
                None => {}
            }
        } else {
            // The shard is fenced: nothing in it can be claimed again, so
            // the pin cannot authorize a deletion by leaking. Reported so
            // the operator knows the store needs reopening.
            tracing::error!(
                allocation = %self.allocation.hex(),
                "allocation protection shard poisoned; pin release recorded nowhere"
            );
        }
    }
}

/// Exclusive ownership of an allocation's deletion. Only its holder can
/// delete the allocation; dropping it without deleting releases the
/// claim.
pub struct ReclaimClaim {
    protection: Arc<Protection>,
    allocation: AllocationId,
}

impl ReclaimClaim {
    /// Delete the payload, its sidecar and its owner marker, then make the
    /// directory change durable. Returns the physical bytes that were
    /// present before deletion, measured on the payload and sidecar, or
    /// `None` when none of the files existed (the allocation was already
    /// reclaimed); a retry after a partial deletion measures only what
    /// remained. Consumes the claim on success; on failure the claim is
    /// returned for retry.
    pub(crate) fn delete(
        self,
        blob_root: &Path,
        fsync: bool,
    ) -> Result<Option<u64>, (Self, StoreError)> {
        match delete_files(blob_root, &self.allocation, fsync) {
            Ok(bytes) => {
                // Identities are never reused, so the completed claim can
                // be forgotten rather than retained forever.
                drop(self);
                Ok(bytes)
            }
            Err(error) => Err((self, error)),
        }
    }
}

impl Drop for ReclaimClaim {
    fn drop(&mut self) {
        if let Ok(mut shard) = self.protection.shard(&self.allocation).lock() {
            shard.claimed.remove(&self.allocation);
        } else {
            tracing::error!(
                allocation = %self.allocation.hex(),
                "allocation protection shard poisoned; claim release recorded nowhere"
            );
        }
    }
}

/// The sidecar is unlinked first, the payload second and the owner marker
/// last, so an interruption leaves files that `classify` still reports
/// and whose remaining evidence decides the same way: a payload without a
/// sidecar is an orphan, and a marker alone names an owner whose rows no
/// longer select the allocation. The reverse order would leave a sidecar
/// that no payload explains.
fn delete_files(
    blob_root: &Path,
    allocation: &AllocationId,
    fsync: bool,
) -> Result<Option<u64>, StoreError> {
    let payload = allocation_path(blob_root, allocation);
    let sidecar = chunk_list_path(blob_root, allocation);
    let marker = owner_path(blob_root, allocation);
    let mut present: Option<u64> = None;
    for target in [&sidecar, &payload] {
        match fs::metadata(target) {
            Ok(metadata) => {
                present = Some(present.unwrap_or(0).saturating_add(metadata.len()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
    }
    if present.is_none() {
        match fs::metadata(&marker) {
            Ok(_) => present = Some(0),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
    }
    let Some(bytes) = present else {
        return Ok(None);
    };
    for target in [&sidecar, &payload, &marker] {
        match fs::remove_file(target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::Io(error)),
        }
    }
    if fsync && let Some(parent) = payload.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(Some(bytes))
}

impl Protection {
    fn shard(&self, allocation: &AllocationId) -> &Mutex<Shard> {
        &self.shards[usize::from(allocation.0[0]) % LOCK_SHARDS]
    }

    fn lock(&self, allocation: &AllocationId) -> Result<MutexGuard<'_, Shard>, StoreError> {
        self.shard(allocation).lock().map_err(|_| {
            StoreError::Internal(format!(
                "allocation protection shard for {} is poisoned",
                allocation.hex()
            ))
        })
    }

    /// Pin `allocation`. Refused while reclamation holds its claim.
    pub(crate) fn pin(self: &Arc<Self>, allocation: AllocationId) -> Result<Pin, StoreError> {
        let mut shard = self.lock(&allocation)?;
        if shard.claimed.contains(&allocation) {
            return Err(StoreError::NotFound(format!(
                "allocation {} is being reclaimed",
                allocation.hex()
            )));
        }
        *shard.pinned.entry(allocation).or_insert(0) += 1;
        drop(shard);
        Ok(Pin {
            protection: Arc::clone(self),
            allocation,
            bytes: 0,
            charge: None,
        })
    }

    /// Pin a fresh identity and create its file exclusively. A collision
    /// releases the pin and draws another identity.
    pub(crate) fn create(self: &Arc<Self>, blob_root: &Path) -> Result<(Pin, File), StoreError> {
        for _ in 0..8 {
            let allocation = AllocationId::generate()?;
            let pin = self.pin(allocation)?;
            match private_create_new().open(allocation_path(blob_root, &allocation)) {
                Ok(file) => return Ok((pin, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => drop(pin),
                Err(error) => return Err(StoreError::Io(error)),
            }
        }
        Err(StoreError::Internal(
            "allocation identity collided eight times".into(),
        ))
    }

    /// Claim `allocation` for deletion: `None` while a pin or another
    /// claim is live.
    pub(crate) fn claim(
        self: &Arc<Self>,
        allocation: AllocationId,
    ) -> Result<Option<ReclaimClaim>, StoreError> {
        let mut shard = self.lock(&allocation)?;
        if shard.pinned.contains_key(&allocation) || !shard.claimed.insert(allocation) {
            return Ok(None);
        }
        drop(shard);
        Ok(Some(ReclaimClaim {
            protection: Arc::clone(self),
            allocation,
        }))
    }

    #[cfg(test)]
    pub(crate) fn is_pinned(&self, allocation: &AllocationId) -> Result<bool, StoreError> {
        Ok(self.lock(allocation)?.pinned.contains_key(allocation))
    }
}
