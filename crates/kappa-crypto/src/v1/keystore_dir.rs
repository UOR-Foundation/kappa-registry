//! The key store's directory, owned through one retained descriptor.
//!
//! Opening establishes, in order: the directory exists (created owner-only,
//! and its name made durable in its parent); its final path component is
//! not a symlink; it is a directory owned by this process's effective user,
//! with group and other access removed; then an exclusive advisory lock on
//! `.lock`, itself a regular single-link file owned by that user. Only then
//! are orphaned staging files from an interrupted publication removed.
//!
//! Every later operation is relative to the retained descriptor, so the
//! directory the store operates on cannot be exchanged by renaming or
//! replacing its path. Entries inside it remain mutable by the owning user;
//! the lock coordinates cooperating owners and does not stop a process that
//! ignores it. Opens never follow a symlink in the final component. Parent
//! components of the path are resolved once, at open.
//!
//! Durability: a published name is acknowledged only after the file was
//! synchronized before linking or renaming and the directory was
//! synchronized after. On Linux `fsync` on the file and on the directory is
//! the persistence contract this relies on; platforms that need stronger
//! barriers (Apple's `F_FULLFSYNC`) are not supported by this module.

use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags};
use zeroize::Zeroizing;

use crate::CryptoError;

/// Prefix of every staging file this module creates.
const STAGE_PREFIX: &str = ".stage-";
/// Lowercase hexadecimal digits after the staging prefix.
const STAGE_DIGITS: usize = 32;
const LOCK: &str = ".lock";

/// Points at which tests inject a failure or abort the process. Outside
/// tests every point is inert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    /// Before staged bytes are written.
    StageWrite,
    /// Before a staged file is linked to its final name.
    Link,
    /// After a link succeeded, before the caller learns of it.
    LinkUnacknowledged,
    /// Before a staged file is renamed over its final name.
    Rename,
    /// After a rename succeeded, before the caller learns of it.
    RenameUnacknowledged,
    /// Before a directory synchronization.
    DirSync,
    /// Before an entry is unlinked.
    Unlink,
}

/// Outcome of best-effort removal that follows an operation which already
/// succeeded. A failure here never replaces the operation's own result.
pub(super) type Cleanup = Result<(), CryptoError>;

/// `Ok(())`, or the failure a test armed at `$point` on `$dir`. Outside
/// tests the point is evaluated and discarded, so production code carries
/// no injection state.
macro_rules! fault {
    ($dir:expr, $point:expr) => {{
        #[cfg(test)]
        {
            $dir.inject($point)
        }
        #[cfg(not(test))]
        {
            let _ = ($dir, $point);
            Ok::<(), io::Error>(())
        }
    }};
}

fn io(error: rustix::io::Errno) -> io::Error {
    io::Error::from(error)
}

/// `primary`, with a failed cleanup recorded after it. The primary error's
/// kind and message come first.
fn with_cleanup(primary: io::Error, cleanup: Cleanup) -> CryptoError {
    match cleanup {
        Ok(()) => primary.into(),
        Err(cleanup) => io::Error::new(
            primary.kind(),
            format!("{primary} (staging cleanup also failed: {cleanup})"),
        )
        .into(),
    }
}

fn denied(reason: &str) -> CryptoError {
    io::Error::new(io::ErrorKind::PermissionDenied, reason.to_owned()).into()
}

fn effective_user() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// A staging name this module could have created: the prefix and exactly
/// 32 lowercase hexadecimal digits.
pub(super) fn is_stage_name(name: &[u8]) -> bool {
    name.strip_prefix(STAGE_PREFIX.as_bytes())
        .is_some_and(|digits| {
            digits.len() == STAGE_DIGITS
                && digits
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        })
}

pub(super) struct KeyDir {
    dir: OwnedFd,
    /// Holds the exclusive lock until the store drops.
    _lock: OwnedFd,
    #[cfg(test)]
    faults: std::sync::Mutex<Vec<Armed>>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct Armed {
    point: Fault,
    /// Hits of `point` to let pass before acting.
    skip: usize,
    abort: bool,
}

impl KeyDir {
    pub fn open(path: &Path) -> Result<Self, CryptoError> {
        let existed = path.exists();
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        if !existed {
            // The new directory's name lives in its parent.
            let parent = match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => Path::new("."),
            };
            fs::File::open(parent)?.sync_all()?;
        }
        let dir = rustix::fs::openat(
            rustix::fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io)?;
        let stat = rustix::fs::fstat(&dir).map_err(io)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(denied("key store path is not a directory"));
        }
        if stat.st_uid != effective_user() {
            return Err(denied(
                "key store directory is not owned by the process's effective user",
            ));
        }
        if Mode::from_raw_mode(stat.st_mode).intersects(Mode::RWXG | Mode::RWXO) {
            rustix::fs::fchmod(&dir, Mode::RWXU).map_err(io)?;
        }
        let lock = rustix::fs::openat(
            &dir,
            LOCK,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io)?;
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                CryptoError::Io(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "key store is owned by another process or handle",
                ))
            } else {
                CryptoError::Io(io(error))
            }
        })?;
        let lock_stat = rustix::fs::fstat(&lock).map_err(io)?;
        if FileType::from_raw_mode(lock_stat.st_mode) != FileType::RegularFile
            || lock_stat.st_uid != effective_user()
            || lock_stat.st_nlink != 1
        {
            return Err(denied(
                "key store lock is not a single-link regular file owned by this user",
            ));
        }
        let store = Self {
            dir,
            _lock: lock,
            #[cfg(test)]
            faults: std::sync::Mutex::new(Vec::new()),
        };
        store.sync()?;
        store.recover_stages()?;
        Ok(store)
    }

    /// Fail, or abort the process, at `point` when a test armed it.
    #[cfg(test)]
    fn inject(&self, point: Fault) -> io::Result<()> {
        let mut armed = self
            .faults
            .lock()
            .map_err(|_| io::Error::other("fault table poisoned"))?;
        let Some(index) = armed.iter().position(|entry| entry.point == point) else {
            return Ok(());
        };
        if armed[index].skip > 0 {
            armed[index].skip -= 1;
            return Ok(());
        }
        let entry = armed.remove(index);
        drop(armed);
        if entry.abort {
            std::process::abort();
        }
        Err(io::Error::other(format!("injected fault at {point:?}")))
    }

    /// Fail the `skip + 1`th time `point` is reached.
    #[cfg(test)]
    pub fn arm(&self, point: Fault, skip: usize) {
        self.arm_entry(Armed {
            point,
            skip,
            abort: false,
        });
    }

    /// Abort the process the `skip + 1`th time `point` is reached.
    #[cfg(test)]
    pub fn arm_abort(&self, point: Fault, skip: usize) {
        self.arm_entry(Armed {
            point,
            skip,
            abort: true,
        });
    }

    #[cfg(test)]
    fn arm_entry(&self, entry: Armed) {
        if let Ok(mut armed) = self.faults.lock() {
            armed.push(entry);
        }
    }

    /// Synchronize the directory, making its entries durable.
    pub fn sync(&self) -> Result<(), CryptoError> {
        fault!(self, Fault::DirSync)?;
        rustix::fs::fsync(&self.dir).map_err(io)?;
        Ok(())
    }

    /// Open `name` for reading: a regular file, not a symlink, owned by
    /// this user and inaccessible to group and other. `None` when absent.
    fn open_owned(&self, name: &str) -> Result<Option<fs::File>, CryptoError> {
        let fd = match rustix::fs::openat(
            &self.dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(rustix::io::Errno::LOOP) => {
                return Err(CryptoError::IntegrityFailure {
                    path: name.to_owned(),
                    reason: "entry is a symlink".into(),
                });
            }
            Err(error) => return Err(io(error).into()),
        };
        let stat = rustix::fs::fstat(&fd).map_err(io)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != effective_user()
            || Mode::from_raw_mode(stat.st_mode).intersects(Mode::RWXG | Mode::RWXO)
        {
            return Err(CryptoError::IntegrityFailure {
                path: name.to_owned(),
                reason: "entry is not an owner-only regular file of this user".into(),
            });
        }
        Ok(Some(fs::File::from(fd)))
    }

    /// The contents of `name`, at most `max` bytes; `None` when absent.
    pub fn read(&self, name: &str, max: u64) -> Result<Option<Zeroizing<Vec<u8>>>, CryptoError> {
        let Some(file) = self.open_owned(name)? else {
            return Ok(None);
        };
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(max + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > max {
            return Err(CryptoError::IntegrityFailure {
                path: name.to_owned(),
                reason: "entry exceeds its size bound".into(),
            });
        }
        Ok(Some(bytes))
    }

    /// Re-establish durability of `name`'s contents and of the directory
    /// entry naming it.
    pub fn confirm(&self, name: &str) -> Result<(), CryptoError> {
        let file = self
            .open_owned(name)?
            .ok_or_else(|| CryptoError::IntegrityFailure {
                path: name.to_owned(),
                reason: "entry to confirm is missing".into(),
            })?;
        file.sync_all()?;
        self.sync()
    }

    /// A fresh owner-only staging file holding `bytes`, synchronized.
    fn stage(&self, bytes: &[u8]) -> Result<String, CryptoError> {
        let mut nonce = [0u8; STAGE_DIGITS / 2];
        getrandom::fill(&mut nonce).map_err(|error| {
            CryptoError::Io(io::Error::other(format!("staging name entropy: {error}")))
        })?;
        let name = format!("{STAGE_PREFIX}{}", hex::encode(nonce));
        let fd = rustix::fs::openat(
            &self.dir,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io)?;
        let mut file = fs::File::from(fd);
        let written = fault!(self, Fault::StageWrite)
            .and_then(|()| file.write_all(bytes))
            .and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = written {
            return Err(with_cleanup(error, self.remove(&name)));
        }
        Ok(name)
    }

    /// Whether `a` and `b` name the same inode, neither followed.
    fn same_file(&self, a: &str, b: &str) -> Result<bool, CryptoError> {
        let stat = |name: &str| match rustix::fs::statat(&self.dir, name, AtFlags::SYMLINK_NOFOLLOW)
        {
            Ok(stat) => Ok(Some((stat.st_dev, stat.st_ino))),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(error) => Err(CryptoError::Io(io(error))),
        };
        Ok(matches!((stat(a)?, stat(b)?), (Some(x), Some(y)) if x == y))
    }

    /// Whether `name` exists, not followed.
    fn exists(&self, name: &str) -> Result<bool, CryptoError> {
        match rustix::fs::statat(&self.dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(error) => Err(io(error).into()),
        }
    }

    /// Publish `bytes` as `file` only if no entry of that name exists.
    ///
    /// `Ok` means `file` holds `bytes` durably. A link whose success was not
    /// reported is detected by inode identity and completed. The returned
    /// [`Cleanup`] reports removal of the staging file, which never changes
    /// the publication outcome; a leftover stage is removed at next open.
    pub fn publish_new(&self, file: &str, bytes: &[u8]) -> Result<Cleanup, CryptoError> {
        let stage = self.stage(bytes)?;
        let linked = fault!(self, Fault::Link)
            .and_then(|()| {
                rustix::fs::linkat(&self.dir, stage.as_str(), &self.dir, file, AtFlags::empty())
                    .map_err(io)
            })
            .and_then(|()| fault!(self, Fault::LinkUnacknowledged));
        if let Err(error) = linked {
            match self.same_file(&stage, file) {
                Ok(true) => {}
                Ok(false) => return Err(with_cleanup(error, self.remove(&stage))),
                Err(probe) => {
                    return Err(with_cleanup(
                        io::Error::new(
                            error.kind(),
                            format!("{error}; publication outcome unknown: {probe}"),
                        ),
                        self.remove(&stage),
                    ));
                }
            }
        }
        if let Err(error) = self.sync() {
            // The record exists but is not confirmed durable; a caller that
            // retries confirms it instead of relinking.
            let cleanup = self.remove(&stage);
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => CryptoError::Io(io::Error::other(format!(
                    "{error} (staging cleanup also failed: {cleanup})"
                ))),
            });
        }
        Ok(self.remove(&stage))
    }

    /// Publish `bytes` as `file`, replacing any previous entry in one
    /// rename, and make the replacement durable. A rename whose success was
    /// not reported is detected by the staging file's absence and completed.
    pub fn publish_replace(&self, file: &str, bytes: &[u8]) -> Result<(), CryptoError> {
        let stage = self.stage(bytes)?;
        let renamed = fault!(self, Fault::Rename)
            .and_then(|()| {
                rustix::fs::renameat(&self.dir, stage.as_str(), &self.dir, file).map_err(io)
            })
            .and_then(|()| fault!(self, Fault::RenameUnacknowledged));
        if let Err(error) = renamed {
            match self.exists(&stage) {
                Ok(false) => {}
                Ok(true) => return Err(with_cleanup(error, self.remove(&stage))),
                Err(probe) => {
                    return Err(with_cleanup(
                        io::Error::new(
                            error.kind(),
                            format!("{error}; replacement outcome unknown: {probe}"),
                        ),
                        self.remove(&stage),
                    ));
                }
            }
        }
        self.sync()
    }

    /// Remove `name` if present and make the removal durable.
    pub fn remove(&self, name: &str) -> Result<(), CryptoError> {
        self.remove_raw(name)?;
        self.sync()
    }

    /// Unlink `name` without synchronizing; absence is success.
    fn remove_raw<P: rustix::path::Arg>(&self, name: P) -> Result<(), CryptoError> {
        fault!(self, Fault::Unlink)?;
        match rustix::fs::unlinkat(&self.dir, name, AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(error) => Err(io(error).into()),
        }
    }

    /// Remove every entry in `names` and synchronize once. Every removal is
    /// attempted; the first failure is returned with the count of others.
    pub fn remove_all(&self, names: &[CString]) -> Result<(), CryptoError> {
        let mut first = None;
        let mut failed = 0usize;
        for name in names {
            if let Err(error) = self.remove_raw(name.as_c_str()) {
                failed += 1;
                first.get_or_insert(error);
            }
        }
        let synced = self.sync();
        match first {
            Some(error) => Err(CryptoError::Io(io::Error::other(format!(
                "{error} ({} of {} removals failed)",
                failed,
                names.len()
            )))),
            None => synced,
        }
    }

    /// Names of every entry in the directory, read through the retained
    /// descriptor. An enumeration failure is an error, never a short list.
    pub fn entries(&self) -> Result<Vec<CString>, CryptoError> {
        let mut names = Vec::new();
        for entry in rustix::fs::Dir::read_from(&self.dir).map_err(io)? {
            let entry = entry.map_err(io)?;
            let name: &CStr = entry.file_name();
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                names.push(name.to_owned());
            }
        }
        Ok(names)
    }

    /// Remove staging files left by an interrupted publication. Only names
    /// this module could have created are touched; they hold no published
    /// state, and may hold a private key.
    fn recover_stages(&self) -> Result<(), CryptoError> {
        let orphans: Vec<CString> = self
            .entries()?
            .into_iter()
            .filter(|name| is_stage_name(name.to_bytes()))
            .collect();
        if orphans.is_empty() {
            return Ok(());
        }
        self.remove_all(&orphans)
    }
}
