//! Disk-backed upload session management with streaming digest verification.
//!
//! Each chunked upload session writes chunks to a staging file on disk.
//! At complete time, the staging file is verified via streaming digest
//! computation (16 KiB chunks through an incremental hasher), then
//! renamed to the blob path (zero-copy, atomic on same filesystem).
//!
//! SHA-1 uses sha1_checked with incremental update(). try_finalize()
//! returns Err on collision detection. Fail closed: reject the upload,
//! delete the staging file, never store the content.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use kappa_core::kappa::{blob_path_for, Sha1Policy};
use kappa_core::types::StoreError;

// -- UploadSession ------------------------------------------------------------

/// A single in-progress chunked upload.
///
/// staging_path is Option: take() transfers ownership to the complete
/// handler. Drop cleans up only if Some.
struct UploadSession {
    namespace: String,
    staging_path: Option<PathBuf>,
    offset: u64,
    created_at: Instant,
}

impl Drop for UploadSession {
    fn drop(&mut self) {
        if let Some(path) = &self.staging_path {
            let _ = fs::remove_file(path);
        }
    }
}

// -- SessionStore -------------------------------------------------------------

/// Manages all active upload sessions with disk-backed staging.
///
/// Startup scans staging/ and removes orphaned files from prior runs.
pub struct SessionStore {
    sessions: Mutex<HashMap<String, UploadSession>>,
    staging_root: PathBuf,
    max_upload_size: usize,
}

impl SessionStore {
    pub fn new(staging_root: PathBuf, max_upload_size: usize) -> Self {
        let _ = fs::create_dir_all(&staging_root);
        if let Ok(entries) = fs::read_dir(&staging_root) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        Self {
            sessions: Mutex::new(HashMap::new()),
            staging_root,
            max_upload_size,
        }
    }

    pub fn create(&self, namespace: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let staging_path = self.staging_root.join(&id);
        // Create the staging file immediately. An empty upload is valid
        // (OCI conformance: empty blob via chunked upload). The file
        // represents the upload's content from the moment the session
        // exists, even if that content is zero bytes.
        let _ = open_staging_append(&staging_path);
        let mut map = self.sessions.lock().unwrap();
        map.insert(
            id.clone(),
            UploadSession {
                namespace: namespace.to_string(),
                staging_path: Some(staging_path),
                offset: 0,
                created_at: Instant::now(),
            },
        );
        id
    }

    pub fn is_expired(&self, id: &str, timeout_secs: u64) -> bool {
        let map = self.sessions.lock().unwrap();
        map.get(id)
            .map(|s| s.created_at.elapsed().as_secs() > timeout_secs)
            .unwrap_or(true)
    }

    pub fn bytes_received(&self, id: &str) -> Option<u64> {
        self.sessions.lock().unwrap().get(id).map(|s| s.offset)
    }

    pub fn namespace_for(&self, id: &str) -> Option<String> {
        self.sessions
            .lock()
            .unwrap()
            .get(id)
            .map(|s| s.namespace.clone())
    }

    /// Append a chunk to the session's staging file.
    /// Validates sequential offset. Returns new total byte count.
    pub fn append(&self, id: &str, offset: u64, chunk: &[u8]) -> Result<u64, AppendError> {
        let mut map = self.sessions.lock().unwrap();
        let session = map.get_mut(id).ok_or(AppendError::NotFound)?;
        if offset != session.offset {
            return Err(AppendError::OutOfOrder {
                expected: session.offset,
                got: offset,
            });
        }
        if session.offset as usize + chunk.len() > self.max_upload_size {
            return Err(AppendError::SizeExceeded(self.max_upload_size));
        }
        let path = session.staging_path.as_ref().ok_or(AppendError::NotFound)?;
        let mut file = open_staging_append(path).map_err(AppendError::Io)?;
        file.write_all(chunk).map_err(AppendError::Io)?;
        session.offset += chunk.len() as u64;
        Ok(session.offset)
    }

    /// Take the staging path for the complete handler.
    /// Removes the session. The staging file is NOT deleted.
    /// If no chunks were sent (staging file does not exist on disk),
    /// creates an empty file so verify_staged_digest has something to hash.
    pub fn take(&self, id: &str) -> Option<(String, PathBuf)> {
        let mut map = self.sessions.lock().unwrap();
        let mut session = map.remove(id)?;
        let path = session.staging_path.take()?;
        let ns = session.namespace.clone();
        // Ensure the staging file exists (empty blob case: no chunks sent)
        if !path.exists() {
            let _ = open_staging_append(&path);
        }
        Some((ns, path))
    }

    pub fn remove(&self, id: &str) -> bool {
        self.sessions.lock().unwrap().remove(id).is_some()
    }

    pub fn evict_expired(&self, timeout_secs: u64) -> usize {
        let mut map = self.sessions.lock().unwrap();
        let before = map.len();
        map.retain(|_, s| s.created_at.elapsed().as_secs() <= timeout_secs);
        before - map.len()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new(std::env::temp_dir().join("kappa-uploads"), 256 * 1024 * 1024)
    }
}

// -- Staging file helpers -----------------------------------------------------

#[cfg(unix)]
fn open_staging_append(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_staging_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

// -- Streaming digest verification --------------------------------------------

/// Verify a staged file matches the expected digest by streaming
/// 16 KiB chunks through an incremental hasher. Does NOT load the
/// file into memory.
pub fn verify_staged_digest(
    staging_path: &Path,
    expected_digest: &str,
    sha1_policy: Sha1Policy,
) -> Result<VerifiedDigest, VerifyError> {
    let (algo, expected_hex) = expected_digest
        .split_once(':')
        .ok_or_else(|| VerifyError::BadDigest(expected_digest.to_owned()))?;

    if algo == "sha1" && sha1_policy == Sha1Policy::Deny {
        return Err(VerifyError::AlgorithmDenied(
            "sha1 denied by namespace policy".to_owned(),
        ));
    }

    let mut file = File::open(staging_path).map_err(VerifyError::Io)?;
    let mut buf = [0u8; 16384];

    let computed_hex = match algo {
        "sha256" => {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            loop {
                let n = file.read(&mut buf).map_err(VerifyError::Io)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            hex::encode(h.finalize())
        }
        "sha512" => {
            use sha2::{Digest, Sha512};
            let mut h = Sha512::new();
            loop {
                let n = file.read(&mut buf).map_err(VerifyError::Io)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            hex::encode(h.finalize())
        }
        "blake3" => {
            let mut h = blake3::Hasher::new();
            loop {
                let n = file.read(&mut buf).map_err(VerifyError::Io)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            h.finalize().to_hex().to_string()
        }
        "sha1" => {
            // sha1_checked wraps Marc Stevens' sha1collisiondetection.
            // Incremental update via the digest crate's Update trait.
            // try_finalize checks the collision flag accumulated across
            // all 64-byte blocks processed during update.
            use sha1_checked::Sha1;
            use sha1_checked::Digest as _;
            let mut h = Sha1::new();
            loop {
                let n = file.read(&mut buf).map_err(VerifyError::Io)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            let result = h.try_finalize();
            if result.has_collision() {
                return Err(VerifyError::Sha1Collision(expected_digest.to_owned()));
            }
            hex::encode(result.hash())
        }
        _ => {
            return Err(VerifyError::BadDigest(format!(
                "unsupported axis: {}",
                algo
            )));
        }
    };

    if computed_hex != expected_hex {
        return Err(VerifyError::Mismatch {
            expected: expected_digest.to_owned(),
            computed: format!("{}:{}", algo, computed_hex),
        });
    }

    let upgrade = if algo == "sha1" && sha1_policy == Sha1Policy::AllowWithSha256Upgrade {
        Some(compute_sha256_of_file(staging_path)?)
    } else {
        None
    };

    Ok(VerifiedDigest {
        primary: expected_digest.to_owned(),
        upgrade,
    })
}

fn compute_sha256_of_file(path: &Path) -> Result<String, VerifyError> {
    use sha2::{Digest, Sha256};
    let mut file = File::open(path).map_err(VerifyError::Io)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 16384];
    loop {
        let n = file.read(&mut buf).map_err(VerifyError::Io)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(h.finalize())))
}

/// Result of successful digest verification.
pub struct VerifiedDigest {
    pub primary: String,
    pub upgrade: Option<String>,
}

// -- Place blob ---------------------------------------------------------------

/// Place a verified staging file at the blob path via rename.
/// Returns true if newly placed, false if already existed.
pub fn place_blob(
    blob_root: &Path,
    staging_path: &Path,
    verified: &VerifiedDigest,
) -> Result<bool, StoreError> {
    let primary_path = blob_path_for(blob_root, &verified.primary)?;
    if let Some(parent) = primary_path.parent() {
        fs::create_dir_all(parent).map_err(StoreError::Io)?;
    }

    let newly_placed = if primary_path.exists() {
        fs::remove_file(staging_path).map_err(StoreError::Io)?;
        false
    } else {
        fs::rename(staging_path, &primary_path).map_err(StoreError::Io)?;
        true
    };

    if let Some(ref upgrade_kappa) = verified.upgrade {
        let upgrade_path = blob_path_for(blob_root, upgrade_kappa)?;
        if let Some(parent) = upgrade_path.parent() {
            fs::create_dir_all(parent).map_err(StoreError::Io)?;
        }
        if !upgrade_path.exists() {
            fs::hard_link(&primary_path, &upgrade_path).map_err(StoreError::Io)?;
        }
    }

    Ok(newly_placed)
}

// -- Errors -------------------------------------------------------------------

/// Error from appending a chunk to an upload session.
#[derive(Debug)]
pub enum AppendError {
    /// Session ID not found or staging path already taken.
    NotFound,
    /// Chunk offset does not match the expected next byte.
    OutOfOrder { expected: u64, got: u64 },
    /// Appending this chunk would exceed the maximum upload size.
    SizeExceeded(usize),
    /// Filesystem I/O error writing to the staging file.
    Io(io::Error),
}

impl std::fmt::Display for AppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "upload session not found"),
            Self::OutOfOrder { expected, got } => {
                write!(f, "out-of-order chunk: expected offset {expected}, got {got}")
            }
            Self::SizeExceeded(max) => write!(f, "upload exceeds max size {max}"),
            Self::Io(e) => write!(f, "staging I/O error: {e}"),
        }
    }
}

#[derive(Debug)]
pub enum VerifyError {
    Io(io::Error),
    BadDigest(String),
    Mismatch { expected: String, computed: String },
    Sha1Collision(String),
    AlgorithmDenied(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {}", e),
            Self::BadDigest(d) => write!(f, "bad digest: {}", d),
            Self::Mismatch { expected, computed } => {
                write!(f, "digest mismatch: expected {}, got {}", expected, computed)
            }
            Self::Sha1Collision(d) => write!(f, "SHA-1 collision attack detected: {}", d),
            Self::AlgorithmDenied(r) => write!(f, "algorithm denied: {}", r),
        }
    }
}
