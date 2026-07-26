//! VRF key storage for AKD integration.
//!
//! The VRF key is per-node (not per-namespace). It lives in the keystore
//! alongside the signing keys. It NEVER rotates -- per akd
//! ecvrf/traits.rs:24-28: "VRF private key should change never;
//! highly recommended to back with a static cache that lives for the
//! life of the process."
//!
//! Rotating a VRF key invalidates every label in every namespace's
//! AKD tree and requires a full rebuild. This is a permanent
//! constraint of the ECVRF-EDWARDS25519-SHA512-TAI suite (0x03).

use std::path::Path;

use crate::store::fs::atomic_write;
use crate::store::StoreError;

/// VRF key material loaded from or generated into the keystore.
///
/// The key bytes are Ed25519 private key bytes (32 bytes), used
/// by akd's ECVRF implementation over Edwards25519.
#[derive(Clone)]
pub struct VrfKeyMaterial {
    key_bytes: Vec<u8>,
    pub_bytes: Vec<u8>,
}

impl VrfKeyMaterial {
    /// Load VRF key from disk, or generate if absent.
    ///
    /// Key files:
    /// - `{keys_dir}/vrf.key` (0o600) -- 32-byte Ed25519 private key
    /// - `{keys_dir}/vrf.pub` (0o644) -- 32-byte Ed25519 public key
    /// - `{keys_dir}/vrf.blake3` (0o600) -- BLAKE3(pub || key) integrity
    ///
    /// # Errors
    ///
    /// Returns `StoreError::Io` on filesystem failures or integrity
    /// check failure.
    pub fn load_or_generate(keys_dir: &Path) -> Result<Self, StoreError> {
        let vrf_key_path = keys_dir.join("vrf.key");
        let vrf_pub_path = keys_dir.join("vrf.pub");
        let vrf_blake3_path = keys_dir.join("vrf.blake3");

        if vrf_key_path.exists() {
            let key_bytes = std::fs::read(&vrf_key_path)?;
            let pub_bytes = std::fs::read(&vrf_pub_path)?;
            let stored_hash = std::fs::read(&vrf_blake3_path)?;

            let mut hasher = blake3::Hasher::new();
            hasher.update(&pub_bytes);
            hasher.update(&key_bytes);
            let computed = hasher.finalize();

            if stored_hash.len() != 32 || stored_hash[..] != computed.as_bytes()[..] {
                return Err(StoreError::Io(std::io::Error::other(
                    "VRF key integrity check failed",
                )));
            }

            Ok(Self {
                key_bytes,
                pub_bytes,
            })
        } else {
            std::fs::create_dir_all(keys_dir)?;

            use getrandom::rand_core::UnwrapErr;
            let signing_key =
                ed25519_dalek::SigningKey::generate(&mut UnwrapErr(getrandom::SysRng));
            let key_bytes = signing_key.to_bytes().to_vec();
            let pub_bytes = signing_key.verifying_key().to_bytes().to_vec();

            atomic_write(&vrf_key_path, &key_bytes)?;
            atomic_write(&vrf_pub_path, &pub_bytes)?;

            let mut hasher = blake3::Hasher::new();
            hasher.update(&pub_bytes);
            hasher.update(&key_bytes);
            let checksum = hasher.finalize();
            atomic_write(&vrf_blake3_path, checksum.as_bytes())?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&vrf_key_path, std::fs::Permissions::from_mode(0o600));
                let _ =
                    std::fs::set_permissions(&vrf_pub_path, std::fs::Permissions::from_mode(0o644));
                let _ = std::fs::set_permissions(
                    &vrf_blake3_path,
                    std::fs::Permissions::from_mode(0o600),
                );
            }

            Ok(Self {
                key_bytes,
                pub_bytes,
            })
        }
    }

    /// Raw private key bytes for VRF operations.
    pub fn key_bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    /// Raw public key bytes for VRF proof verification.
    pub fn pub_bytes(&self) -> &[u8] {
        &self.pub_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_creates_files() {
        let dir = TempDir::new().unwrap();
        let keys_dir = dir.path().join("keys");
        let vrf = VrfKeyMaterial::load_or_generate(&keys_dir).unwrap();
        assert_eq!(vrf.key_bytes().len(), 32);
        assert_eq!(vrf.pub_bytes().len(), 32);
        assert!(keys_dir.join("vrf.key").exists());
        assert!(keys_dir.join("vrf.pub").exists());
        assert!(keys_dir.join("vrf.blake3").exists());
    }

    #[test]
    fn load_after_generate_returns_same_key() {
        let dir = TempDir::new().unwrap();
        let keys_dir = dir.path().join("keys");
        let v1 = VrfKeyMaterial::load_or_generate(&keys_dir).unwrap();
        let v2 = VrfKeyMaterial::load_or_generate(&keys_dir).unwrap();
        assert_eq!(v1.key_bytes(), v2.key_bytes());
        assert_eq!(v1.pub_bytes(), v2.pub_bytes());
    }

    #[test]
    fn detects_tampered_key() {
        let dir = TempDir::new().unwrap();
        let keys_dir = dir.path().join("keys");
        VrfKeyMaterial::load_or_generate(&keys_dir).unwrap();
        std::fs::write(keys_dir.join("vrf.key"), vec![0u8; 32]).unwrap();
        let result = VrfKeyMaterial::load_or_generate(&keys_dir);
        assert!(result.is_err());
    }
}
