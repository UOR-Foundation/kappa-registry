use super::*;
use std::sync::{Arc, mpsc};

#[test]
fn erasure_waits_for_admitted_delivery_and_revokes_later_delivery()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let owner = Arc::new(BlobEncryption::new(
        FileKms::new([53; 32], directory.path().join("erased"))?,
        None,
    )?);
    let (admitted, admission) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let reader_owner = Arc::clone(&owner);
    let reader = std::thread::spawn(move || -> Result<i32, StoreError> {
        reader_owner.while_active(|| -> Result<i32, StoreError> {
            admitted
                .send(())
                .map_err(|error| StoreError::Internal(error.to_string()))?;
            released
                .recv()
                .map_err(|error| StoreError::Internal(error.to_string()))?;
            Ok(41)
        })?
    });
    admission.recv()?;
    assert!(
        owner.cipher.try_write().is_err(),
        "erasure cannot overlap admitted delivery"
    );
    let eraser_owner = Arc::clone(&owner);
    let eraser = std::thread::spawn(move || eraser_owner.erase());
    release.send(())?;
    assert_eq!(reader.join().map_err(|_| "reader panicked")??, 41);
    eraser.join().map_err(|_| "eraser panicked")??;
    assert!(
        owner
            .while_active(|| panic!("revoked callback executed"))
            .is_err()
    );
    assert!(owner.encrypt("context", b"content").is_err());
    Ok(())
}

#[test]
fn failed_durable_erasure_revokes_cached_keys_and_can_be_retried()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("erased");
    let owner = BlobEncryption::new(FileKms::new([59; 32], path.clone())?, None)?;
    let stored = owner.encrypt("context", b"content")?;
    std::fs::remove_dir(&path)?;
    std::fs::write(&path, b"storage failure")?;
    assert!(owner.erase().is_err());
    let guard = owner
        .cipher
        .read()
        .map_err(|_| "encryption ownership poisoned")?;
    assert!(guard.is_none());
    drop(guard);
    assert!(owner.decrypt("context", &stored).is_err());
    std::fs::remove_file(&path)?;
    std::fs::create_dir(&path)?;
    owner.erase()?;
    assert!(
        owner
            .kms
            .derive_subject_key("_default", "_blob_encryption")
            .is_err()
    );
    Ok(())
}

/// A domain that outlives every other holder of its filesystem scope keeps
/// the scope, so later checks distinguish erasure from a vanished
/// directory; the scope goes only with the domain itself.
#[test]
fn domain_retains_its_scope_and_still_honors_erasure() -> Result<(), Box<dyn std::error::Error>> {
    let scope = Arc::new(tempfile::tempdir()?);
    let root = scope.path().to_path_buf();
    let domain = BlobEncryption::new(
        FileKms::new([61; 32], root.join("erased"))?,
        Some(scope.clone()),
    )?;
    drop(scope);
    assert!(
        root.join("erased").is_dir(),
        "scope released while retained"
    );
    let stored = domain.encrypt("context", b"retained")?;
    assert_eq!(domain.decrypt("context", &stored)?, b"retained");
    domain.erase()?;
    assert!(matches!(
        domain.decrypt("context", &stored),
        Err(StoreError::Rejected(_))
    ));
    drop(domain);
    assert!(!root.exists(), "scope outlived its last holder");
    Ok(())
}
