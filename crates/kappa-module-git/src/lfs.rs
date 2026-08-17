//! Git LFS batch API.
//!
//! LFS objects are stored as regular blobs via ingest_verified. The OID
//! is already a SHA-256 kappa-label. The batch API returns URLs pointing
//! to the blob GET/PUT endpoints. No separate LFS storage -- the
//! content-addressed store IS the LFS backend.
//!
//! Endpoints:
//!   POST /{repo}.git/info/lfs/objects/batch
//!   PUT  /{repo}.git/info/lfs/objects/{oid}
//!   GET  /{repo}.git/info/lfs/objects/{oid}
//!
//! Protocol-free: takes parsed request structs, returns response structs.
//! HTTP wiring is in kappa-server/src/main.rs.

use kappa_core::store::KappaStore;
use serde::{Deserialize, Serialize};

/// LFS batch request.
#[derive(Debug, Deserialize)]
pub struct BatchRequest {
    pub operation: String,
    pub objects: Vec<LfsObject>,
    #[serde(default)]
    pub transfers: Vec<String>,
    #[serde(default)]
    pub r#ref: Option<LfsRef>,
}

#[derive(Debug, Deserialize)]
pub struct LfsObject {
    pub oid: String,
    pub size: u64,
}

#[derive(Debug, Deserialize)]
pub struct LfsRef {
    pub name: String,
}

/// LFS batch response.
#[derive(Debug, Serialize)]
pub struct BatchResponse {
    pub transfer: String,
    pub objects: Vec<LfsObjectResponse>,
}

#[derive(Debug, Serialize)]
pub struct LfsObjectResponse {
    pub oid: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<LfsActions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<LfsError>,
}

#[derive(Debug, Serialize)]
pub struct LfsActions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<LfsAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload: Option<LfsAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<LfsAction>,
}

#[derive(Debug, Serialize)]
pub struct LfsAction {
    pub href: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LfsError {
    pub code: u16,
    pub message: String,
}

/// Process a batch request and return a batch response.
///
/// `base_url` is the server's external URL (e.g. "http://localhost:5000").
/// `repo` is the repository namespace.
pub fn process_batch(
    store: &dyn KappaStore,
    base_url: &str,
    repo: &str,
    request: &BatchRequest,
) -> BatchResponse {
    let mut objects = Vec::with_capacity(request.objects.len());

    for obj in &request.objects {
        let kappa = format!("sha256:{}", obj.oid);
        let exists = store.blob_exists(&kappa).unwrap_or(false);

        match request.operation.as_str() {
            "download" => {
                if exists {
                    objects.push(LfsObjectResponse {
                        oid: obj.oid.clone(),
                        size: obj.size,
                        actions: Some(LfsActions {
                            download: Some(LfsAction {
                                href: format!(
                                    "{}/v2/{}/blobs/sha256:{}",
                                    base_url, repo, obj.oid
                                ),
                                expires_at: None,
                            }),
                            upload: None,
                            verify: None,
                        }),
                        error: None,
                    });
                } else {
                    objects.push(LfsObjectResponse {
                        oid: obj.oid.clone(),
                        size: obj.size,
                        actions: None,
                        error: Some(LfsError {
                            code: 404,
                            message: "object not found".into(),
                        }),
                    });
                }
            }
            "upload" => {
                if exists {
                    // Already exists -- no action needed
                    objects.push(LfsObjectResponse {
                        oid: obj.oid.clone(),
                        size: obj.size,
                        actions: None,
                        error: None,
                    });
                } else {
                    objects.push(LfsObjectResponse {
                        oid: obj.oid.clone(),
                        size: obj.size,
                        actions: Some(LfsActions {
                            download: None,
                            upload: Some(LfsAction {
                                href: format!(
                                    "{}/v2/{}/blobs/sha256:{}",
                                    base_url, repo, obj.oid
                                ),
                                expires_at: None,
                            }),
                            verify: Some(LfsAction {
                                href: format!(
                                    "{}/{}.git/info/lfs/objects/verify",
                                    base_url, repo
                                ),
                                expires_at: None,
                            }),
                        }),
                        error: None,
                    });
                }
            }
            _ => {
                objects.push(LfsObjectResponse {
                    oid: obj.oid.clone(),
                    size: obj.size,
                    actions: None,
                    error: Some(LfsError {
                        code: 400,
                        message: format!("unsupported operation: {}", request.operation),
                    }),
                });
            }
        }
    }

    BatchResponse {
        transfer: "basic".into(),
        objects,
    }
}

/// Verify an LFS object exists and has the expected size.
pub fn verify_object(
    store: &dyn KappaStore,
    oid: &str,
    expected_size: u64,
) -> Result<(), LfsError> {
    let kappa = format!("sha256:{}", oid);
    let size = store.blob_size(&kappa).map_err(|_| LfsError {
        code: 404,
        message: "object not found".into(),
    })?;
    if size != expected_size {
        return Err(LfsError {
            code: 422,
            message: format!(
                "size mismatch: expected {}, actual {}",
                expected_size, size
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_core::clock::ntp_lamport::NtpLamportClock;
    use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
    use std::sync::Arc;

    fn test_store() -> (Arc<InMemoryStore>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let clock = Arc::new(NtpLamportClock::new());
        let store = InMemoryStore::new(
            MemoryStoreConfig::new(tmp.path().join("blobs")),
            clock,
        )
        .unwrap();
        (Arc::new(store), tmp)
    }

    #[test]
    fn batch_download_existing() {
        let (store, _tmp) = test_store();
        let content = b"lfs object content";
        let kappa = kappa_core::kappa::kappa_from_bytes(content);
        store.ingest_verified(&kappa, content).unwrap();
        let hex_oid = kappa.strip_prefix("sha256:").unwrap();

        let req = BatchRequest {
            operation: "download".into(),
            objects: vec![LfsObject {
                oid: hex_oid.to_string(),
                size: content.len() as u64,
            }],
            transfers: vec![],
            r#ref: None,
        };

        let resp = process_batch(&*store, "http://localhost:5000", "myrepo", &req);
        assert_eq!(resp.objects.len(), 1);
        assert!(resp.objects[0].actions.is_some());
        let download = resp.objects[0].actions.as_ref().unwrap().download.as_ref().unwrap();
        assert!(download.href.contains("sha256:"));
        assert!(resp.objects[0].error.is_none());
    }

    #[test]
    fn batch_download_missing() {
        let (store, _tmp) = test_store();
        let req = BatchRequest {
            operation: "download".into(),
            objects: vec![LfsObject {
                oid: "0".repeat(64),
                size: 100,
            }],
            transfers: vec![],
            r#ref: None,
        };

        let resp = process_batch(&*store, "http://localhost:5000", "myrepo", &req);
        assert_eq!(resp.objects.len(), 1);
        assert!(resp.objects[0].error.is_some());
        assert_eq!(resp.objects[0].error.as_ref().unwrap().code, 404);
    }

    #[test]
    fn batch_upload_new() {
        let (store, _tmp) = test_store();
        let req = BatchRequest {
            operation: "upload".into(),
            objects: vec![LfsObject {
                oid: "a".repeat(64),
                size: 1000,
            }],
            transfers: vec![],
            r#ref: None,
        };

        let resp = process_batch(&*store, "http://localhost:5000", "myrepo", &req);
        assert_eq!(resp.objects.len(), 1);
        let actions = resp.objects[0].actions.as_ref().unwrap();
        assert!(actions.upload.is_some());
        assert!(actions.verify.is_some());
    }

    #[test]
    fn batch_upload_existing_no_action() {
        let (store, _tmp) = test_store();
        let content = b"already exists";
        let kappa = kappa_core::kappa::kappa_from_bytes(content);
        store.ingest_verified(&kappa, content).unwrap();
        let hex_oid = kappa.strip_prefix("sha256:").unwrap();

        let req = BatchRequest {
            operation: "upload".into(),
            objects: vec![LfsObject {
                oid: hex_oid.to_string(),
                size: content.len() as u64,
            }],
            transfers: vec![],
            r#ref: None,
        };

        let resp = process_batch(&*store, "http://localhost:5000", "myrepo", &req);
        assert!(resp.objects[0].actions.is_none());
        assert!(resp.objects[0].error.is_none());
    }

    #[test]
    fn verify_existing_correct_size() {
        let (store, _tmp) = test_store();
        let content = b"verify me";
        let kappa = kappa_core::kappa::kappa_from_bytes(content);
        store.ingest_verified(&kappa, content).unwrap();
        let hex_oid = kappa.strip_prefix("sha256:").unwrap();

        assert!(verify_object(&*store, hex_oid, content.len() as u64).is_ok());
    }

    #[test]
    fn verify_wrong_size() {
        let (store, _tmp) = test_store();
        let content = b"verify me";
        let kappa = kappa_core::kappa::kappa_from_bytes(content);
        store.ingest_verified(&kappa, content).unwrap();
        let hex_oid = kappa.strip_prefix("sha256:").unwrap();

        let err = verify_object(&*store, hex_oid, 999).unwrap_err();
        assert_eq!(err.code, 422);
    }
}
