use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::blob::BlobStore;
use serde::{Deserialize, Serialize};

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
pub fn process_batch<S: BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    base_url: &str,
    repo: &str,
    request: &BatchRequest,
) -> BatchResponse {
    let mut objects = Vec::with_capacity(request.objects.len());

    for obj in &request.objects {
        let kappa_str = format!("sha256:{}", obj.oid);
        let kappa = match Kappa::parse(&kappa_str) {
            Ok(k) => k,
            Err(_) => {
                objects.push(LfsObjectResponse {
                    oid: obj.oid.clone(),
                    size: obj.size,
                    actions: None,
                    error: Some(LfsError {
                        code: 422,
                        message: format!("invalid OID: {}", obj.oid),
                    }),
                });
                continue;
            }
        };
        let exists = store.blob_exists_in(namespace, &kappa).unwrap_or(false);

        match request.operation.as_str() {
            "download" => {
                if exists {
                    objects.push(LfsObjectResponse {
                        oid: obj.oid.clone(),
                        size: obj.size,
                        actions: Some(LfsActions {
                            download: Some(LfsAction {
                                href: format!("{}/v2/{}/blobs/sha256:{}", base_url, repo, obj.oid),
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
                                href: format!("{}/v2/{}/blobs/sha256:{}", base_url, repo, obj.oid),
                                expires_at: None,
                            }),
                            verify: Some(LfsAction {
                                href: format!("{}/{}.git/info/lfs/objects/verify", base_url, repo),
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
pub fn verify_object<S: BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    oid: &str,
    expected_size: u64,
) -> Result<(), LfsError> {
    let kappa_str = format!("sha256:{}", oid);
    let kappa = Kappa::parse(&kappa_str).map_err(|_| LfsError {
        code: 422,
        message: format!("invalid OID: {}", oid),
    })?;
    let size = store
        .blob_size_in(namespace, &kappa)
        .map_err(|_| LfsError {
            code: 404,
            message: "object not found".into(),
        })?;
    if size != expected_size {
        return Err(LfsError {
            code: 422,
            message: format!("size mismatch: expected {}, actual {}", expected_size, size),
        });
    }
    Ok(())
}
