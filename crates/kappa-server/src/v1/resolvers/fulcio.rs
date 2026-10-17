use kappa_handler::{ExternalIdentifierResolver, ResolveError, ResolvedIdentity};
#[cfg(feature = "atproto")]
use kappa_store::kappa::Kappa;

pub struct FulcioResolver {
    client: reqwest::Client,
    rekor_url: String,
    ttl: u64,
}

impl FulcioResolver {
    pub fn new(rekor_url: &str, ttl: u64) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .connect_timeout(std::time::Duration::from_secs(5))
            .pool_max_idle_per_host(8)
            .build()?;
        Ok(Self {
            client,
            rekor_url: rekor_url.trim_end_matches('/').to_string(),
            ttl,
        })
    }

    fn is_fulcio_identifier(identifier: &str) -> bool {
        if identifier.starts_with("did:") || identifier.starts_with("at://") {
            return false;
        }
        let has_at = identifier.contains('@');
        let has_dot_after_at = identifier
            .split('@')
            .nth(1)
            .is_some_and(|d| d.contains('.'));
        let is_github = identifier.starts_with("https://github.com/");
        (has_at && has_dot_after_at) || is_github
    }
}

#[async_trait::async_trait]
impl ExternalIdentifierResolver for FulcioResolver {
    fn id_type(&self) -> &str {
        "fulcio"
    }

    fn accepts(&self, identifier: &str) -> bool {
        cfg!(feature = "atproto") && Self::is_fulcio_identifier(identifier)
    }

    async fn resolve(&self, identifier: &str) -> Result<Option<ResolvedIdentity>, ResolveError> {
        let search_url = format!("{}/api/v1/index/retrieve", self.rekor_url);
        let query = serde_json::json!({ "email": identifier });
        let resp = self
            .client
            .post(&search_url)
            .json(&query)
            .send()
            .await
            .map_err(|e| ResolveError::Network {
                resolver: "fulcio".into(),
                reason: format!("Rekor search {}: {}", search_url, e),
            })?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let uuids: Vec<String> = resp.json().await.map_err(|e| ResolveError::Parse {
            resolver: "fulcio".into(),
            reason: format!("Rekor search response: {}", e),
        })?;
        let Some(uuid) = uuids.first() else {
            return Ok(None);
        };

        let entry_url = format!("{}/api/v1/log/entries/{}", self.rekor_url, uuid);
        let entry_resp =
            self.client
                .get(&entry_url)
                .send()
                .await
                .map_err(|e| ResolveError::Network {
                    resolver: "fulcio".into(),
                    reason: format!("Rekor entry {}: {}", entry_url, e),
                })?;
        if !entry_resp.status().is_success() {
            return Ok(None);
        }

        #[cfg(feature = "atproto")]
        {
            let entry: serde_json::Value =
                entry_resp.json().await.map_err(|e| ResolveError::Parse {
                    resolver: "fulcio".into(),
                    reason: format!("Rekor entry JSON: {}", e),
                })?;

            let body_b64 = entry
                .as_object()
                .and_then(|m| m.values().next())
                .and_then(|v| v.get("body"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| ResolveError::Parse {
                    resolver: "fulcio".into(),
                    reason: "missing body in Rekor entry".into(),
                })?;

            let body_bytes = base64_simd::STANDARD
                .decode_to_vec(body_b64.as_bytes())
                .map_err(|e| ResolveError::Parse {
                    resolver: "fulcio".into(),
                    reason: format!("body base64: {}", e),
                })?;
            let body: serde_json::Value =
                serde_json::from_slice(&body_bytes).map_err(|e| ResolveError::Parse {
                    resolver: "fulcio".into(),
                    reason: format!("body JSON: {}", e),
                })?;

            let cert_b64 = body
                .get("spec")
                .and_then(|s| s.get("signature"))
                .and_then(|s| s.get("publicKey"))
                .and_then(|s| s.get("content"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| ResolveError::Parse {
                    resolver: "fulcio".into(),
                    reason: "missing certificate in Rekor entry".into(),
                })?;

            let cert_pem = base64_simd::STANDARD
                .decode_to_vec(cert_b64.as_bytes())
                .map_err(|e| ResolveError::Parse {
                    resolver: "fulcio".into(),
                    reason: format!("cert base64: {}", e),
                })?;

            use x509_parser::prelude::*;
            let pem_str = String::from_utf8_lossy(&cert_pem);
            let (_, pem) = parse_x509_pem(pem_str.as_bytes()).map_err(|e| ResolveError::Parse {
                resolver: "fulcio".into(),
                reason: format!("PEM parse: {}", e),
            })?;
            let (_, cert) =
                X509Certificate::from_der(&pem.contents).map_err(|e| ResolveError::Parse {
                    resolver: "fulcio".into(),
                    reason: format!("X509 parse: {}", e),
                })?;

            let spki = cert.public_key();
            let algorithm = match spki.algorithm.algorithm.to_id_string().as_str() {
                "1.2.840.10045.2.1" => "p256",
                "1.3.101.112" => "ed25519",
                "1.3.132.0.10" => "k256",
                oid => {
                    return Err(ResolveError::InvalidKey {
                        resolver: "fulcio".into(),
                        reason: format!("unsupported cert algorithm OID: {}", oid),
                    });
                }
            };

            let raw_key =
                extract_raw_key(algorithm, &spki.subject_public_key.data).map_err(|reason| {
                    ResolveError::InvalidKey {
                        resolver: "fulcio".into(),
                        reason,
                    }
                })?;

            let anchor =
                Kappa::from_key(algorithm, &raw_key).map_err(|error| ResolveError::InvalidKey {
                    resolver: "fulcio".into(),
                    reason: error.to_string(),
                })?;

            return Ok(Some(ResolvedIdentity {
                anchor,
                public_key: raw_key,
                algorithm: algorithm.into(),
                service_endpoint: None,
                handle: Some(identifier.to_string()),
                evidence: Some(cert_pem),
            }));
        }

        #[cfg(not(feature = "atproto"))]
        {
            let _ = entry_resp;
            Ok(None)
        }
    }

    fn cache_ttl_secs(&self) -> u64 {
        self.ttl
    }
}

#[cfg(feature = "atproto")]
fn extract_raw_key(algorithm: &str, spki_bytes: &[u8]) -> Result<Vec<u8>, String> {
    match algorithm {
        "ed25519" => {
            if spki_bytes.len() != 32 {
                return Err(format!(
                    "ed25519 SPKI key is {} bytes, expected 32",
                    spki_bytes.len(),
                ));
            }
            Ok(spki_bytes.to_vec())
        }
        "p256" | "k256" => {
            if spki_bytes.is_empty() {
                return Err("empty SPKI key bytes".into());
            }
            match spki_bytes[0] {
                0x02 | 0x03 if spki_bytes.len() == 33 => Ok(spki_bytes.to_vec()),
                0x04 if spki_bytes.len() == 65 => Ok(spki_bytes.to_vec()),
                prefix => Err(format!(
                    "unexpected EC point prefix 0x{:02x} with {} bytes",
                    prefix,
                    spki_bytes.len(),
                )),
            }
        }
        _ => Ok(spki_bytes.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_email() {
        assert!(FulcioResolver::is_fulcio_identifier("user@example.com"));
    }

    #[test]
    fn accepts_github_url() {
        assert!(FulcioResolver::is_fulcio_identifier(
            "https://github.com/octocat"
        ));
    }

    #[test]
    fn rejects_did() {
        assert!(!FulcioResolver::is_fulcio_identifier("did:plc:abc123"));
    }

    #[test]
    fn rejects_at_uri() {
        assert!(!FulcioResolver::is_fulcio_identifier(
            "at://alice.example.com"
        ));
    }

    #[test]
    fn rejects_bare_at_sign() {
        assert!(!FulcioResolver::is_fulcio_identifier("something@"));
    }

    #[test]
    fn rejects_at_without_dot() {
        assert!(!FulcioResolver::is_fulcio_identifier("user@localhost"));
    }

    #[test]
    fn rejects_empty() {
        assert!(!FulcioResolver::is_fulcio_identifier(""));
    }

    #[cfg(feature = "atproto")]
    #[test]
    fn extract_ed25519_raw_key() {
        let key = vec![0u8; 32];
        assert_eq!(extract_raw_key("ed25519", &key).unwrap().len(), 32);
    }

    #[cfg(feature = "atproto")]
    #[test]
    fn extract_ed25519_wrong_length() {
        let key = vec![0u8; 31];
        assert!(extract_raw_key("ed25519", &key).is_err());
    }

    #[cfg(feature = "atproto")]
    #[test]
    fn extract_p256_compressed() {
        let mut key = vec![0x02];
        key.extend_from_slice(&[0u8; 32]);
        assert_eq!(extract_raw_key("p256", &key).unwrap().len(), 33);
    }

    #[cfg(feature = "atproto")]
    #[test]
    fn extract_p256_uncompressed() {
        let mut key = vec![0x04];
        key.extend_from_slice(&[0u8; 64]);
        assert_eq!(extract_raw_key("p256", &key).unwrap().len(), 65);
    }

    #[cfg(feature = "atproto")]
    #[test]
    fn extract_p256_invalid_prefix() {
        let mut key = vec![0x05];
        key.extend_from_slice(&[0u8; 32]);
        assert!(extract_raw_key("p256", &key).is_err());
    }

    #[cfg(feature = "atproto")]
    #[test]
    fn extract_empty_spki() {
        assert!(extract_raw_key("p256", &[]).is_err());
    }
}
