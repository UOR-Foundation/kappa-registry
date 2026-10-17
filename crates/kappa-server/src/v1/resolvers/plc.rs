use kappa_handler::{ExternalIdentifierResolver, ResolveError, ResolvedIdentity};
use kappa_store::kappa::Kappa;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PlcError {
    #[error("invalid did:key format: {did_key}")]
    InvalidDidKey { did_key: String },

    #[error("did:key decoded bytes too short: {len} bytes")]
    DidKeyTooShort { len: usize },

    #[error("unknown multicodec code: 0x{code:x} (raw bytes 0x{hi:02x}{lo:02x})")]
    UnknownMulticodec { code: u64, hi: u8, lo: u8 },

    #[error("{algorithm} key too short: {len} bytes, expected {expected}")]
    KeyTooShort {
        algorithm: String,
        len: usize,
        expected: usize,
    },

    #[error("invalid compressed point prefix byte: 0x{byte:02x}")]
    InvalidPointPrefix { byte: u8 },

    #[error("base58 decode failed: {reason}")]
    Base58Decode { reason: String },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlcDocument {
    #[serde(default)]
    verification_methods: Option<serde_json::Value>,
    #[serde(default)]
    also_known_as: Option<Vec<String>>,
    #[serde(default)]
    service: Option<Vec<PlcService>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlcService {
    id: String,
    #[serde(default)]
    service_endpoint: Option<String>,
}

pub struct PlcResolver {
    client: reqwest::Client,
    directory_url: String,
    ttl: u64,
}

impl PlcResolver {
    pub fn new(directory_url: &str, ttl: u64) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .connect_timeout(std::time::Duration::from_secs(3))
            .pool_max_idle_per_host(8)
            .build()?;
        Ok(Self {
            client,
            directory_url: directory_url.trim_end_matches('/').to_string(),
            ttl,
        })
    }

    fn extract_did_key(doc: &PlcDocument) -> Option<String> {
        doc.verification_methods
            .as_ref()?
            .as_object()?
            .get("atproto")?
            .as_str()
            .map(|s| s.to_string())
    }

    fn extract_handle(doc: &PlcDocument) -> Option<String> {
        doc.also_known_as
            .as_ref()?
            .iter()
            .find_map(|uri| uri.strip_prefix("at://").map(|s| s.to_string()))
    }

    fn extract_endpoint(doc: &PlcDocument) -> Option<String> {
        doc.service.as_ref()?.iter().find_map(|svc| {
            if svc.id == "#atproto_pds" {
                svc.service_endpoint.clone()
            } else {
                None
            }
        })
    }
}

#[async_trait::async_trait]
impl ExternalIdentifierResolver for PlcResolver {
    fn id_type(&self) -> &str {
        "plc"
    }

    fn accepts(&self, identifier: &str) -> bool {
        identifier.starts_with("did:plc:")
    }

    async fn resolve(&self, identifier: &str) -> Result<Option<ResolvedIdentity>, ResolveError> {
        let url = format!("{}/{}", self.directory_url, identifier);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ResolveError::Network {
                resolver: "plc".into(),
                reason: format!("{}: {}", url, e),
            })?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(ResolveError::Network {
                resolver: "plc".into(),
                reason: format!("HTTP {} for {}", resp.status(), identifier),
            });
        }

        let doc: PlcDocument = resp.json().await.map_err(|e| ResolveError::Parse {
            resolver: "plc".into(),
            reason: format!("{}: {}", identifier, e),
        })?;

        let did_key = match Self::extract_did_key(&doc) {
            Some(k) => k,
            None => return Ok(None),
        };

        let (algorithm, pubkey) =
            decode_did_key(&did_key).map_err(|e| ResolveError::InvalidKey {
                resolver: "plc".into(),
                reason: format!("{}: {}", identifier, e),
            })?;

        validate_public_key(&algorithm, &pubkey).map_err(|e| ResolveError::InvalidKey {
            resolver: "plc".into(),
            reason: format!("{}: {}", identifier, e),
        })?;

        let anchor =
            Kappa::from_key(&algorithm, &pubkey).map_err(|error| ResolveError::InvalidKey {
                resolver: "plc".into(),
                reason: error.to_string(),
            })?;

        let evidence = serde_json::to_vec(&doc).map_err(|e| ResolveError::Internal {
            resolver: "plc".into(),
            reason: format!("evidence serialization: {}", e),
        })?;

        Ok(Some(ResolvedIdentity {
            anchor,
            public_key: pubkey,
            algorithm,
            service_endpoint: Self::extract_endpoint(&doc),
            handle: Self::extract_handle(&doc),
            evidence: Some(evidence),
        }))
    }

    fn cache_ttl_secs(&self) -> u64 {
        self.ttl
    }
}

/// Multicodec code to (algorithm_name, expected_key_length) mapping.
///
/// Codes are the decoded unsigned-varint values from the multiformats
/// table.csv `key` rows, not the raw prefix bytes: ed25519-pub is 0xed,
/// encoded on the wire as 0xed 0x01.
fn multicodec_to_algorithm(code: u64) -> Option<(&'static str, usize)> {
    match code {
        0xe7 => Some(("k256", 33)),    // secp256k1-pub, compressed SEC1
        0xed => Some(("ed25519", 32)), // ed25519-pub
        0x1200 => Some(("p256", 33)),  // p256-pub, compressed SEC1
        0x1203 => Some(("ed448", 57)), // ed448-pub
        0x1205 => Some(("rsa", 0)),    // rsa-pub, DER RSAPublicKey, variable length
        _ => None,
    }
}

/// Decode a did:key to (algorithm, raw_public_key_bytes).
///
/// Uses unsigned varint decoding for the multicodec prefix so any
/// future key type works without changing the decoder -- only the
/// multicodec_to_algorithm table needs a new entry.
fn decode_did_key(did_key: &str) -> Result<(String, Vec<u8>), PlcError> {
    let z_part = did_key
        .strip_prefix("did:key:z")
        .ok_or_else(|| PlcError::InvalidDidKey {
            did_key: did_key.to_string(),
        })?;

    let decoded = bs58::decode(z_part)
        .into_vec()
        .map_err(|e| PlcError::Base58Decode {
            reason: e.to_string(),
        })?;

    if decoded.len() < 2 {
        return Err(PlcError::DidKeyTooShort { len: decoded.len() });
    }

    // Decode unsigned varint multicodec prefix
    let (code, remaining) =
        unsigned_varint::decode::u64(&decoded).map_err(|e| PlcError::InvalidDidKey {
            did_key: format!("varint decode failed: {:?}", e),
        })?;

    let (algorithm, expected_len) =
        multicodec_to_algorithm(code).ok_or_else(|| PlcError::UnknownMulticodec {
            code,
            hi: decoded[0],
            lo: decoded.get(1).copied().unwrap_or(0),
        })?;

    // Variable-length keys (RSA): take all remaining bytes
    let key = if expected_len == 0 {
        remaining.to_vec()
    } else {
        if remaining.len() < expected_len {
            return Err(PlcError::KeyTooShort {
                algorithm: algorithm.into(),
                len: remaining.len(),
                expected: expected_len,
            });
        }
        remaining[..expected_len].to_vec()
    };

    Ok((algorithm.into(), key))
}

/// Validate that a decoded public key has the correct format for its algorithm.
fn validate_public_key(algorithm: &str, key: &[u8]) -> Result<(), PlcError> {
    match algorithm {
        "p256" | "k256" => {
            if key.is_empty() {
                return Err(PlcError::InvalidPointPrefix { byte: 0 });
            }
            match key[0] {
                0x02..=0x04 => Ok(()),
                other => Err(PlcError::InvalidPointPrefix { byte: other }),
            }
        }
        "ed25519" => {
            if key.len() != 32 {
                return Err(PlcError::KeyTooShort {
                    algorithm: "ed25519".into(),
                    len: key.len(),
                    expected: 32,
                });
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did_key(prefix: &[u8], key: &[u8]) -> String {
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(key);
        format!("did:key:z{}", bs58::encode(&bytes).into_string())
    }

    #[test]
    fn decode_ed25519_did_key() -> Result<(), PlcError> {
        let (algo, key) =
            decode_did_key("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")?;
        assert_eq!(algo, "ed25519");
        assert_eq!(key.len(), 32);
        Ok(())
    }

    #[test]
    fn decode_secp256k1_did_key() -> Result<(), PlcError> {
        // secp256k1-pub 0xe7 as varint: 0xe7 0x01.
        let (algo, key) = decode_did_key(&did_key(&[0xe7, 0x01], &[0x02; 33]))?;
        assert_eq!(algo, "k256");
        assert_eq!(key, [0x02; 33]);
        Ok(())
    }

    #[test]
    fn decode_rejects_invalid_prefix() {
        let result = decode_did_key("not-a-did-key");
        match result {
            Err(PlcError::InvalidDidKey { did_key }) => {
                assert_eq!(did_key, "not-a-did-key");
            }
            other => panic!("expected InvalidDidKey, got {:?}", other),
        }
    }

    #[test]
    fn decode_rejects_empty_after_z() {
        let result = decode_did_key("did:key:z");
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_unknown_multicodec() {
        // x25519-pub 0xec is a valid key codec this resolver does not accept.
        let result = decode_did_key(&did_key(&[0xec, 0x01], &[0u8; 32]));
        assert!(
            matches!(
                result,
                Err(PlcError::UnknownMulticodec {
                    code: 0xec,
                    hi: 0xec,
                    lo: 0x01
                })
            ),
            "expected UnknownMulticodec 0xec, got {result:?}"
        );
    }

    #[test]
    fn validate_p256_prefix_bytes() {
        assert!(validate_public_key("p256", &[0x02; 33]).is_ok());
        assert!(validate_public_key("p256", &[0x03; 33]).is_ok());
        assert!(validate_public_key("p256", &[0x04; 65]).is_ok());
        assert!(validate_public_key("p256", &[0x05; 33]).is_err());
        assert!(validate_public_key("p256", &[]).is_err());
    }

    #[test]
    fn validate_ed25519_length() {
        assert!(validate_public_key("ed25519", &[0u8; 32]).is_ok());
        assert!(validate_public_key("ed25519", &[0u8; 31]).is_err());
        assert!(validate_public_key("ed25519", &[0u8; 33]).is_err());
    }

    #[test]
    fn validate_k256_prefix_bytes() {
        assert!(validate_public_key("k256", &[0x02; 33]).is_ok());
        assert!(validate_public_key("k256", &[0x03; 33]).is_ok());
        assert!(validate_public_key("k256", &[0x05; 33]).is_err());
    }

    #[test]
    fn plc_document_typed_deserialization() {
        let json = r##"{
            "verificationMethods": {"atproto": "did:key:zABC"},
            "alsoKnownAs": ["at://alice.example.com"],
            "service": [{"id": "#atproto_pds", "serviceEndpoint": "https://pds.example.com"}]
        }"##;
        let doc: PlcDocument = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            PlcResolver::extract_did_key(&doc).as_deref(),
            Some("did:key:zABC"),
        );
        assert_eq!(
            PlcResolver::extract_handle(&doc).as_deref(),
            Some("alice.example.com"),
        );
        assert_eq!(
            PlcResolver::extract_endpoint(&doc).as_deref(),
            Some("https://pds.example.com"),
        );
    }

    #[test]
    fn plc_document_missing_fields_tolerated() {
        let doc: PlcDocument = serde_json::from_str("{}").expect("deserialize empty");
        assert!(PlcResolver::extract_did_key(&doc).is_none());
        assert!(PlcResolver::extract_handle(&doc).is_none());
        assert!(PlcResolver::extract_endpoint(&doc).is_none());
    }

    #[test]
    fn plc_document_partial_fields_tolerated() {
        let json = r#"{"verificationMethods": {"atproto": "did:key:z123"}}"#;
        let doc: PlcDocument = serde_json::from_str(json).expect("deserialize partial");
        assert!(PlcResolver::extract_did_key(&doc).is_some());
        assert!(PlcResolver::extract_handle(&doc).is_none());
        assert!(PlcResolver::extract_endpoint(&doc).is_none());
    }

    #[test]
    fn accepts_did_plc_only() {
        let resolver = PlcResolver::new("https://plc.directory", 3600).expect("build resolver");
        assert!(resolver.accepts("did:plc:z72i7hdynmk6r22z27h6tvur"));
        assert!(!resolver.accepts("did:web:example.com"));
        assert!(!resolver.accepts("did:key:z6Mk..."));
        assert!(!resolver.accepts("alice.bsky.social"));
        assert!(!resolver.accepts(""));
    }

    #[test]
    fn anchor_from_decoded_key_is_deterministic() -> Result<(), kappa_store::kappa::KappaParseError>
    {
        let key = [42u8; 32];
        let a = Kappa::from_key("ed25519", &key)?;
        let b = Kappa::from_key("ed25519", &key)?;
        assert_eq!(a, b);
        Ok(())
    }
}
