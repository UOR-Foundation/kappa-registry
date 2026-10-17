use std::collections::HashMap;

use kappa_handler::{ExternalIdentifierResolver, ResolveError, ResolvedIdentity};
use kappa_store::kappa::Kappa;

/// Trusted Nix signing keys. Holds public keys only.
#[derive(Debug)]
pub struct NixKeyResolver {
    keys: HashMap<String, NixKey>,
    ttl: u64,
}

#[derive(Debug)]
struct NixKey {
    anchor: Kappa,
    public_key: Vec<u8>,
    algorithm: String,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NixKeyError {
    #[error(transparent)]
    KeyFraming(#[from] kappa_store::kappa::KappaParseError),
    #[error("invalid base64 in key '{name}': {reason}")]
    InvalidBase64 { name: String, reason: String },

    #[error("key '{name}' is {len} bytes, expected 32")]
    InvalidKeyLength { name: String, len: usize },

    #[error("no valid keys found in KAPPA_NIX_TRUSTED_KEYS")]
    NoValidKeys,

    #[error("missing ':' separator in key entry '{entry}'")]
    MalformedEntry { entry: String },
}

impl NixKeyResolver {
    pub fn from_env(ttl: u64) -> Result<Option<Self>, NixKeyError> {
        let raw = match std::env::var("KAPPA_NIX_TRUSTED_KEYS") {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };
        Self::from_raw(&raw, ttl).map(Some)
    }

    pub fn from_raw(raw: &str, ttl: u64) -> Result<Self, NixKeyError> {
        let mut keys = HashMap::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (name, b64_key) =
                entry
                    .split_once(':')
                    .ok_or_else(|| NixKeyError::MalformedEntry {
                        entry: entry.to_string(),
                    })?;
            let key_bytes =
                kappa_handler::base64_decode(b64_key).map_err(|e| NixKeyError::InvalidBase64 {
                    name: name.into(),
                    reason: e.to_string(),
                })?;
            if key_bytes.len() != 32 {
                return Err(NixKeyError::InvalidKeyLength {
                    name: name.into(),
                    len: key_bytes.len(),
                });
            }
            let anchor = Kappa::from_key("ed25519", &key_bytes)?;
            keys.insert(
                name.to_string(),
                NixKey {
                    anchor,
                    public_key: key_bytes,
                    algorithm: "ed25519".into(),
                },
            );
        }
        if keys.is_empty() {
            return Err(NixKeyError::NoValidKeys);
        }
        Ok(Self { keys, ttl })
    }
}

#[async_trait::async_trait]
impl ExternalIdentifierResolver for NixKeyResolver {
    fn id_type(&self) -> &str {
        "nix-key"
    }

    fn accepts(&self, identifier: &str) -> bool {
        self.keys.contains_key(identifier)
    }

    async fn resolve(&self, identifier: &str) -> Result<Option<ResolvedIdentity>, ResolveError> {
        match self.keys.get(identifier) {
            Some(key) => Ok(Some(ResolvedIdentity {
                anchor: key.anchor.clone(),
                public_key: key.public_key.clone(),
                algorithm: key.algorithm.clone(),
                service_endpoint: None,
                handle: Some(identifier.to_string()),
                evidence: None,
            })),
            None => Ok(None),
        }
    }

    fn cache_ttl_secs(&self) -> u64 {
        self.ttl
    }
}

#[cfg(test)]
mod tests {
    //! Private access: `NixKeyResolver::keys` and `NixKey::anchor`.

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn test_resolver() -> Result<NixKeyResolver, NixKeyError> {
        let key_bytes = [42u8; 32];
        let b64 = kappa_handler::base64_encode(&key_bytes);
        NixKeyResolver::from_raw(&format!("test-key-1:{b64}"), 300)
    }

    #[test]
    fn accepts_known_key() -> TestResult {
        assert!(test_resolver()?.accepts("test-key-1"));
        Ok(())
    }

    #[test]
    fn rejects_unknown_key() -> TestResult {
        assert!(!test_resolver()?.accepts("unknown-key"));
        Ok(())
    }

    #[tokio::test]
    async fn resolve_known_key_returns_identity() -> TestResult {
        let resolver = test_resolver()?;
        let identity = resolver
            .resolve("test-key-1")
            .await?
            .ok_or("known key did not resolve")?;
        assert_eq!(identity.algorithm, "ed25519");
        assert_eq!(identity.public_key.len(), 32);
        assert_eq!(identity.handle.as_deref(), Some("test-key-1"));
        assert_eq!(identity.anchor, Kappa::from_key("ed25519", &[42u8; 32])?);
        Ok(())
    }

    #[tokio::test]
    async fn resolve_unknown_key_returns_none() -> TestResult {
        assert!(test_resolver()?.resolve("nonexistent").await?.is_none());
        Ok(())
    }

    #[test]
    fn rejects_wrong_length_key() {
        let short_b64 = kappa_handler::base64_encode(&[1, 2, 3]);
        let result = NixKeyResolver::from_raw(&format!("bad-key:{short_b64}"), 300);
        assert!(
            matches!(
                &result,
                Err(NixKeyError::InvalidKeyLength { name, len: 3 }) if name == "bad-key"
            ),
            "expected InvalidKeyLength for bad-key of 3 bytes, got {result:?}"
        );
    }

    #[test]
    fn rejects_empty_input() {
        let result = NixKeyResolver::from_raw("", 300);
        assert!(matches!(result, Err(NixKeyError::NoValidKeys)));
    }

    #[test]
    fn rejects_malformed_entry() {
        let result = NixKeyResolver::from_raw("no-colon-here", 300);
        assert!(matches!(result, Err(NixKeyError::MalformedEntry { .. })));
    }

    #[test]
    fn multiple_keys_parsed() -> TestResult {
        let k1 = kappa_handler::base64_encode(&[1u8; 32]);
        let k2 = kappa_handler::base64_encode(&[2u8; 32]);
        let resolver = NixKeyResolver::from_raw(&format!("key-a:{k1}, key-b:{k2}"), 300)?;
        assert!(resolver.accepts("key-a"));
        assert!(resolver.accepts("key-b"));
        assert!(!resolver.accepts("key-c"));
        Ok(())
    }

    #[test]
    fn anchor_is_deterministic() -> TestResult {
        let key_bytes = [99u8; 32];
        let b64 = kappa_handler::base64_encode(&key_bytes);
        let r1 = NixKeyResolver::from_raw(&format!("k:{b64}"), 300)?;
        let r2 = NixKeyResolver::from_raw(&format!("k:{b64}"), 300)?;
        let a1 = &r1.keys.get("k").ok_or("k missing from r1")?.anchor;
        let a2 = &r2.keys.get("k").ok_or("k missing from r2")?.anchor;
        assert_eq!(a1, a2);
        Ok(())
    }
}
