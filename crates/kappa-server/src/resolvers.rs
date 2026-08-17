//! Identity resolvers: PlcResolver, FulcioResolver, WebFingerResolver.
//!
//! Each resolver implements ExternalIdentifierResolver with async resolve().
//! PlcResolver and WebFingerResolver use reqwest::Client (async).
//! NixKeyResolver is sync (HashMap lookup) wrapped in async at zero cost.

use std::sync::{Arc, Weak};
use std::time::Duration;

use kappa_core::crypto::anchor::anchor_from_key_str;
use kappa_core::identity::resolver::{
    ExternalIdentifierResolver, ResolvedIdentity, ResolverRegistry,
};

// -- PlcResolver --------------------------------------------------------------

/// Resolves did:plc identifiers to asserter anchors via the PLC directory.
pub struct PlcResolver {
    plc_url: String,
    client: reqwest::Client,
}

impl PlcResolver {
    pub fn new(plc_url: &str) -> Self {
        Self {
            plc_url: plc_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("failed to build reqwest client"),
        }
    }

    pub fn from_env() -> Self {
        let url = std::env::var("KAPPA_PLC_DIRECTORY_URL")
            .unwrap_or_else(|_| "https://plc.directory".to_string());
        Self::new(&url)
    }
}

#[async_trait::async_trait]
impl ExternalIdentifierResolver for PlcResolver {
    fn id_type(&self) -> &str { "did:plc" }

    fn accepts(&self, identifier: &str) -> bool {
        identifier.starts_with("did:plc:")
    }

    async fn resolve(&self, identifier: &str) -> Result<Option<ResolvedIdentity>, String> {
        let url = format!("{}/{}", self.plc_url, identifier);
        let resp = self.client.get(&url).send().await
            .map_err(|e| format!("PLC directory request failed: {}", e))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(format!("PLC directory returned {}", resp.status()));
        }

        let doc: serde_json::Value = resp.json().await
            .map_err(|e| format!("PLC directory response parse failed: {}", e))?;

        let did_key = doc.get("verificationMethods")
            .and_then(|vm| vm.get("atproto"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| "DID document missing verificationMethods.atproto".to_string())?;

        let pubkey = decode_did_key(did_key)?;
        let algorithm = if pubkey.len() == 33 { "p256" }
            else if pubkey.len() == 32 { "ed25519" }
            else { return Err(format!("unexpected public key length: {}", pubkey.len())); };

        let anchor = anchor_from_key_str(algorithm, &pubkey);

        let handle = doc.get("alsoKnownAs")
            .and_then(|aka| aka.as_array())
            .and_then(|arr| arr.iter().find_map(|v| {
                v.as_str()?.strip_prefix("at://").map(|h| h.to_string())
            }))
            .unwrap_or_default();

        let service_endpoint = doc.get("service")
            .and_then(|svc| svc.as_array())
            .and_then(|arr| arr.iter().find_map(|entry| {
                let id = entry.get("id")?.as_str()?;
                if id == "#atproto_pds" {
                    entry.get("serviceEndpoint").and_then(|se| se.as_str()).map(|s| s.to_string())
                } else { None }
            }));

        let evidence = serde_json::to_vec(&doc).ok();

        Ok(Some(ResolvedIdentity {
            anchor, public_key: pubkey, algorithm: algorithm.to_string(),
            service_endpoint, handle, evidence,
        }))
    }

    fn cache_ttl_secs(&self) -> u64 { 3600 }
}

/// Decode a did:key to raw public key bytes.
fn decode_did_key(did_key: &str) -> Result<Vec<u8>, String> {
    let encoded = did_key.strip_prefix("did:key:z")
        .ok_or_else(|| format!("invalid did:key format: {}", did_key))?;
    let decoded = bs58_decode(encoded)
        .map_err(|e| format!("base58btc decode failed: {}", e))?;
    if decoded.len() < 2 {
        return Err("did:key decoded bytes too short".to_string());
    }
    if decoded[0] == 0x80 && decoded.len() > 1 && decoded[1] == 0x24 {
        // P-256: multicodec 0x1200 as varint [0x80, 0x24]
        if decoded.len() < 2 + 33 { return Err("P-256 key too short".to_string()); }
        Ok(decoded[2..2 + 33].to_vec())
    } else if decoded[0] == 0xED && decoded.len() > 1 && decoded[1] == 0x01 {
        // Ed25519: multicodec 0xED01
        if decoded.len() < 2 + 32 { return Err("Ed25519 key too short".to_string()); }
        Ok(decoded[2..2 + 32].to_vec())
    } else if decoded[0] == 0xE7 && decoded.len() > 1 && decoded[1] == 0x01 {
        // secp256k1: multicodec 0xE701
        if decoded.len() < 2 + 33 { return Err("secp256k1 key too short".to_string()); }
        Ok(decoded[2..2 + 33].to_vec())
    } else {
        Err(format!("unsupported multicodec prefix: 0x{:02x}{:02x}",
            decoded[0], decoded.get(1).copied().unwrap_or(0)))
    }
}

/// Simple base58btc decoder (Bitcoin alphabet).
fn bs58_decode(input: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes: Vec<u8> = Vec::new();
    for c in input.bytes() {
        let val = ALPHABET.iter().position(|&a| a == c)
            .ok_or_else(|| format!("invalid base58 character: {}", c as char))? as u64;
        let mut carry = val;
        for byte in bytes.iter_mut() {
            carry += *byte as u64 * 58;
            *byte = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    for c in input.bytes() {
        if c == b'1' { bytes.push(0); } else { break; }
    }
    bytes.reverse();
    Ok(bytes)
}

// -- FulcioResolver -----------------------------------------------------------

/// Resolves OIDC identities to asserter anchors via Sigstore Rekor.
#[cfg(feature = "atproto")]
pub struct FulcioResolver {
    rekor_url: String,
    client: reqwest::Client,
}

#[cfg(feature = "atproto")]
impl FulcioResolver {
    pub fn new(rekor_url: &str) -> Self {
        Self {
            rekor_url: rekor_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("failed to build reqwest client"),
        }
    }

    pub fn from_env() -> Self {
        let url = std::env::var("KAPPA_REKOR_URL")
            .unwrap_or_else(|_| "https://rekor.sigstore.dev".to_string());
        Self::new(&url)
    }
}

#[cfg(feature = "atproto")]
#[async_trait::async_trait]
impl ExternalIdentifierResolver for FulcioResolver {
    fn id_type(&self) -> &str { "fulcio" }

    fn accepts(&self, identifier: &str) -> bool {
        identifier.contains('@') || identifier.starts_with("https://github.com/")
    }

    async fn resolve(&self, identifier: &str) -> Result<Option<ResolvedIdentity>, String> {
        let search_url = format!("{}/api/v1/index/retrieve", self.rekor_url);
        let search_body = serde_json::json!({ "email": identifier });

        let resp = self.client.post(&search_url).json(&search_body).send().await
            .map_err(|e| format!("Rekor search failed: {}", e))?;

        if !resp.status().is_success() { return Ok(None); }

        let uuids: Vec<String> = resp.json().await
            .map_err(|e| format!("Rekor search response parse failed: {}", e))?;
        if uuids.is_empty() { return Ok(None); }

        let entry_url = format!("{}/api/v1/log/entries/{}", self.rekor_url, uuids[0]);
        let entry_resp = self.client.get(&entry_url).send().await
            .map_err(|e| format!("Rekor entry fetch failed: {}", e))?;
        if !entry_resp.status().is_success() { return Ok(None); }

        let entry: serde_json::Value = entry_resp.json().await
            .map_err(|e| format!("Rekor entry parse failed: {}", e))?;

        let body_b64 = entry.as_object()
            .and_then(|map| map.values().next())
            .and_then(|v| v.get("body"))
            .and_then(|b| b.as_str())
            .ok_or_else(|| "Rekor entry missing body".to_string())?;

        let body_bytes = base64_simd::STANDARD.decode_to_vec(body_b64.as_bytes())
            .map_err(|e| format!("Rekor body base64 decode failed: {}", e))?;

        let body: serde_json::Value = serde_json::from_slice(&body_bytes)
            .map_err(|e| format!("Rekor body JSON parse failed: {}", e))?;

        let cert_b64 = body.get("spec")
            .and_then(|s| s.get("signature"))
            .and_then(|s| s.get("publicKey"))
            .and_then(|pk| pk.get("content"))
            .and_then(|c| c.as_str())
            .ok_or_else(|| "Rekor entry missing spec.signature.publicKey.content".to_string())?;

        let cert_pem = base64_simd::STANDARD.decode_to_vec(cert_b64.as_bytes())
            .map_err(|e| format!("cert PEM base64 decode failed: {}", e))?;

        // Parse certificate for public key
        use x509_parser::prelude::*;
        let pem_str = String::from_utf8_lossy(&cert_pem);
        let (_, pem) = parse_x509_pem(pem_str.as_bytes())
            .map_err(|e| format!("PEM parse failed: {}", e))?;
        let (_, cert) = X509Certificate::from_der(&pem.contents)
            .map_err(|e| format!("X509 parse failed: {}", e))?;

        let pubkey_der = cert.public_key().raw;
        let algorithm = "p256";
        let anchor = anchor_from_key_str(algorithm, pubkey_der);

        Ok(Some(ResolvedIdentity {
            anchor, public_key: pubkey_der.to_vec(),
            algorithm: algorithm.to_string(),
            service_endpoint: Some(self.rekor_url.clone()),
            handle: identifier.to_string(),
            evidence: Some(cert_pem),
        }))
    }

    fn cache_ttl_secs(&self) -> u64 { 60 }
}

// -- WebFingerResolver --------------------------------------------------------

/// Resolves handle@domain identifiers to DIDs via WebFinger, then
/// delegates DID resolution to the ResolverRegistry.
pub struct WebFingerResolver {
    client: reqwest::Client,
    registry: Weak<ResolverRegistry>,
    dns: Arc<hickory_resolver::TokioResolver>,
}

impl WebFingerResolver {
    pub fn new(registry: Weak<ResolverRegistry>, dns: Arc<hickory_resolver::TokioResolver>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::limited(3))
                .build()
                .expect("failed to build reqwest client"),
            registry,
            dns,
        }
    }
}

#[async_trait::async_trait]
impl ExternalIdentifierResolver for WebFingerResolver {
    fn id_type(&self) -> &str { "webfinger" }

    fn accepts(&self, identifier: &str) -> bool {
        let clean = identifier.strip_prefix('@').unwrap_or(identifier);
        clean.contains('.') && !clean.starts_with("did:")
    }

    async fn resolve(&self, identifier: &str) -> Result<Option<ResolvedIdentity>, String> {
        let handle = identifier.strip_prefix('@').unwrap_or(identifier);

        // Phase 1: handle -> DID via WebFinger
        let did = match self.resolve_webfinger(handle).await {
            Ok(Some(d)) => Some(d),
            _ => self.resolve_dns_txt(handle).await?,
        };

        let did = match did {
            Some(d) => d,
            None => return Ok(None),
        };

        // Phase 2: DID -> anchor via registry
        let registry = self.registry.upgrade()
            .ok_or_else(|| "resolver registry dropped".to_string())?;
        registry.resolve(&did).await
    }

    fn cache_ttl_secs(&self) -> u64 { 300 }
}

impl WebFingerResolver {
    async fn resolve_webfinger(&self, handle: &str) -> Result<Option<String>, String> {
        let url = format!(
            "https://{}/.well-known/webfinger?resource=acct:{}",
            handle, handle
        );
        let resp = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => {
                // Fallback: try domain part
                let domain = handle.rsplit_once('.')
                    .map(|(prefix, _)| {
                        if let Some(pos) = prefix.rfind('.') { &handle[pos + 1..] }
                        else { handle }
                    })
                    .unwrap_or(handle);
                let fallback_url = format!(
                    "https://{}/.well-known/webfinger?resource=acct:{}",
                    domain, handle
                );
                match self.client.get(&fallback_url).send().await {
                    Ok(r) => r,
                    Err(_) => return Ok(None),
                }
            }
        };

        if !resp.status().is_success() { return Ok(None); }

        let jrd: serde_json::Value = resp.json().await
            .map_err(|e| format!("WebFinger response parse failed: {}", e))?;

        let did = jrd.get("links")
            .and_then(|links| links.as_array())
            .and_then(|arr| arr.iter().find_map(|link| {
                let rel = link.get("rel")?.as_str()?;
                if rel == "self" {
                    link.get("href").and_then(|h| h.as_str())
                        .filter(|h| h.starts_with("did:"))
                        .map(|h| h.to_string())
                } else { None }
            }));

        Ok(did)
    }

    async fn resolve_dns_txt(&self, handle: &str) -> Result<Option<String>, String> {
        let query_name = format!("_atproto.{}.", handle);
        let txt_lookup = match self.dns.txt_lookup(&query_name).await {
            Ok(lookup) => lookup,
            Err(_) => return Ok(None),
        };

        let did = txt_lookup.iter()
            .flat_map(|txt| txt.iter())
            .find_map(|data| {
                let s = String::from_utf8_lossy(data);
                let clean = s.trim().trim_matches('"');
                clean.strip_prefix("did=").map(|d| d.to_string())
            });

        Ok(did)
    }
}

// -- NixKeyResolver -----------------------------------------------------------

/// Resolves Nix signing key names to identity anchors from static config.
pub struct NixKeyResolver {
    keys: Vec<(String, Vec<u8>)>,
}

impl NixKeyResolver {
    pub fn new(keys: Vec<(String, Vec<u8>)>) -> Self { Self { keys } }

    pub fn from_env() -> Self {
        let raw = std::env::var("KAPPA_NIX_TRUSTED_KEYS").unwrap_or_default();
        let keys = raw.split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|entry| {
                let (name, b64) = entry.split_once(':')?;
                let pubkey = base64_simd::STANDARD.decode_to_vec(b64.as_bytes()).ok()?;
                Some((name.to_string(), pubkey))
            })
            .collect();
        Self { keys }
    }
}

#[async_trait::async_trait]
impl ExternalIdentifierResolver for NixKeyResolver {
    fn id_type(&self) -> &str { "nix-key" }

    fn accepts(&self, identifier: &str) -> bool {
        self.keys.iter().any(|(name, _)| name == identifier)
    }

    async fn resolve(&self, identifier: &str) -> Result<Option<ResolvedIdentity>, String> {
        for (name, pubkey) in &self.keys {
            if name == identifier {
                let anchor = anchor_from_key_str("ed25519", pubkey);
                return Ok(Some(ResolvedIdentity {
                    anchor, public_key: pubkey.clone(),
                    algorithm: "ed25519".to_string(),
                    service_endpoint: None, handle: name.clone(), evidence: None,
                }));
            }
        }
        Ok(None)
    }

    fn cache_ttl_secs(&self) -> u64 { u64::MAX }
}

// -- Registry builder ---------------------------------------------------------

/// Build a ResolverRegistry from environment config.
pub fn build_registry(dns: Arc<hickory_resolver::TokioResolver>) -> Arc<ResolverRegistry> {
    let mut registry = ResolverRegistry::new();

    let nix = NixKeyResolver::from_env();
    if !nix.keys.is_empty() {
        registry.add(Arc::new(nix));
    }

    registry.add(Arc::new(PlcResolver::from_env()));

    // WebFingerResolver needs a weak ref back to the registry for DID -> anchor
    // resolution after handle -> DID via WebFinger/DNS. We build the registry,
    // wrap it in Arc, then rebuild with the weak ref. The rebuild duplicates
    // Nix + PLC resolvers but shares the DNS resolver and cache.
    let inner = Arc::new(registry);
    let mut full = ResolverRegistry::new();

    let nix2 = NixKeyResolver::from_env();
    if !nix2.keys.is_empty() {
        full.add(Arc::new(nix2));
    }
    full.add(Arc::new(PlcResolver::from_env()));
    let weak = Arc::downgrade(&inner);
    full.add(Arc::new(WebFingerResolver::new(weak, dns)));

    Arc::new(full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nix_resolver_finds_configured_key() {
        let keys = vec![("test-key".to_string(), vec![1u8; 32])];
        let resolver = NixKeyResolver::new(keys);
        assert!(resolver.accepts("test-key"));
        assert!(!resolver.accepts("unknown-key"));
    }

    #[test]
    fn plc_resolver_accepts_did_plc() {
        let resolver = PlcResolver::new("https://plc.directory");
        assert!(resolver.accepts("did:plc:z72i7hdynmk6r22z27h6tvur"));
        assert!(!resolver.accepts("did:web:example.com"));
        assert!(!resolver.accepts("alice.bsky.social"));
    }

    #[test]
    fn bs58_decode_basic() {
        let decoded = bs58_decode("").unwrap();
        assert!(decoded.is_empty());
        let decoded = bs58_decode("1").unwrap();
        assert_eq!(decoded, vec![0]);
        let decoded = bs58_decode("2").unwrap();
        assert_eq!(decoded, vec![1]);
    }

    #[test]
    fn decode_did_key_error() {
        assert!(decode_did_key("not-a-did-key").is_err());
    }

    #[tokio::test]
    async fn registry_dispatch() {
        let mut registry = ResolverRegistry::new();
        let nix = NixKeyResolver::new(vec![("cache-key".to_string(), vec![42u8; 32])]);
        registry.add(Arc::new(nix));

        let result = registry.resolve("cache-key").await.unwrap();
        assert!(result.is_some());

        let result = registry.resolve("unknown").await.unwrap();
        assert!(result.is_none());
    }
}
