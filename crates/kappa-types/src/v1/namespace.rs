use dcbor::prelude::*;

/// Canonical protocol surface identifier.
///
/// Lowercase ASCII alphanumeric plus hyphen. Enforced at construction.
/// The substrate uses this as a compound key component in namespace
/// aliases and handle records. The substrate does not parse it,
/// dispatch on it, or behave differently based on its value.
///
/// Each protocol module defines its own `ProtocolId` constant.
/// The substrate contains zero protocol names.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "String")]
pub struct ProtocolId(String);

/// Construction error for invalid protocol identifier strings.
#[derive(Debug, thiserror::Error)]
#[error("invalid protocol id: must be non-empty lowercase ASCII alphanumeric plus hyphen")]
pub struct InvalidProtocolId;

impl ProtocolId {
    /// Construct a validated protocol identifier.
    /// Accepts non-empty strings of lowercase ASCII letters, digits, and hyphens.
    pub fn new(s: &str) -> Result<Self, InvalidProtocolId> {
        if s.is_empty() {
            return Err(InvalidProtocolId);
        }
        if s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            Ok(Self(s.to_string()))
        } else {
            Err(InvalidProtocolId)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ProtocolId {
    type Error = InvalidProtocolId;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(InvalidProtocolId);
        }
        Ok(Self(value))
    }
}

impl AsRef<str> for ProtocolId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Injective namespace alias framing shared by every storage backend.
///
/// Protocol identifiers cannot contain NUL; the first NUL separates the
/// optional protocol from the alias, whose bytes are preserved verbatim.
pub fn namespace_alias_key(name: &str, protocol: Option<&ProtocolId>) -> String {
    format!("{}\0{name}", protocol.map_or("", ProtocolId::as_str))
}

// dCBOR: ProtocolId encodes as a text string.
impl From<ProtocolId> for CBOR {
    fn from(p: ProtocolId) -> Self {
        Self::from(p.0)
    }
}

impl From<&ProtocolId> for CBOR {
    fn from(p: &ProtocolId) -> Self {
        Self::from(p.0.clone())
    }
}

impl TryFrom<CBOR> for ProtocolId {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, dcbor::Error> {
        let s: String = cbor.try_into()?;
        Self::new(&s).map_err(|_| dcbor::Error::WrongType)
    }
}

// ---------------------------------------------------------------------------
// NamespaceRef
// ---------------------------------------------------------------------------

/// Namespace identity with human-readable name attached.
///
/// Not Copy. The display name travels with the ref so every log line,
/// tracing span, and error message includes it without a store lookup.
///
/// No `From<&str>`. Construction goes through `deterministic()`, `generate()`,
/// `resolved()`, or well-known constants.
///
/// CBOR encoding: `[uuid_bytes, display_name_string]`. The protocol
/// field is NOT persisted in the `NamespaceRef` encoding -- it comes
/// from the containing `NamespaceInfo` record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NamespaceRef {
    id: [u8; 16],
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    protocol: Option<ProtocolId>,
}

impl NamespaceRef {
    /// Deterministic namespace from a well-known name.
    /// BLAKE3 keyed hash, same name always produces same UUID across
    /// all nodes and restarts. Used for system namespaces.
    pub fn deterministic(name: &str) -> Self {
        Self::deterministic_from_bytes(name.as_bytes(), name.to_string())
    }

    /// Deterministic namespace from raw bytes.
    /// Used for per-identity namespaces where the input is a Kappa's
    /// `key_bytes()` -- the binary digest, not the formatted string.
    pub fn deterministic_from_bytes(input: &[u8], display_name: String) -> Self {
        let key = blake3::hash(b"kappa-namespace-uuid");
        let hash = blake3::keyed_hash(key.as_bytes(), input);
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash.as_bytes()[..16]);
        id[6] = (id[6] & 0x0F) | 0x80; // custom UUID version
        id[8] = (id[8] & 0x3F) | 0x80; // RFC 4122 variant
        Self {
            id,
            display_name,
            protocol: None,
        }
    }

    /// Deterministic namespace from a Kappa anchor.
    /// The namespace ID depends on the anchor's raw digest bytes,
    /// not on the formatted string representation.
    pub fn for_anchor(anchor: &crate::kappa::Kappa) -> Self {
        Self::deterministic_from_bytes(&anchor.key_bytes(), anchor.to_string())
    }

    /// Generate a new `UUIDv7` (time-ordered) namespace.
    pub fn generate(name: &str, now: crate::clock::ClockMs) -> Result<Self, crate::StoreError> {
        let ms = now.physical_ms();
        let mut id = [0u8; 16];
        id[0..6].copy_from_slice(&ms.to_be_bytes()[2..8]);
        getrandom::fill(&mut id[6..16])
            .map_err(|error| crate::StoreError::Internal(format!("namespace entropy: {error}")))?;
        id[6] = (id[6] & 0x0F) | 0x70; // version 7
        id[8] = (id[8] & 0x3F) | 0x80; // RFC 4122 variant
        Ok(Self {
            id,
            display_name: name.to_string(),
            protocol: None,
        })
    }

    /// Construct from a store lookup result.
    pub const fn resolved(
        id: [u8; 16],
        display_name: String,
        protocol: Option<ProtocolId>,
    ) -> Self {
        Self {
            id,
            display_name,
            protocol,
        }
    }

    #[must_use]
    pub fn with_protocol(mut self, protocol: ProtocolId) -> Self {
        self.protocol = Some(protocol);
        self
    }

    pub const fn id(&self) -> &[u8; 16] {
        &self.id
    }
    pub fn uuid_hex(&self) -> String {
        hex::encode(self.id)
    }
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    pub const fn protocol(&self) -> Option<&ProtocolId> {
        self.protocol.as_ref()
    }

    pub fn as_str(&self) -> &str {
        &self.display_name
    }
}

impl PartialEq for NamespaceRef {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for NamespaceRef {}

impl std::hash::Hash for NamespaceRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl std::fmt::Display for NamespaceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display_name)
    }
}

// -- dCBOR: NamespaceRef encodes as [uuid_bytes, display_name] ----------------

impl From<NamespaceRef> for dcbor::CBOR {
    fn from(ns: NamespaceRef) -> Self {
        let uuid: Self = dcbor::ByteString::from(ns.id.to_vec()).into();
        let name: Self = ns.display_name.into();
        vec![uuid, name].into()
    }
}

impl From<&NamespaceRef> for dcbor::CBOR {
    fn from(ns: &NamespaceRef) -> Self {
        let uuid: Self = dcbor::ByteString::from(ns.id.to_vec()).into();
        let name: Self = ns.display_name.clone().into();
        vec![uuid, name].into()
    }
}

impl TryFrom<dcbor::CBOR> for NamespaceRef {
    type Error = dcbor::Error;
    fn try_from(cbor: dcbor::CBOR) -> Result<Self, dcbor::Error> {
        let arr = cbor
            .as_array()
            .ok_or_else(|| dcbor::Error::msg("NamespaceRef: expected array"))?;
        if arr.len() != 2 {
            return Err(dcbor::Error::msg("NamespaceRef: need [uuid, name]"));
        }
        let uuid_bytes = arr[0]
            .as_byte_string()
            .ok_or_else(|| dcbor::Error::msg("NamespaceRef: uuid not bytes"))?;
        if uuid_bytes.len() != 16 {
            return Err(dcbor::Error::msg("NamespaceRef: uuid not 16 bytes"));
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(uuid_bytes);
        let name: String = arr[1].clone().try_into()?;
        Ok(Self {
            id,
            display_name: name,
            protocol: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_framing_separates_global_scoped_and_delimiter_names() -> Result<(), InvalidProtocolId>
    {
        let protocol = ProtocolId::new("git")?;
        assert_ne!(
            namespace_alias_key("git:repo", None),
            namespace_alias_key("repo", Some(&protocol))
        );
        assert_ne!(
            namespace_alias_key("repo", None),
            namespace_alias_key("repo", Some(&protocol))
        );
        assert_ne!(
            namespace_alias_key("a\0b", None),
            namespace_alias_key("a", None)
        );
        assert_eq!(namespace_alias_key("repo", Some(&protocol)), "git\0repo");
        Ok(())
    }

    #[test]
    fn namespace_uuid_has_exact_byte_string_encoding() {
        let ns = NamespaceRef::resolved([1; 16], "n".into(), None);
        let mut expected = vec![0x82, 0x50];
        expected.extend_from_slice(&[1; 16]);
        expected.extend_from_slice(&[0x61, b'n']);
        assert_eq!(CBOR::from(&ns).to_cbor_data(), expected);
        assert_eq!(CBOR::from(ns).to_cbor_data(), expected);
        let malformed: CBOR = vec![CBOR::from(vec![1u8; 16]), CBOR::from("n")].into();
        assert!(NamespaceRef::try_from(malformed).is_err());
        let extra: CBOR = vec![CBOR::to_byte_string([1; 16]), CBOR::from("n"), CBOR::null()].into();
        assert!(NamespaceRef::try_from(extra).is_err());
    }

    #[test]
    fn protocol_id_valid() {
        assert!(ProtocolId::new("oci").is_ok());
        assert!(ProtocolId::new("atproto").is_ok());
        assert!(ProtocolId::new("my-protocol-v2").is_ok());
        assert!(ProtocolId::new("s3").is_ok());
    }

    #[test]
    fn protocol_id_rejects_invalid() {
        assert!(ProtocolId::new("").is_err());
        assert!(ProtocolId::new("OCI").is_err());
        assert!(ProtocolId::new("my protocol").is_err());
        assert!(ProtocolId::new("my_protocol").is_err());
        assert!(ProtocolId::new("protocol/v1").is_err());
    }

    #[test]
    fn protocol_id_json_cannot_bypass_constructor_validation() -> Result<(), serde_json::Error> {
        for invalid in [
            "",
            "OCI",
            "my protocol",
            "my_protocol",
            "protocol/v1",
            "\u{e9}",
        ] {
            let encoded = serde_json::to_string(invalid)?;
            assert!(serde_json::from_str::<ProtocolId>(&encoded).is_err());
        }
        let id: ProtocolId = serde_json::from_str("\"custom-v2\"")?;
        assert_eq!(id.as_str(), "custom-v2");
        assert_eq!(serde_json::to_string(&id)?, "\"custom-v2\"");
        Ok(())
    }

    #[test]
    fn protocol_id_as_str() -> Result<(), InvalidProtocolId> {
        let id = ProtocolId::new("atproto")?;
        assert_eq!(id.as_str(), "atproto");
        Ok(())
    }

    #[test]
    fn protocol_id_display() -> Result<(), InvalidProtocolId> {
        let id = ProtocolId::new("git")?;
        assert_eq!(format!("{id}"), "git");
        Ok(())
    }

    #[test]
    fn protocol_id_equality() -> Result<(), InvalidProtocolId> {
        let a = ProtocolId::new("s3")?;
        let b = ProtocolId::new("s3")?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn protocol_id_ordering() -> Result<(), InvalidProtocolId> {
        let a = ProtocolId::new("atproto")?;
        let b = ProtocolId::new("oci")?;
        assert!(a < b);
        Ok(())
    }

    #[test]
    fn protocol_id_cbor_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let id = ProtocolId::new("nix")?;
        let cbor: CBOR = id.clone().into();
        let recovered: ProtocolId = cbor.try_into()?;
        assert_eq!(recovered, id);
        Ok(())
    }

    #[test]
    fn namespace_ref_deterministic() {
        let a = NamespaceRef::deterministic("_root");
        let b = NamespaceRef::deterministic("_root");
        assert_eq!(a, b);
        assert_eq!(a.display_name(), "_root");
    }

    #[test]
    fn namespace_ref_different_names() {
        let a = NamespaceRef::deterministic("_root");
        let b = NamespaceRef::deterministic("_system");
        assert_ne!(a, b);
    }

    #[test]
    fn namespace_ref_with_protocol() -> Result<(), InvalidProtocolId> {
        let ns = NamespaceRef::deterministic("test").with_protocol(ProtocolId::new("oci")?);
        assert_eq!(ns.protocol().map(ProtocolId::as_str), Some("oci"));
        Ok(())
    }
}
