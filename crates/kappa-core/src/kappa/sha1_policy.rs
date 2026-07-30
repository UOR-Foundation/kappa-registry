//! Per-namespace SHA-1 digest policy.
//!
//! SHA-1 is accepted by default for backward compatibility with Docker
//! v2 schema1 manifests. Namespaces can restrict or upgrade via metadata.
//!
//! The policy is stored as a blob referenced by the tag
//! `_policy/digest/sha1`. The blob content is the policy string:
//! "allow", "deny", or "upgrade". Missing tag = default (Allow).

use crate::store::KappaStore;

/// Policy for SHA-1 digest handling in a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sha1Policy {
    /// Accept sha1 if no collision detected. Default.
    #[default]
    Allow,
    /// Reject all sha1 uploads. For namespaces requiring modern algorithms.
    Deny,
    /// Accept sha1 but also compute and store a sha256 for the same content.
    /// The blob is addressable by both digests via hardlink.
    AllowWithSha256Upgrade,
}

impl Sha1Policy {
    /// Parse a policy string.
    pub fn parse_str(s: &str) -> Self {
        match s.trim() {
            "deny" => Self::Deny,
            "upgrade" => Self::AllowWithSha256Upgrade,
            _ => Self::Allow,
        }
    }

    /// Serialize to the metadata value string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::AllowWithSha256Upgrade => "upgrade",
        }
    }

    /// Look up the SHA-1 policy for a namespace.
    ///
    /// Reads the `_policy/digest/sha1` tag, then reads the blob it
    /// points to. The blob content is the policy string. Missing tag
    /// or any read error returns the default policy (Allow).
    pub fn for_namespace(store: &dyn KappaStore, ns: &str) -> Self {
        let entry = match store.tag_get(ns, "_policy/digest/sha1") {
            Ok(e) => e,
            Err(_) => return Self::default(),
        };
        let blob = match store.blob_get(&entry.kappa) {
            Ok(b) => b,
            Err(_) => return Self::default(),
        };
        let text = String::from_utf8_lossy(&blob);
        Self::parse_str(&text)
    }
}
