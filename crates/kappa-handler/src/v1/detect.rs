//! Protocol detection trait for pre-routing signal analysis.
//!
//! Each protocol module implements this trait to claim requests
//! based on headers, query parameters, path patterns, or host.
//! The server's namespace layer runs all registered detectors
//! in priority order. First match wins.
//!
//! Adding a protocol: implement `ProtocolDetector` in the module
//! crate, register it in the server's bootstrap. No modification
//! to the namespace layer or any existing detector.

/// Result of a successful protocol detection.
#[derive(Debug, Clone)]
pub struct ProtocolMatch {
    /// Protocol identifier (e.g., "git", "s3", "oci", "nix", "atproto").
    pub protocol: &'static str,
    /// Extracted namespace name from the request path.
    /// None for system endpoints or protocols that resolve internally.
    pub namespace: Option<String>,
    /// If Some, the request URI is rewritten before routing.
    /// The namespace layer applies this rewrite generically.
    pub rewrite: Option<String>,
    /// Detected operation intent for authorization decisions.
    pub operation: DetectedOperation,
    /// Size class of the request body, for the server's body limit.
    pub body: BodyClass,
}

/// Size class of a request body, declared by the detector that claims it.
///
/// The server bounds `Content` bodies by `MaxBlobSize` and `Control` bodies
/// by its API body limit before the handler runs; handlers still enforce
/// their own exact limits while reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyClass {
    /// Stored object bytes: blobs, upload chunks, S3 objects and parts,
    /// Git packs, NARs, bundles, staged transaction blobs.
    Content,
    /// Protocol control documents: JSON, XML, and form bodies.
    Control,
}

/// Operation intent detected from protocol signals.
///
/// The auth layer uses this to decide whether a nonexistent
/// namespace returns 404 (Read) or `AllowCreateNew` (Write).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedOperation {
    /// Pure read. GET/HEAD that does not precede a write.
    Read,
    /// State-modifying operation.
    Write,
    /// Read that must succeed for a subsequent write to proceed.
    /// Git GET /info/refs?service=git-receive-pack.
    /// Treated as Write for namespace creation purposes.
    WriteDiscovery,
}

impl DetectedOperation {
    pub const fn is_write(&self) -> bool {
        matches!(self, Self::Write | Self::WriteDiscovery)
    }
}

/// Protocol detector implemented by each protocol module.
///
/// Priority convention:
///   100: definitive header signals (Content-Type, Authorization scheme)
///   200: reserved path prefixes (/v2/, /_git/, /_nix/, /xrpc/)
///   300: path suffix signals (/info/refs, *.narinfo)
///   400: fallback heuristics (Git dumb HTTP /HEAD, /objects/)
pub trait ProtocolDetector: Send + Sync {
    /// Unique protocol identifier.
    fn protocol(&self) -> &'static str;

    /// Detection priority. Lower runs first.
    fn priority(&self) -> u32;

    /// Examine the request and return Some if this protocol claims it.
    fn detect(
        &self,
        path: &str,
        query: &str,
        headers: &http::HeaderMap,
        host: Option<&str>,
    ) -> Option<ProtocolMatch>;
}

/// Registry of protocol detectors sorted by priority.
/// First matching detector wins.
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn ProtocolDetector>>,
}

impl DetectorRegistry {
    pub const fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// Register a detector. The registry re-sorts by priority
    /// after each insertion so detection order is deterministic.
    pub fn register(&mut self, detector: impl ProtocolDetector + 'static) {
        self.detectors.push(Box::new(detector));
        self.detectors.sort_by_key(|d| d.priority());
    }

    /// Run all detectors in priority order. First match wins.
    pub fn detect(
        &self,
        path: &str,
        query: &str,
        headers: &http::HeaderMap,
        host: Option<&str>,
    ) -> Option<ProtocolMatch> {
        self.detectors
            .iter()
            .find_map(|d| d.detect(path, query, headers, host))
    }

    pub const fn len(&self) -> usize {
        self.detectors.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysMatch {
        proto: &'static str,
        prio: u32,
    }

    impl ProtocolDetector for AlwaysMatch {
        fn protocol(&self) -> &'static str {
            self.proto
        }
        fn priority(&self) -> u32 {
            self.prio
        }
        fn detect(
            &self,
            _path: &str,
            _query: &str,
            _headers: &http::HeaderMap,
            _host: Option<&str>,
        ) -> Option<ProtocolMatch> {
            Some(ProtocolMatch {
                protocol: self.proto,
                namespace: None,
                rewrite: None,
                operation: DetectedOperation::Read,
                body: BodyClass::Control,
            })
        }
    }

    struct NeverMatch;

    impl ProtocolDetector for NeverMatch {
        fn protocol(&self) -> &'static str {
            "never"
        }
        fn priority(&self) -> u32 {
            0
        }
        fn detect(
            &self,
            _path: &str,
            _query: &str,
            _headers: &http::HeaderMap,
            _host: Option<&str>,
        ) -> Option<ProtocolMatch> {
            None
        }
    }

    #[test]
    fn empty_registry_returns_none() {
        let reg = DetectorRegistry::new();
        assert!(
            reg.detect("/foo", "", &http::HeaderMap::new(), None)
                .is_none()
        );
    }

    #[test]
    fn first_match_wins() -> Result<(), &'static str> {
        let mut reg = DetectorRegistry::new();
        reg.register(AlwaysMatch {
            proto: "a",
            prio: 200,
        });
        reg.register(AlwaysMatch {
            proto: "b",
            prio: 100,
        });
        let m = reg
            .detect("/foo", "", &http::HeaderMap::new(), None)
            .ok_or("no matching detector")?;
        assert_eq!(m.protocol, "b");
        Ok(())
    }

    #[test]
    fn priority_ordering() -> Result<(), &'static str> {
        let mut reg = DetectorRegistry::new();
        reg.register(AlwaysMatch {
            proto: "low",
            prio: 400,
        });
        reg.register(AlwaysMatch {
            proto: "high",
            prio: 100,
        });
        reg.register(AlwaysMatch {
            proto: "mid",
            prio: 200,
        });
        let m = reg
            .detect("/foo", "", &http::HeaderMap::new(), None)
            .ok_or("no matching detector")?;
        assert_eq!(m.protocol, "high");
        Ok(())
    }

    #[test]
    fn skip_non_matching() -> Result<(), &'static str> {
        let mut reg = DetectorRegistry::new();
        reg.register(NeverMatch);
        reg.register(AlwaysMatch {
            proto: "found",
            prio: 200,
        });
        let m = reg
            .detect("/foo", "", &http::HeaderMap::new(), None)
            .ok_or("no matching detector")?;
        assert_eq!(m.protocol, "found");
        Ok(())
    }

    #[test]
    fn all_non_matching_returns_none() {
        let mut reg = DetectorRegistry::new();
        reg.register(NeverMatch);
        assert!(
            reg.detect("/foo", "", &http::HeaderMap::new(), None)
                .is_none()
        );
    }

    #[test]
    fn len_and_is_empty() {
        let mut reg = DetectorRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        reg.register(NeverMatch);
        assert!(!reg.is_empty());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn detected_operation_is_write() {
        assert!(!DetectedOperation::Read.is_write());
        assert!(DetectedOperation::Write.is_write());
        assert!(DetectedOperation::WriteDiscovery.is_write());
    }
}
