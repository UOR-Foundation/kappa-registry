use kappa_handler::detect::{BodyClass, DetectedOperation, ProtocolDetector, ProtocolMatch};

/// Rotation of the node's signing authority. Resolved against `_root`, so
/// authorization requires `_root` admin authority.
pub const NODE_ROTATE_PATH: &str = "/_node/authority/rotate";

/// The node's authority status. Resolved against `_root` as a read.
pub const NODE_AUTHORITY_PATH: &str = "/_node/authority";

pub struct SystemPathDetector;

impl ProtocolDetector for SystemPathDetector {
    fn protocol(&self) -> &'static str {
        "system"
    }
    fn priority(&self) -> u32 {
        200
    }

    fn detect(
        &self,
        path: &str,
        _query: &str,
        _headers: &http::HeaderMap,
        _host: Option<&str>,
    ) -> Option<ProtocolMatch> {
        if path == NODE_ROTATE_PATH {
            return Some(ProtocolMatch {
                protocol: "system",
                namespace: Some(kappa_handler::authority::ROOT_NAMESPACE.into()),
                rewrite: None,
                operation: DetectedOperation::Write,
                body: BodyClass::Control,
            });
        }
        if path == NODE_AUTHORITY_PATH {
            return Some(ProtocolMatch {
                protocol: "system",
                namespace: Some(kappa_handler::authority::ROOT_NAMESPACE.into()),
                rewrite: None,
                operation: DetectedOperation::Read,
                body: BodyClass::Control,
            });
        }
        let is_system = path == "/_status"
            || path.starts_with("/_status/")
            || path == "/openapi.json"
            || path == "/docs"
            || path == "/docs/scalar.js"
            || path == "/"
            || path.starts_with("/identity/");
        if !is_system {
            return None;
        }
        Some(ProtocolMatch {
            protocol: "system",
            namespace: None,
            rewrite: None,
            operation: DetectedOperation::Read,
            body: BodyClass::Control,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(path: &str) -> Option<ProtocolMatch> {
        SystemPathDetector.detect(path, "", &http::HeaderMap::new(), None)
    }

    #[test]
    fn status() {
        assert!(detect("/_status").is_some());
        assert!(detect("/_status/ready").is_some());
    }

    #[test]
    fn openapi() {
        assert!(detect("/openapi.json").is_some());
    }

    #[test]
    fn docs() {
        assert!(detect("/docs").is_some());
        assert!(detect("/docs/scalar.js").is_some());
    }

    #[test]
    fn root() {
        assert!(detect("/").is_some());
    }

    #[test]
    fn identity() {
        assert!(detect("/identity/whoami").is_some());
        assert!(detect("/identity/resolve/sha256:abc").is_some());
    }

    #[test]
    fn node_rotation_resolves_to_root_as_a_write() -> Result<(), &'static str> {
        let matched = detect(NODE_ROTATE_PATH).ok_or("rotation path not detected")?;
        assert_eq!(matched.namespace.as_deref(), Some("_root"));
        assert!(matched.operation.is_write());
        assert!(detect("/_node/authority/rotate/extra").is_none());
        Ok(())
    }

    #[test]
    fn node_authority_status_resolves_to_root_as_a_read() -> Result<(), &'static str> {
        let matched = detect(NODE_AUTHORITY_PATH).ok_or("authority path not detected")?;
        assert_eq!(matched.namespace.as_deref(), Some("_root"));
        assert!(!matched.operation.is_write());
        Ok(())
    }

    #[test]
    fn non_system() {
        assert!(detect("/v2/myrepo/blobs/sha256:abc").is_none());
        assert!(detect("/mybucket/mykey").is_none());
        assert!(detect("/xrpc/com.atproto.server.describeServer").is_none());
    }
}
