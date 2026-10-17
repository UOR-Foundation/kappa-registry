use kappa_handler::detect::{BodyClass, DetectedOperation, ProtocolDetector, ProtocolMatch};
use topcoat::router::HeaderMap;

/// kappa-distribution shares the /v2/ prefix with OCI but serves
/// extension endpoints. The OCI detector handles /v2/ namespace
/// extraction. This detector is registered at a lower priority
/// and only fires for distribution-specific paths that OCI does
/// not claim.
pub struct DistributionDetector;

impl ProtocolDetector for DistributionDetector {
    fn protocol(&self) -> &'static str {
        "distribution"
    }
    fn priority(&self) -> u32 {
        190
    }

    fn detect(
        &self,
        path: &str,
        _query: &str,
        _headers: &HeaderMap,
        _host: Option<&str>,
    ) -> Option<ProtocolMatch> {
        if !path.starts_with("/v2/") {
            return None;
        }
        let distribution_markers = [
            "/edges/",
            "/edges",
            "/compose/",
            "/witnesses/",
            "/_bundle/",
            "/_reconcile",
            "/_transaction/",
            "/_sequence/",
            "/_root",
            "/_events",
            "/_crdt/",
            "/gc/",
            "/filters/",
            "/schemas/",
            "/blobs/_cascade",
        ];
        let is_distribution = distribution_markers.iter().any(|m| path.contains(m));
        if !is_distribution {
            return None;
        }
        Some(ProtocolMatch {
            protocol: "distribution",
            namespace: extract_namespace(path),
            rewrite: None,
            operation: DetectedOperation::Read,
            body: body_class(path),
        })
    }
}

/// Staged transaction blobs (`/_transaction/{id}/{kappa}`) and ingested
/// bundles carry stored content; every other extension body is a control
/// document.
fn body_class(path: &str) -> BodyClass {
    let staged = path
        .split_once("/_transaction/")
        .and_then(|(_, rest)| rest.split_once('/'))
        .is_some_and(|(id, tail)| id != "begin" && !tail.is_empty() && tail != "commit");
    if staged || path.contains("/_bundle/ingest") {
        BodyClass::Content
    } else {
        BodyClass::Control
    }
}

fn extract_namespace(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/v2/")?;
    if rest.is_empty() {
        return None;
    }
    let boundaries = [
        "/edges/",
        "/edges",
        "/compose/",
        "/witnesses/",
        "/gc/",
        "/_transaction/",
        "/_sequence/",
        "/_root",
        "/_events",
        "/_bundle/",
        "/_reconcile",
        "/filters/",
        "/schemas/",
        "/_crdt/",
        "/blobs/_cascade",
    ];
    for b in boundaries {
        if let Some(idx) = rest.find(b)
            && idx > 0
        {
            return Some(rest[..idx].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_edge_path() {
        let m = DistributionDetector
            .detect("/v2/myrepo/edges/sha256:abc", "", &HeaderMap::new(), None)
            .unwrap();
        assert_eq!(m.namespace.as_deref(), Some("myrepo"));
    }

    #[test]
    fn detects_compose_path() {
        let m = DistributionDetector
            .detect("/v2/myrepo/compose/g2", "", &HeaderMap::new(), None)
            .unwrap();
        assert_eq!(m.namespace.as_deref(), Some("myrepo"));
    }

    #[test]
    fn body_classes() {
        assert_eq!(
            body_class("/v2/repo/_transaction/7/sha256:abc"),
            BodyClass::Content
        );
        assert_eq!(body_class("/v2/repo/_bundle/ingest"), BodyClass::Content);
        for path in [
            "/v2/repo/_transaction/begin",
            "/v2/repo/_transaction/7/commit",
            "/v2/repo/_transaction/7",
            "/v2/repo/_bundle/create",
            "/v2/repo/edges/",
        ] {
            assert_eq!(body_class(path), BodyClass::Control, "{path}");
        }
    }

    #[test]
    fn ignores_pure_oci() {
        assert!(
            DistributionDetector
                .detect("/v2/myrepo/blobs/sha256:abc", "", &HeaderMap::new(), None)
                .is_none()
        );
    }

    #[test]
    fn ignores_non_v2() {
        assert!(
            DistributionDetector
                .detect("/mybucket/mykey", "", &HeaderMap::new(), None)
                .is_none()
        );
    }
}
