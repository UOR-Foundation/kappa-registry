use kappa_handler::detect::{BodyClass, DetectedOperation, ProtocolDetector, ProtocolMatch};

pub struct OciPrefixDetector;

impl ProtocolDetector for OciPrefixDetector {
    fn protocol(&self) -> &'static str {
        "oci"
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
        if !(path.starts_with("/v2/") || path == "/v2" || path == "/v2/") {
            return None;
        }
        Some(ProtocolMatch {
            protocol: "oci",
            namespace: extract_v2_namespace(path),
            rewrite: None,
            operation: DetectedOperation::Read,
            body: body_class(path),
        })
    }
}

/// Blob bodies, upload chunks, staged transaction blobs and ingested
/// bundles carry stored content. Manifests, tags, graph, policy and every
/// other /v2/ body is a control document; the blob cascade endpoint takes
/// a JSON document despite its /blobs/ prefix.
fn body_class(path: &str) -> BodyClass {
    let content = path.starts_with("/v2/_uploads/")
        || (path.contains("/blobs/") && !path.contains("/blobs/_"))
        || path.contains("/_bundle/ingest")
        || path
            .split_once("/_transaction/")
            .is_some_and(|(_, rest)| staged_blob(rest));
    if content {
        BodyClass::Content
    } else {
        BodyClass::Control
    }
}

/// `{id}/{kappa}` under `/_transaction/` stages a blob; `begin` and
/// `{id}/commit` are control operations.
fn staged_blob(rest: &str) -> bool {
    rest.split_once('/')
        .is_some_and(|(id, tail)| id != "begin" && !tail.is_empty() && tail != "commit")
}

fn extract_v2_namespace(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/v2/")?;
    if rest.is_empty()
        || rest.starts_with("_health/")
        || rest.starts_with("_uploads/")
        || rest.starts_with("_namespaces")
    {
        return None;
    }
    let boundaries = [
        "/blobs/",
        "/blobs",
        "/manifests/",
        "/tags/",
        "/tags",
        "/edges/",
        "/edges",
        "/filters/",
        "/schemas/",
        "/gc/",
        "/_transaction/",
        "/_sequence/",
        "/_root",
        "/_events",
        "/_bundle/",
        "/_reconcile",
        "/compose/",
        "/witnesses/",
        "/referrers/",
        "/_crdt/",
        "/_namespace",
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
    fn v2_blob() -> Result<(), &'static str> {
        let m = OciPrefixDetector
            .detect(
                "/v2/myrepo/blobs/sha256:abc",
                "",
                &http::HeaderMap::new(),
                None,
            )
            .ok_or("blob path not detected")?;
        assert_eq!(m.namespace.as_deref(), Some("myrepo"));
        Ok(())
    }

    #[test]
    fn v2_nested() -> Result<(), &'static str> {
        let m = OciPrefixDetector
            .detect(
                "/v2/org/team/image/manifests/latest",
                "",
                &http::HeaderMap::new(),
                None,
            )
            .ok_or("nested manifest path not detected")?;
        assert_eq!(m.namespace.as_deref(), Some("org/team/image"));
        Ok(())
    }

    #[test]
    fn v2_root() -> Result<(), &'static str> {
        let m = OciPrefixDetector
            .detect("/v2/", "", &http::HeaderMap::new(), None)
            .ok_or("v2 root not detected")?;
        assert!(m.namespace.is_none());
        Ok(())
    }

    #[test]
    fn v2_health() -> Result<(), &'static str> {
        let m = OciPrefixDetector
            .detect("/v2/_health/ready", "", &http::HeaderMap::new(), None)
            .ok_or("health path not detected")?;
        assert!(m.namespace.is_none());
        Ok(())
    }

    #[test]
    fn body_classes() {
        for path in [
            "/v2/repo/blobs/sha256:abc",
            "/v2/repo/blobs/uploads/",
            "/v2/_uploads/0f1e",
            "/v2/repo/_transaction/7/sha256:abc",
            "/v2/repo/_bundle/ingest",
        ] {
            assert_eq!(body_class(path), BodyClass::Content, "{path}");
        }
        for path in [
            "/v2/repo/blobs/_cascade",
            "/v2/repo/blobs/_meta",
            "/v2/repo/manifests/latest",
            "/v2/repo/tags/_batch",
            "/v2/repo/_transaction/begin",
            "/v2/repo/_transaction/7/commit",
            "/v2/repo/_bundle/create",
            "/v2/repo/edges/",
        ] {
            assert_eq!(body_class(path), BodyClass::Control, "{path}");
        }
    }

    #[test]
    fn non_v2() {
        assert!(
            OciPrefixDetector
                .detect("/mybucket/mykey", "", &http::HeaderMap::new(), None)
                .is_none()
        );
    }
}
