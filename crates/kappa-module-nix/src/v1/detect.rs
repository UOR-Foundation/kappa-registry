use kappa_handler::detect::{BodyClass, DetectedOperation, ProtocolDetector, ProtocolMatch};
use topcoat::router::HeaderMap;

pub struct NixPathDetector;

impl ProtocolDetector for NixPathDetector {
    fn protocol(&self) -> &'static str {
        "nix"
    }
    fn priority(&self) -> u32 {
        300
    }

    fn detect(
        &self,
        path: &str,
        _query: &str,
        _headers: &HeaderMap,
        _host: Option<&str>,
    ) -> Option<ProtocolMatch> {
        if path.starts_with("/_nix/") {
            return Some(ProtocolMatch {
                protocol: "nix",
                namespace: Some("_nix".into()),
                rewrite: None,
                operation: DetectedOperation::Read,
                body: body_class(path),
            });
        }
        let rewrite = rewrite_nix(path)?;
        Some(ProtocolMatch {
            protocol: "nix",
            namespace: Some("_nix".into()),
            body: body_class(&rewrite),
            rewrite: Some(rewrite),
            operation: DetectedOperation::Read,
        })
    }
}

/// NAR transfers carry store content; narinfo and cache info are control
/// documents. Classified on the internal `/_nix/` path.
fn body_class(internal_path: &str) -> BodyClass {
    if internal_path.starts_with("/_nix/nar/") {
        BodyClass::Content
    } else {
        BodyClass::Control
    }
}

fn rewrite_nix(path: &str) -> Option<String> {
    if path == "/nix-cache-info" {
        return Some("/_nix/nix-cache-info".into());
    }
    if path.ends_with(".narinfo") {
        let stripped = path
            .strip_prefix("/nix/")
            .unwrap_or(path.strip_prefix('/').unwrap_or(path));
        let hash = stripped.strip_suffix(".narinfo").unwrap_or(stripped);
        return Some(format!("/_nix/narinfo/{hash}"));
    }
    if path.starts_with("/nar/") {
        return Some(format!("/_nix{path}"));
    }
    if path.starts_with("/nix/") {
        let rest = &path[4..];
        return Some(format!("/_nix{rest}"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_prefix() {
        let m = NixPathDetector
            .detect("/_nix/nix-cache-info", "", &HeaderMap::new(), None)
            .unwrap();
        assert_eq!(m.protocol, "nix");
        assert!(m.rewrite.is_none());
    }

    #[test]
    fn cache_info() {
        let m = NixPathDetector
            .detect("/nix-cache-info", "", &HeaderMap::new(), None)
            .unwrap();
        assert_eq!(m.rewrite.as_deref(), Some("/_nix/nix-cache-info"));
    }

    #[test]
    fn narinfo() {
        let m = NixPathDetector
            .detect("/abc123.narinfo", "", &HeaderMap::new(), None)
            .unwrap();
        assert_eq!(m.rewrite.as_deref(), Some("/_nix/narinfo/abc123"));
    }

    #[test]
    fn narinfo_with_nix_prefix() {
        let m = NixPathDetector
            .detect("/nix/abc123.narinfo", "", &HeaderMap::new(), None)
            .unwrap();
        assert_eq!(m.rewrite.as_deref(), Some("/_nix/narinfo/abc123"));
    }

    #[test]
    fn nar_path() {
        let m = NixPathDetector
            .detect("/nar/abc.nar.zst", "", &HeaderMap::new(), None)
            .unwrap();
        assert_eq!(m.rewrite.as_deref(), Some("/_nix/nar/abc.nar.zst"));
    }

    #[test]
    fn body_classes() -> Result<(), &'static str> {
        for path in [
            "/nar/abc.nar.zst",
            "/_nix/nar/abc.nar.zst",
            "/nix/nar/abc.nar",
        ] {
            let m = NixPathDetector
                .detect(path, "", &HeaderMap::new(), None)
                .ok_or("nar path not detected")?;
            assert_eq!(m.body, BodyClass::Content, "{path}");
        }
        for path in ["/abc.narinfo", "/_nix/narinfo/abc", "/nix-cache-info"] {
            let m = NixPathDetector
                .detect(path, "", &HeaderMap::new(), None)
                .ok_or("nix control path not detected")?;
            assert_eq!(m.body, BodyClass::Control, "{path}");
        }
        Ok(())
    }

    #[test]
    fn no_match() {
        assert!(
            NixPathDetector
                .detect("/v2/myrepo/blobs/sha256:abc", "", &HeaderMap::new(), None)
                .is_none()
        );
    }
}
