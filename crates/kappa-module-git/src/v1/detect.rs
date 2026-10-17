use kappa_handler::detect::{BodyClass, DetectedOperation, ProtocolDetector, ProtocolMatch};
use topcoat::router::HeaderMap;

pub struct GitHeaderDetector;

impl ProtocolDetector for GitHeaderDetector {
    fn protocol(&self) -> &'static str {
        "git"
    }
    fn priority(&self) -> u32 {
        100
    }

    fn detect(
        &self,
        path: &str,
        query: &str,
        headers: &HeaderMap,
        _host: Option<&str>,
    ) -> Option<ProtocolMatch> {
        let has_git_ct = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("application/x-git-"));
        let has_git_query =
            query.contains("service=git-upload-pack") || query.contains("service=git-receive-pack");
        if !has_git_ct && !has_git_query {
            return None;
        }
        let (ns, rewrite) = parse_git(path, query);
        Some(ProtocolMatch {
            protocol: "git",
            namespace: ns,
            rewrite,
            operation: detect_git_op(path, query),
            body: body_class(path),
        })
    }
}

pub struct GitPathDetector;

impl ProtocolDetector for GitPathDetector {
    fn protocol(&self) -> &'static str {
        "git"
    }
    fn priority(&self) -> u32 {
        300
    }

    fn detect(
        &self,
        path: &str,
        query: &str,
        _headers: &HeaderMap,
        _host: Option<&str>,
    ) -> Option<ProtocolMatch> {
        if path.starts_with("/_git/") {
            let (ns, _) = parse_git(path, query);
            return Some(ProtocolMatch {
                protocol: "git",
                namespace: ns,
                rewrite: None,
                operation: detect_git_op(path, query),
                body: body_class(path),
            });
        }
        let suffixes = [
            "/info/refs",
            "/git-upload-pack",
            "/git-receive-pack",
            "/git-lfs/",
            "/info/lfs/",
        ];
        if suffixes.iter().any(|s| path.contains(s)) {
            let (ns, rewrite) = parse_git(path, query);
            return Some(ProtocolMatch {
                protocol: "git",
                namespace: ns,
                rewrite,
                operation: detect_git_op(path, query),
                body: body_class(path),
            });
        }
        None
    }
}

pub struct GitDumbHttpDetector;

impl ProtocolDetector for GitDumbHttpDetector {
    fn protocol(&self) -> &'static str {
        "git"
    }
    fn priority(&self) -> u32 {
        400
    }

    fn detect(
        &self,
        path: &str,
        query: &str,
        _headers: &HeaderMap,
        _host: Option<&str>,
    ) -> Option<ProtocolMatch> {
        if path.starts_with("/v2") || path.starts_with("/nix") || path.starts_with("/nar") {
            return None;
        }
        if !(path.ends_with("/HEAD") || path.contains("/objects/") || path.contains("/info/packs"))
        {
            return None;
        }
        let (ns, rewrite) = parse_git(path, query);
        Some(ProtocolMatch {
            protocol: "git",
            namespace: ns,
            rewrite,
            operation: DetectedOperation::Read,
            body: BodyClass::Control,
        })
    }
}

/// Pack negotiation and pack transfer bodies (upload-pack, receive-pack,
/// before or after the internal rewrite) and LFS object transfers carry
/// repository content. Ref advertisement and LFS batch requests carry
/// control documents.
fn body_class(path: &str) -> BodyClass {
    let pack = [
        "/git-upload-pack",
        "/git-receive-pack",
        "/git_upload_pack",
        "/git_receive_pack",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix));
    if pack || path.contains("/git-lfs/objects/") {
        BodyClass::Content
    } else {
        BodyClass::Control
    }
}

fn detect_git_op(path: &str, query: &str) -> DetectedOperation {
    if query.contains("service=git-receive-pack") {
        DetectedOperation::WriteDiscovery
    } else if path.ends_with("/git-receive-pack") || path.ends_with("/git_receive_pack") {
        DetectedOperation::Write
    } else {
        DetectedOperation::Read
    }
}

fn parse_git(path: &str, query: &str) -> (Option<String>, Option<String>) {
    if let Some(rest) = path.strip_prefix("/_git/") {
        let boundaries = ["/info/", "/git_upload_pack", "/git_receive_pack"];
        for b in boundaries {
            if let Some(idx) = rest.find(b)
                && idx > 0
            {
                return (Some(rest[..idx].to_string()), None);
            }
        }
        return (None, None);
    }
    let stripped = match path.strip_prefix('/') {
        Some(s) => s,
        None => return (None, None),
    };
    let boundaries = [
        "/info/refs",
        "/git-upload-pack",
        "/git-receive-pack",
        "/info/lfs/objects/batch",
        "/info/lfs/",
        "/HEAD",
        "/info/packs",
    ];
    for b in boundaries {
        if let Some(idx) = stripped.find(b) {
            if idx == 0 {
                return (None, None);
            }
            let ns = stripped[..idx]
                .strip_suffix(".git")
                .unwrap_or(&stripped[..idx]);
            let sub = stripped[idx..]
                .replace("git-upload-pack", "git_upload_pack")
                .replace("git-receive-pack", "git_receive_pack");
            let mut target = format!("/_git/{ns}{sub}");
            if !query.is_empty() {
                target = format!("{target}?{query}");
            }
            return (Some(ns.to_string()), Some(target));
        }
    }
    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_detector_content_type() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert(
            "content-type",
            "application/x-git-upload-pack-request".parse().unwrap(),
        );
        let m = GitHeaderDetector
            .detect("/myrepo/git-upload-pack", "", &hdrs, None)
            .unwrap();
        assert_eq!(m.protocol, "git");
    }

    #[test]
    fn header_detector_query_param() {
        let m = GitHeaderDetector
            .detect(
                "/myrepo/info/refs",
                "service=git-upload-pack",
                &HeaderMap::new(),
                None,
            )
            .unwrap();
        assert_eq!(m.protocol, "git");
        assert!(m.rewrite.is_some());
    }

    #[test]
    fn header_detector_receive_pack_is_write_discovery() {
        let m = GitHeaderDetector
            .detect(
                "/myrepo/info/refs",
                "service=git-receive-pack",
                &HeaderMap::new(),
                None,
            )
            .unwrap();
        assert_eq!(m.operation, DetectedOperation::WriteDiscovery);
    }

    #[test]
    fn path_detector_internal_prefix() {
        let m = GitPathDetector
            .detect("/_git/myrepo/info/refs", "", &HeaderMap::new(), None)
            .unwrap();
        assert_eq!(m.namespace.as_deref(), Some("myrepo"));
        assert!(m.rewrite.is_none());
    }

    #[test]
    fn path_detector_nested_namespace() {
        let m = GitHeaderDetector
            .detect(
                "/myorg/team/repo/info/refs",
                "service=git-upload-pack",
                &HeaderMap::new(),
                None,
            )
            .unwrap();
        assert_eq!(m.namespace.as_deref(), Some("myorg/team/repo"));
    }

    #[test]
    fn path_detector_dot_git_stripped() {
        let m = GitHeaderDetector
            .detect(
                "/myrepo.git/info/refs",
                "service=git-upload-pack",
                &HeaderMap::new(),
                None,
            )
            .unwrap();
        assert_eq!(m.namespace.as_deref(), Some("myrepo"));
    }

    #[test]
    fn body_classes() {
        for path in [
            "/repo.git/git-receive-pack",
            "/repo/git-upload-pack",
            "/_git/org/repo/git_receive_pack",
            "/_git/repo/git_upload_pack",
            "/repo/git-lfs/objects/4d7a2146",
        ] {
            assert_eq!(body_class(path), BodyClass::Content, "{path}");
        }
        for path in [
            "/repo/info/refs",
            "/_git/repo/info/refs",
            "/repo/info/lfs/objects/batch",
            "/repo/HEAD",
        ] {
            assert_eq!(body_class(path), BodyClass::Control, "{path}");
        }
    }

    #[test]
    fn dumb_http_head() {
        let m = GitDumbHttpDetector
            .detect("/myrepo/HEAD", "", &HeaderMap::new(), None)
            .unwrap();
        assert_eq!(m.protocol, "git");
    }

    #[test]
    fn dumb_http_not_v2() {
        assert!(
            GitDumbHttpDetector
                .detect("/v2/HEAD", "", &HeaderMap::new(), None)
                .is_none()
        );
    }

    #[test]
    fn no_match_without_signals() {
        assert!(
            GitHeaderDetector
                .detect("/random/path", "", &HeaderMap::new(), None)
                .is_none()
        );
        assert!(
            GitPathDetector
                .detect("/random/path", "", &HeaderMap::new(), None)
                .is_none()
        );
        assert!(
            GitDumbHttpDetector
                .detect("/random/path", "", &HeaderMap::new(), None)
                .is_none()
        );
    }
}
