//! Namespace resolution interceptor layer.
//!
//! Pathless layer that runs on every request. Extracts namespace name
//! and protocol from the URL path, resolves via store.namespace_resolve
//! (read-only, never creates), and stores the result in request context
//! as ResolvedNamespace.
//!
//! Handlers read `request_context::<ResolvedNamespace>(cx)` and call
//! `.expect_exists()?` for read paths or match on NotFound for write
//! paths that need to create on first write.

use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::{Body, Next};
use topcoat::router::request::uri;

use kappa_core::store::KappaStore;
use kappa_core::types::ResolvedNamespace;

pub fn namespace_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let path = uri(cx).path().to_string();
        let resolved = resolve_from_path(cx, &path).await;
        let cx = cx.with(resolved);
        next.run(&cx, body).await
    })
}

async fn resolve_from_path(cx: &Cx, path: &str) -> ResolvedNamespace {
    let parsed = parse_namespace_from_path(path);

    let Some((ns_name, proto)) = parsed else {
        return ResolvedNamespace::NoNamespace;
    };

    let store = app_context::<Arc<dyn KappaStore>>(cx).clone();
    let name_owned = ns_name.clone();
    let proto_owned = proto.clone();

    let result = tokio::task::spawn_blocking(move || {
        store.namespace_resolve(&name_owned, Some(&proto_owned))
    })
    .await;

    match result {
        Ok(Ok(ns)) => ResolvedNamespace::Exists(ns),
        _ => ResolvedNamespace::NotFound {
            name: ns_name,
            protocol: proto,
        },
    }
}

fn parse_namespace_from_path(path: &str) -> Option<(String, String)> {
    if path.starts_with("/v2/") {
        extract_v2_namespace(path)
    } else if path.starts_with("/_git/") {
        extract_git_namespace(path)
    } else if path.starts_with("/_nix/") {
        Some(("_nix".to_string(), "nix".to_string()))
    } else if path.starts_with("/identity/") {
        None
    } else if path == "/_status"
        || path == "/v2/"
        || path == "/v2"
        || path.starts_with("/v2/_health/")
        || path.starts_with("/v2/_uploads/")
        || path == "/openapi.json"
        || path == "/docs"
        || path == "/"
    {
        None
    } else {
        extract_s3_namespace(path)
    }
}

fn extract_v2_namespace(path: &str) -> Option<(String, String)> {
    let rest = path.strip_prefix("/v2/")?;
    if rest.starts_with("_health/")
        || rest.starts_with("_uploads/")
        || rest.starts_with("_namespaces")
    {
        return None;
    }
    let boundaries = [
        "/blobs/", "/blobs", "/manifests/", "/tags/", "/tags",
        "/edges/", "/edges", "/filters/", "/schemas/",
        "/gc/", "/_transaction/", "/_sequence/", "/_root",
        "/_events", "/_bundle/", "/_reconcile", "/compose/",
        "/witnesses/", "/referrers/", "/_crdt/", "/_namespace",
    ];
    for boundary in boundaries {
        if let Some(idx) = rest.find(boundary) {
            if idx > 0 {
                return Some((rest[..idx].to_string(), "oci".to_string()));
            }
        }
    }
    None
}

fn extract_git_namespace(path: &str) -> Option<(String, String)> {
    let rest = path.strip_prefix("/_git/")?;
    let boundaries = ["/info/", "/git_upload_pack", "/git_receive_pack"];
    for boundary in boundaries {
        if let Some(idx) = rest.find(boundary) {
            if idx > 0 {
                return Some((rest[..idx].to_string(), "git".to_string()));
            }
        }
    }
    None
}

fn extract_s3_namespace(path: &str) -> Option<(String, String)> {
    let rest = path.strip_prefix('/')?;
    if rest.is_empty() {
        return None;
    }
    let bucket = rest.split('/').next()?;
    if bucket.is_empty() {
        return None;
    }
    Some((bucket.to_string(), "s3".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_blob_path() {
        assert_eq!(
            parse_namespace_from_path("/v2/myrepo/blobs/sha256:abc"),
            Some(("myrepo".to_string(), "oci".to_string()))
        );
    }

    #[test]
    fn v2_nested_namespace() {
        assert_eq!(
            parse_namespace_from_path("/v2/org/team/image/manifests/latest"),
            Some(("org/team/image".to_string(), "oci".to_string()))
        );
    }

    #[test]
    fn v2_health_no_namespace() {
        assert_eq!(parse_namespace_from_path("/v2/_health/ready"), None);
    }

    #[test]
    fn v2_uploads_no_namespace() {
        assert_eq!(parse_namespace_from_path("/v2/_uploads/abc-123"), None);
    }

    #[test]
    fn v2_root_no_namespace() {
        assert_eq!(parse_namespace_from_path("/v2/"), None);
    }

    #[test]
    fn git_info_refs() {
        assert_eq!(
            parse_namespace_from_path("/_git/myrepo/info/refs"),
            Some(("myrepo".to_string(), "git".to_string()))
        );
    }

    #[test]
    fn git_nested_repo() {
        assert_eq!(
            parse_namespace_from_path("/_git/org/team/repo/git_upload_pack"),
            Some(("org/team/repo".to_string(), "git".to_string()))
        );
    }

    #[test]
    fn nix_always_nix() {
        assert_eq!(
            parse_namespace_from_path("/_nix/nix-cache-info"),
            Some(("_nix".to_string(), "nix".to_string()))
        );
    }

    #[test]
    fn s3_bucket_key() {
        assert_eq!(
            parse_namespace_from_path("/mybucket/mykey"),
            Some(("mybucket".to_string(), "s3".to_string()))
        );
    }

    #[test]
    fn s3_bucket_only() {
        assert_eq!(
            parse_namespace_from_path("/mybucket"),
            Some(("mybucket".to_string(), "s3".to_string()))
        );
    }

    #[test]
    fn root_list_buckets_no_namespace() {
        assert_eq!(parse_namespace_from_path("/"), None);
    }

    #[test]
    fn status_no_namespace() {
        assert_eq!(parse_namespace_from_path("/_status"), None);
    }

    #[test]
    fn identity_no_namespace() {
        assert_eq!(parse_namespace_from_path("/identity/whoami"), None);
    }

    #[test]
    fn openapi_no_namespace() {
        assert_eq!(parse_namespace_from_path("/openapi.json"), None);
    }
}
