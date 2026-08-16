//! Namespace resolution interceptor layer with protocol detection.
//!
//! Pathless layer that runs on every request. Three responsibilities:
//!
//! 1. Protocol detection: identifies the protocol from request signals
//!    (path suffixes, query params, headers) — not from URL conventions
//!    like `.git` suffixes.
//!
//! 2. URI rewriting: transforms external protocol URLs into internal
//!    routing paths before topcoat dispatches the route handler.
//!    - Git: /{ns}/info/refs -> /_git/{ns}/info/refs
//!    - Nix: /nix-cache-info, /*.narinfo, /nar/* -> /_nix/*
//!    - S3 vhost: bucket.domain/key -> /{bucket}/key
//!    Rewrites return `Err(rewrite(...))` causing the router to re-dispatch.
//!
//! 3. Namespace resolution: extracts namespace name and protocol from
//!    the request, resolves via store.namespace_resolve (read-only, never
//!    creates), and stores the result in request context as ResolvedNamespace.

use std::sync::Arc;

use topcoat::context::{app_context, try_app_context, Cx};
use topcoat::router::{Body, Next};
use topcoat::router::request::{headers, uri};
use topcoat::router::error::rewrite;

use kappa_core::store::KappaStore;
use kappa_core::types::ResolvedNamespace;

/// S3 base domain for virtual-hosted-style bucket routing.
/// Registered in app context from KAPPA_S3_BASE_DOMAIN env var.
#[derive(Debug, Clone)]
pub struct S3BaseDomain(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetectedProtocol {
    Oci,
    S3,
    Git,
    Nix,
    System, // /_status, /v2/, /docs, /openapi.json, /identity
}

pub fn namespace_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let request_uri = uri(cx).clone();
        let path = request_uri.path().to_string();
        let query = request_uri.query().unwrap_or("");
        let hdrs = headers(cx);

        let protocol = detect_protocol(&path, query, hdrs);

        // Phase 1: URI rewriting for protocols that need internal route prefixes
        match protocol {
            DetectedProtocol::Git => {
                // Rewrite /{ns}/info/refs -> /_git/{ns}/info/refs
                // Rewrite /{ns}/git-upload-pack -> /_git/{ns}/git_upload_pack
                // Rewrite /{ns}/git-receive-pack -> /_git/{ns}/git_receive_pack
                // Rewrite /{ns}/info/lfs/objects/batch -> /_git/{ns}/info/lfs/objects/batch
                if !path.starts_with("/_git/") {
                    if let Some(rewritten) = rewrite_git_to_internal(&path, query) {
                        return Err(rewrite(&rewritten, body).into());
                    }
                }
            }
            DetectedProtocol::Nix => {
                // Rewrite Nix paths to /_nix/ internal prefix
                if !path.starts_with("/_nix/") {
                    if let Some(rewritten) = rewrite_nix_to_internal(&path) {
                        let pq = match request_uri.query() {
                            Some(q) => format!("{rewritten}?{q}"),
                            None => rewritten,
                        };
                        return Err(rewrite(&pq, body).into());
                    }
                }
            }
            DetectedProtocol::S3 => {
                // S3 vhost rewrite: bucket.domain/key -> /{bucket}/key
                if let Some(base_domain) = try_app_context::<S3BaseDomain>(cx) {
                    if !base_domain.0.is_empty() {
                        if let Some(host) = hdrs.get("host").and_then(|v| v.to_str().ok()) {
                            if let Some(bucket) = extract_s3_bucket(host, &base_domain.0) {
                                let new_path = format!("/{bucket}{}", request_uri.path());
                                let pq = match request_uri.query() {
                                    Some(q) => format!("{new_path}?{q}"),
                                    None => new_path,
                                };
                                return Err(rewrite(&pq, body).into());
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        // Phase 2: Namespace resolution
        let resolved = resolve_from_path(cx, &path, protocol).await;
        let cx = cx.with(resolved);
        next.run(&cx, body).await
    })
}

fn detect_protocol(path: &str, query: &str, hdrs: &topcoat::router::HeaderMap) -> DetectedProtocol {
    // Definitive prefix matches (fastest, no ambiguity)
    if path.starts_with("/v2/") || path == "/v2" || path == "/v2/" {
        return DetectedProtocol::Oci;
    }

    // System endpoints
    if path == "/_status"
        || path == "/openapi.json"
        || path == "/docs"
        || path.starts_with("/identity/")
    {
        return DetectedProtocol::System;
    }

    // Internal prefixes from prior rewrites
    if path.starts_with("/_git/") {
        return DetectedProtocol::Git;
    }
    if path.starts_with("/_nix/") {
        return DetectedProtocol::Nix;
    }

    // S3: definitive header matches
    if hdrs.contains_key("x-amz-content-sha256")
        || hdrs.get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.starts_with("AWS4-HMAC-SHA256"))
            .unwrap_or(false)
    {
        return DetectedProtocol::S3;
    }

    // Git: path suffix signals
    if path.ends_with("/info/refs")
        || path.ends_with("/git-upload-pack")
        || path.ends_with("/git-receive-pack")
        || path.contains("/git-lfs/")
        || path.ends_with("/HEAD")
        || path.ends_with("/info/packs")
    {
        return DetectedProtocol::Git;
    }

    // Git: query parameter signal
    if query.contains("service=git-upload-pack")
        || query.contains("service=git-receive-pack")
    {
        return DetectedProtocol::Git;
    }

    // Git: content-type signal
    if hdrs.get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("application/x-git-"))
        .unwrap_or(false)
    {
        return DetectedProtocol::Git;
    }

    // Nix: path signals
    if path == "/nix-cache-info"
        || path.ends_with(".narinfo")
        || path.starts_with("/nar/")
    {
        return DetectedProtocol::Nix;
    }

    // Default: S3 path-style
    DetectedProtocol::S3
}

/// Rewrite git protocol URLs to internal /_git/ routing prefix.
/// Extracts namespace as everything before the git operation suffix.
/// Strips .git suffix from namespace if present.
/// Normalizes git-upload-pack -> git_upload_pack (hyphen to underscore).
fn rewrite_git_to_internal(path: &str, query: &str) -> Option<String> {
    let stripped = path.strip_prefix('/')?;
    let git_boundaries = [
        "/info/refs",
        "/git-upload-pack",
        "/git-receive-pack",
        "/info/lfs/objects/batch",
        "/info/lfs/",
        "/HEAD",
        "/info/packs",
    ];
    for boundary in git_boundaries {
        if let Some(idx) = stripped.find(boundary) {
            if idx == 0 {
                return None; // no namespace segment
            }
            let ns = &stripped[..idx];
            let ns = ns.strip_suffix(".git").unwrap_or(ns);
            let sub_path = &stripped[idx..];
            // Normalize hyphens to underscores for route matching
            let sub_path = sub_path
                .replace("git-upload-pack", "git_upload_pack")
                .replace("git-receive-pack", "git_receive_pack");
            let result = format!("/_git/{ns}{sub_path}");
            if !query.is_empty() {
                return Some(format!("{result}?{query}"));
            }
            return Some(result);
        }
    }
    None
}

/// Rewrite Nix protocol URLs to internal /_nix/ routing prefix.
fn rewrite_nix_to_internal(path: &str) -> Option<String> {
    if path == "/nix-cache-info" {
        return Some("/_nix/nix-cache-info".to_string());
    }
    if path.ends_with(".narinfo") {
        // /{hash}.narinfo -> /_nix/{hash}.narinfo
        return Some(format!("/_nix{path}"));
    }
    if path.starts_with("/nar/") {
        // /nar/{filehash}.nar.zst -> /_nix/nar/{rest}
        return Some(format!("/_nix{path}"));
    }
    None
}

/// Extract bucket name from Host header subdomain.
fn extract_s3_bucket(host: &str, base_domain: &str) -> Option<String> {
    let host_no_port = host.split(':').next().unwrap_or(host);
    let suffix = format!(".{}", base_domain);
    host_no_port
        .strip_suffix(&suffix)
        .filter(|bucket| !bucket.is_empty() && !bucket.contains('.'))
        .map(|b| b.to_string())
}

async fn resolve_from_path(cx: &Cx, path: &str, protocol: DetectedProtocol) -> ResolvedNamespace {
    let parsed = extract_namespace(path, protocol);

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

fn extract_namespace(path: &str, protocol: DetectedProtocol) -> Option<(String, String)> {
    match protocol {
        DetectedProtocol::Oci => extract_v2_namespace(path),
        DetectedProtocol::Git => extract_git_namespace(path),
        DetectedProtocol::Nix => Some(("_nix".to_string(), "nix".to_string())),
        DetectedProtocol::S3 => extract_s3_namespace(path),
        DetectedProtocol::System => None,
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

/// Extract git namespace from internal /_git/ path (post-rewrite)
/// or from original path with git operation suffixes (pre-rewrite).
fn extract_git_namespace(path: &str) -> Option<(String, String)> {
    // Post-rewrite: /_git/{ns}/info/refs
    if let Some(rest) = path.strip_prefix("/_git/") {
        let boundaries = ["/info/", "/git_upload_pack", "/git_receive_pack"];
        for boundary in boundaries {
            if let Some(idx) = rest.find(boundary) {
                if idx > 0 {
                    return Some((rest[..idx].to_string(), "git".to_string()));
                }
            }
        }
        return None;
    }
    // Pre-rewrite: /{ns}/info/refs (shouldn't reach here after rewrite, but defensive)
    let stripped = path.strip_prefix('/')?;
    let boundaries = [
        "/info/refs", "/git-upload-pack", "/git-receive-pack",
        "/git-lfs/", "/HEAD", "/info/packs",
    ];
    for boundary in boundaries {
        if let Some(idx) = stripped.find(boundary) {
            if idx > 0 {
                let ns = &stripped[..idx];
                let ns = ns.strip_suffix(".git").unwrap_or(ns);
                if !ns.is_empty() {
                    return Some((ns.to_string(), "git".to_string()));
                }
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
    use topcoat::router::HeaderMap;

    // -- Protocol detection --

    #[test]
    fn oci_detected_from_v2_prefix() {
        assert_eq!(detect_protocol("/v2/myrepo/blobs/sha256:abc", "", &HeaderMap::new()), DetectedProtocol::Oci);
        assert_eq!(detect_protocol("/v2/", "", &HeaderMap::new()), DetectedProtocol::Oci);
        assert_eq!(detect_protocol("/v2", "", &HeaderMap::new()), DetectedProtocol::Oci);
    }

    #[test]
    fn git_detected_from_info_refs_suffix() {
        assert_eq!(detect_protocol("/myrepo/info/refs", "service=git-upload-pack", &HeaderMap::new()), DetectedProtocol::Git);
    }

    #[test]
    fn git_detected_from_upload_pack_suffix() {
        assert_eq!(detect_protocol("/myrepo/git-upload-pack", "", &HeaderMap::new()), DetectedProtocol::Git);
    }

    #[test]
    fn git_detected_from_receive_pack_suffix() {
        assert_eq!(detect_protocol("/myorg/team/repo/git-receive-pack", "", &HeaderMap::new()), DetectedProtocol::Git);
    }

    #[test]
    fn git_detected_from_query_param() {
        assert_eq!(detect_protocol("/myrepo/info/refs", "service=git-upload-pack", &HeaderMap::new()), DetectedProtocol::Git);
    }

    #[test]
    fn git_detected_from_content_type() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert("content-type", "application/x-git-upload-pack-request".parse().unwrap());
        assert_eq!(detect_protocol("/myrepo/git-upload-pack", "", &hdrs), DetectedProtocol::Git);
    }

    #[test]
    fn git_with_dot_git_suffix_detected() {
        assert_eq!(detect_protocol("/myrepo.git/info/refs", "", &HeaderMap::new()), DetectedProtocol::Git);
    }

    #[test]
    fn nix_detected_from_narinfo() {
        assert_eq!(detect_protocol("/r5sjd57x0r07bwgipryaxqdkx1gglhiy.narinfo", "", &HeaderMap::new()), DetectedProtocol::Nix);
    }

    #[test]
    fn nix_detected_from_nar_prefix() {
        assert_eq!(detect_protocol("/nar/abc123.nar.zst", "", &HeaderMap::new()), DetectedProtocol::Nix);
    }

    #[test]
    fn nix_detected_from_cache_info() {
        assert_eq!(detect_protocol("/nix-cache-info", "", &HeaderMap::new()), DetectedProtocol::Nix);
    }

    #[test]
    fn s3_detected_from_amz_header() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        assert_eq!(detect_protocol("/mybucket/mykey", "", &hdrs), DetectedProtocol::S3);
    }

    #[test]
    fn s3_default_for_unknown() {
        assert_eq!(detect_protocol("/mybucket/mykey", "", &HeaderMap::new()), DetectedProtocol::S3);
    }

    #[test]
    fn system_endpoints_detected() {
        assert_eq!(detect_protocol("/_status", "", &HeaderMap::new()), DetectedProtocol::System);
        assert_eq!(detect_protocol("/openapi.json", "", &HeaderMap::new()), DetectedProtocol::System);
        assert_eq!(detect_protocol("/docs", "", &HeaderMap::new()), DetectedProtocol::System);
        assert_eq!(detect_protocol("/identity/whoami", "", &HeaderMap::new()), DetectedProtocol::System);
    }

    // -- Git rewrite --

    #[test]
    fn git_rewrite_shallow() {
        assert_eq!(
            rewrite_git_to_internal("/myrepo/info/refs", "service=git-upload-pack"),
            Some("/_git/myrepo/info/refs?service=git-upload-pack".to_string())
        );
    }

    #[test]
    fn git_rewrite_nested() {
        assert_eq!(
            rewrite_git_to_internal("/myorg/team/repo/info/refs", ""),
            Some("/_git/myorg/team/repo/info/refs".to_string())
        );
    }

    #[test]
    fn git_rewrite_deep_nested() {
        assert_eq!(
            rewrite_git_to_internal("/myorg/team/sub/myrepo/git-upload-pack", ""),
            Some("/_git/myorg/team/sub/myrepo/git_upload_pack".to_string())
        );
    }

    #[test]
    fn git_rewrite_strips_dot_git() {
        assert_eq!(
            rewrite_git_to_internal("/myrepo.git/info/refs", ""),
            Some("/_git/myrepo/info/refs".to_string())
        );
    }

    #[test]
    fn git_rewrite_nested_with_dot_git() {
        assert_eq!(
            rewrite_git_to_internal("/myorg/team/repo.git/git-receive-pack", ""),
            Some("/_git/myorg/team/repo/git_receive_pack".to_string())
        );
    }

    #[test]
    fn git_rewrite_lfs() {
        assert_eq!(
            rewrite_git_to_internal("/myrepo/info/lfs/objects/batch", ""),
            Some("/_git/myrepo/info/lfs/objects/batch".to_string())
        );
    }

    #[test]
    fn git_rewrite_no_namespace_returns_none() {
        assert_eq!(rewrite_git_to_internal("/info/refs", ""), None);
    }

    // -- Nix rewrite --

    #[test]
    fn nix_rewrite_cache_info() {
        assert_eq!(
            rewrite_nix_to_internal("/nix-cache-info"),
            Some("/_nix/nix-cache-info".to_string())
        );
    }

    #[test]
    fn nix_rewrite_narinfo() {
        assert_eq!(
            rewrite_nix_to_internal("/r5sjd57x.narinfo"),
            Some("/_nix/r5sjd57x.narinfo".to_string())
        );
    }

    #[test]
    fn nix_rewrite_nar() {
        assert_eq!(
            rewrite_nix_to_internal("/nar/abc.nar.zst"),
            Some("/_nix/nar/abc.nar.zst".to_string())
        );
    }

    // -- Namespace extraction --

    #[test]
    fn v2_blob_path() {
        assert_eq!(
            extract_namespace("/v2/myrepo/blobs/sha256:abc", DetectedProtocol::Oci),
            Some(("myrepo".to_string(), "oci".to_string()))
        );
    }

    #[test]
    fn v2_nested_namespace() {
        assert_eq!(
            extract_namespace("/v2/org/team/image/manifests/latest", DetectedProtocol::Oci),
            Some(("org/team/image".to_string(), "oci".to_string()))
        );
    }

    #[test]
    fn git_namespace_shallow() {
        assert_eq!(
            extract_git_namespace("/_git/myrepo/info/refs"),
            Some(("myrepo".to_string(), "git".to_string()))
        );
    }

    #[test]
    fn git_namespace_nested() {
        assert_eq!(
            extract_git_namespace("/_git/myorg/team/repo/git_upload_pack"),
            Some(("myorg/team/repo".to_string(), "git".to_string()))
        );
    }

    #[test]
    fn git_namespace_pre_rewrite_no_dot_git() {
        assert_eq!(
            extract_git_namespace("/myrepo/info/refs"),
            Some(("myrepo".to_string(), "git".to_string()))
        );
    }

    #[test]
    fn git_namespace_pre_rewrite_with_dot_git() {
        assert_eq!(
            extract_git_namespace("/myrepo.git/info/refs"),
            Some(("myrepo".to_string(), "git".to_string()))
        );
    }

    #[test]
    fn git_namespace_pre_rewrite_deep_nested() {
        assert_eq!(
            extract_git_namespace("/myorg/team/sub/myrepo/git-receive-pack"),
            Some(("myorg/team/sub/myrepo".to_string(), "git".to_string()))
        );
    }

    #[test]
    fn git_namespace_pre_rewrite_deep_nested_with_dot_git() {
        assert_eq!(
            extract_git_namespace("/myorg/team/sub/myrepo.git/git-upload-pack"),
            Some(("myorg/team/sub/myrepo".to_string(), "git".to_string()))
        );
    }

    #[test]
    fn nix_namespace_always_nix() {
        assert_eq!(
            extract_namespace("/_nix/nix-cache-info", DetectedProtocol::Nix),
            Some(("_nix".to_string(), "nix".to_string()))
        );
    }

    #[test]
    fn s3_bucket_key() {
        assert_eq!(
            extract_namespace("/mybucket/mykey", DetectedProtocol::S3),
            Some(("mybucket".to_string(), "s3".to_string()))
        );
    }

    #[test]
    fn system_no_namespace() {
        assert_eq!(extract_namespace("/_status", DetectedProtocol::System), None);
    }

    // -- S3 vhost --

    #[test]
    fn s3_bucket_from_subdomain() {
        assert_eq!(extract_s3_bucket("mybucket.localhost", "localhost"), Some("mybucket".into()));
        assert_eq!(extract_s3_bucket("mybucket.localhost:5000", "localhost"), Some("mybucket".into()));
    }

    #[test]
    fn s3_no_subdomain() {
        assert_eq!(extract_s3_bucket("localhost", "localhost"), None);
    }

    #[test]
    fn s3_wrong_domain() {
        assert_eq!(extract_s3_bucket("mybucket.other.com", "localhost"), None);
    }
}
