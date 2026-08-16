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
use kappa_core::types::{DetectedOperation, ResolvedNamespace};

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
    System,  // /_status, /v2/, /docs, /openapi.json, /identity
    Unknown, // no protocol signal matched — 404
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

        // Phase 2: Detect operation intent from protocol signals
        let method = topcoat::router::request::method(cx);
        let detected_op = detect_operation(&path, query, method, protocol);
        let cx = cx.with(detected_op);

        // Phase 3: Namespace resolution
        let resolved = resolve_from_path(&cx, &path, protocol).await;
        let cx = cx.with(resolved);
        next.run(&cx, body).await
    })
}

fn detect_protocol(path: &str, query: &str, hdrs: &topcoat::router::HeaderMap) -> DetectedProtocol {
    // 1. Content-Type header (definitive for Git POST, gRPC)
    if let Some(ct) = hdrs.get("content-type").and_then(|v| v.to_str().ok()) {
        if ct.starts_with("application/x-git-") {
            return DetectedProtocol::Git;
        }
    }

    // 2. S3 headers (definitive, present on EVERY conformant S3 request)
    if hdrs.contains_key("x-amz-content-sha256") {
        return DetectedProtocol::S3;
    }
    if hdrs.get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("AWS4-HMAC-SHA256"))
        .unwrap_or(false)
    {
        return DetectedProtocol::S3;
    }

    // 3. Git query parameter (definitive for discovery)
    if query.contains("service=git-upload-pack")
        || query.contains("service=git-receive-pack")
    {
        return DetectedProtocol::Git;
    }

    // 4. Path prefix (unambiguous, cheap byte compare)
    if path.starts_with("/v2/") || path == "/v2" || path == "/v2/" {
        return DetectedProtocol::Oci;
    }
    if path.starts_with("/_git/") {
        return DetectedProtocol::Git;
    }
    if path.starts_with("/_nix/") {
        return DetectedProtocol::Nix;
    }
    if path == "/_status"
        || path.starts_with("/_status/")
        || path == "/openapi.json"
        || path == "/docs"
        || path == "/"
        || path.starts_with("/identity/")
    {
        return DetectedProtocol::System;
    }

    // 5. Nix path signals
    if path == "/nix-cache-info"
        || path.starts_with("/nix/")
        || path.ends_with(".narinfo")
        || path.starts_with("/nar/")
    {
        return DetectedProtocol::Nix;
    }

    // 6. Git path signals (after Nix, because /nix/ must not hit Git)
    if path.contains("/info/refs")
        || path.ends_with("/git-upload-pack")
        || path.ends_with("/git-receive-pack")
        || path.contains("/git-lfs/")
        || path.contains("/info/lfs/")
    {
        return DetectedProtocol::Git;
    }

    // 7. Git dumb HTTP (must not match OCI or Nix paths)
    if (path.ends_with("/HEAD") || path.contains("/objects/") || path.contains("/info/packs"))
        && !path.starts_with("/v2")
        && !path.starts_with("/nix")
        && !path.starts_with("/nar")
    {
        return DetectedProtocol::Git;
    }

    // 8. No protocol signal matched
    DetectedProtocol::Unknown
}

/// Detect the operation intent from protocol-specific signals.
/// The auth layer uses this to decide whether a nonexistent namespace
/// should return 404 (read) or AllowCreateNew (write/write-discovery).
fn detect_operation(
    path: &str,
    query: &str,
    method: &http::Method,
    protocol: DetectedProtocol,
) -> DetectedOperation {
    match protocol {
        DetectedProtocol::Git => {
            // git-receive-pack discovery: GET with ?service=git-receive-pack
            if query.contains("service=git-receive-pack") {
                return DetectedOperation::WriteDiscovery;
            }
            // git-receive-pack data: POST
            if path.ends_with("/git-receive-pack") || path.ends_with("/git_receive_pack") {
                return DetectedOperation::Write;
            }
            DetectedOperation::Read
        }
        DetectedProtocol::Nix => {
            if *method == http::Method::PUT {
                DetectedOperation::Write
            } else {
                DetectedOperation::Read
            }
        }
        _ => {
            if *method == http::Method::GET || *method == http::Method::HEAD {
                DetectedOperation::Read
            } else {
                DetectedOperation::Write
            }
        }
    }
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
        // /{hash}.narinfo -> /_nix/narinfo/{hash}
        // /nix/{hash}.narinfo -> /_nix/narinfo/{hash}
        let stripped = path.strip_prefix("/nix/").unwrap_or(path.strip_prefix('/').unwrap_or(path));
        let hash = stripped.strip_suffix(".narinfo").unwrap_or(stripped);
        return Some(format!("/_nix/narinfo/{hash}"));
    }
    if path.starts_with("/nar/") {
        // /nar/{filehash}.nar.zst -> /_nix/nar/{rest}
        return Some(format!("/_nix{path}"));
    }
    if path.starts_with("/nix/") {
        // /nix/nix-cache-info -> /_nix/nix-cache-info
        // /nix/nar/{rest} -> /_nix/nar/{rest}
        let rest = &path[4..]; // strip "/nix"
        return Some(format!("/_nix{rest}"));
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
        DetectedProtocol::Unknown => None,
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
    fn unknown_path_no_headers_is_unknown() {
        assert_eq!(detect_protocol("/mybucket/mykey", "", &HeaderMap::new()), DetectedProtocol::Unknown);
    }

    #[test]
    fn s3_detected_only_from_headers() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        assert_eq!(detect_protocol("/mybucket/mykey", "", &hdrs), DetectedProtocol::S3);
        // Without S3 headers, same path is Unknown
        assert_eq!(detect_protocol("/mybucket/mykey", "", &HeaderMap::new()), DetectedProtocol::Unknown);
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
            Some("/_nix/narinfo/r5sjd57x".to_string())
        );
    }

    #[test]
    fn nix_rewrite_narinfo_with_prefix() {
        assert_eq!(
            rewrite_nix_to_internal("/nix/r5sjd57x.narinfo"),
            Some("/_nix/narinfo/r5sjd57x".to_string())
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
    fn s3_bucket_key_with_headers() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        let protocol = detect_protocol("/mybucket/mykey", "", &hdrs);
        assert_eq!(protocol, DetectedProtocol::S3);
        assert_eq!(
            extract_namespace("/mybucket/mykey", protocol),
            Some(("mybucket".to_string(), "s3".to_string()))
        );
    }

    #[test]
    fn s3_bucket_key_without_headers_is_unknown() {
        let protocol = detect_protocol("/mybucket/mykey", "", &HeaderMap::new());
        assert_eq!(protocol, DetectedProtocol::Unknown);
        assert_eq!(extract_namespace("/mybucket/mykey", protocol), None);
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

    // -- Cross-protocol collision resolution --

    #[test]
    fn git_query_param_wins_over_nix_prefix() {
        // /nix/info/refs?service=git-upload-pack is Git, not Nix
        assert_eq!(
            detect_protocol("/nix/info/refs", "service=git-upload-pack", &HeaderMap::new()),
            DetectedProtocol::Git
        );
    }

    #[test]
    fn s3_header_wins_over_git_objects_path() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        assert_eq!(
            detect_protocol("/objects/abc123", "", &hdrs),
            DetectedProtocol::S3
        );
    }

    #[test]
    fn git_objects_without_s3_headers() {
        assert_eq!(
            detect_protocol("/objects/abc123", "", &HeaderMap::new()),
            DetectedProtocol::Git
        );
    }

    #[test]
    fn s3_header_wins_over_nix_nar_prefix() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        assert_eq!(
            detect_protocol("/nar/myfile", "", &hdrs),
            DetectedProtocol::S3
        );
    }

    #[test]
    fn nix_nar_without_s3_headers() {
        assert_eq!(
            detect_protocol("/nar/myfile.nar", "", &HeaderMap::new()),
            DetectedProtocol::Nix
        );
    }

    #[test]
    fn v2_prefix_wins_over_git_head() {
        assert_eq!(
            detect_protocol("/v2/HEAD", "", &HeaderMap::new()),
            DetectedProtocol::Oci
        );
    }

    #[test]
    fn s3_header_wins_over_git_head() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        assert_eq!(
            detect_protocol("/myrepo/HEAD", "", &hdrs),
            DetectedProtocol::S3
        );
    }

    #[test]
    fn git_head_without_s3_headers() {
        assert_eq!(
            detect_protocol("/myrepo/HEAD", "", &HeaderMap::new()),
            DetectedProtocol::Git
        );
    }

    #[test]
    fn git_content_type_wins() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert("content-type", "application/x-git-upload-pack-request".parse().unwrap());
        assert_eq!(
            detect_protocol("/myrepo/git-upload-pack", "", &hdrs),
            DetectedProtocol::Git
        );
    }

    #[test]
    fn nix_cache_info_exact_match() {
        assert_eq!(
            detect_protocol("/nix-cache-info", "", &HeaderMap::new()),
            DetectedProtocol::Nix
        );
    }

    #[test]
    fn nix_narinfo_suffix() {
        assert_eq!(
            detect_protocol("/r5sjd57x0r07bwgipryaxqdkx1gglhiy.narinfo", "", &HeaderMap::new()),
            DetectedProtocol::Nix
        );
    }

    #[test]
    fn nix_prefix_path() {
        assert_eq!(
            detect_protocol("/nix/nix-cache-info", "", &HeaderMap::new()),
            DetectedProtocol::Nix
        );
    }

    #[test]
    fn unknown_path_no_signals() {
        assert_eq!(
            detect_protocol("/random/path/here", "", &HeaderMap::new()),
            DetectedProtocol::Unknown
        );
    }

    // -- DetectedOperation --

    #[test]
    fn git_receive_pack_query_is_write_discovery() {
        assert_eq!(
            detect_operation("/_git/myrepo/info/refs", "service=git-receive-pack", &http::Method::GET, DetectedProtocol::Git),
            DetectedOperation::WriteDiscovery
        );
    }

    #[test]
    fn git_upload_pack_query_is_read() {
        assert_eq!(
            detect_operation("/_git/myrepo/info/refs", "service=git-upload-pack", &http::Method::GET, DetectedProtocol::Git),
            DetectedOperation::Read
        );
    }

    #[test]
    fn git_receive_pack_post_is_write() {
        assert_eq!(
            detect_operation("/_git/myrepo/git_receive_pack", "", &http::Method::POST, DetectedProtocol::Git),
            DetectedOperation::Write
        );
    }

    #[test]
    fn nix_put_is_write() {
        assert_eq!(
            detect_operation("/_nix/nar/abc.nar.zst", "", &http::Method::PUT, DetectedProtocol::Nix),
            DetectedOperation::Write
        );
    }

    #[test]
    fn nix_get_is_read() {
        assert_eq!(
            detect_operation("/_nix/nix-cache-info", "", &http::Method::GET, DetectedProtocol::Nix),
            DetectedOperation::Read
        );
    }

    #[test]
    fn oci_get_is_read() {
        assert_eq!(
            detect_operation("/v2/myrepo/manifests/latest", "", &http::Method::GET, DetectedProtocol::Oci),
            DetectedOperation::Read
        );
    }

    #[test]
    fn oci_put_is_write() {
        assert_eq!(
            detect_operation("/v2/myrepo/manifests/latest", "", &http::Method::PUT, DetectedProtocol::Oci),
            DetectedOperation::Write
        );
    }
}
